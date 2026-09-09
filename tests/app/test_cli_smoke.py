"""CLI wiring smoke tests — no network.

Both clients are faked by monkeypatching build_context, so these exercise command
registration, the exit-code contract, and the output contract without hitting an
API.
"""

import json
import re
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import cvss_adjuster.app.cli.main as main
from cvss_adjuster.app.clients.errors import ParamifyAuthError, ParamifyConfigError
from cvss_adjuster.app.settings import Settings

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Strip ANSI codes so assertions match regardless of rich styling.

    Rich's option highlighter splits a flag like ``--program-id`` into separately
    styled fragments; removing the codes reassembles it. CI renders errors with
    color, local pytest usually doesn't — normalizing makes the two agree.
    """
    return _ANSI.sub("", text)


class FakeParamify:
    def list_programs(self):
        return [{"id": "P1", "name": "Prog One"}, {"id": "P2", "name": "Prog Two"}]

    def get_issues(self, **kwargs):
        return [{"id": "ISS-1", "poamId": "POAM-1", "title": "Log4j", "cveIds": ["CVE-1"]}]

    def close(self):
        pass


class FakeNvd:
    def fetch_cves(self, cve_ids):
        return [
            {
                "cve_id": "CVE-1",
                "missing": False,
                "metrics": [
                    {
                        "metric_key": "cvssMetricV31",
                        "type": "Primary",
                        "source": "nvd@nist.gov",
                        "vector": "CVSS:3.1/AV:N",
                        "base_score": 9.8,
                        "version": "3.1",
                    }
                ],
            }
        ]


def _fake_context(settings=None):
    return SimpleNamespace(
        settings=settings or Settings(paramify_api_key="k"),
        paramify=FakeParamify(),
        nvd=FakeNvd(),
        http=None,
        close=lambda: None,
    )


@pytest.fixture(autouse=True)
def _no_env_json(monkeypatch):
    monkeypatch.delenv("CVSS_ADJUST_JSON", raising=False)


def test_help_lists_every_command():
    result = runner.invoke(main.app, ["--help"])
    assert result.exit_code == 0
    out = _plain(result.output)
    for command in ("score", "adjust-program", "programs"):
        assert command in out


def test_programs_json(monkeypatch):
    monkeypatch.setattr(main, "build_context", lambda: _fake_context())
    result = runner.invoke(main.app, ["programs", "--json"])
    assert result.exit_code == 0
    assert [p["id"] for p in json.loads(result.output)] == ["P1", "P2"]


def test_programs_text_is_tab_separated(monkeypatch):
    monkeypatch.setattr(main, "build_context", lambda: _fake_context())
    result = runner.invoke(main.app, ["programs"])
    assert result.exit_code == 0
    assert result.output.splitlines()[0] == "P1\tProg One"


def test_env_var_forces_json_without_the_flag(monkeypatch):
    monkeypatch.setattr(main, "build_context", lambda: _fake_context())
    monkeypatch.setenv("CVSS_ADJUST_JSON", "1")
    result = runner.invoke(main.app, ["programs"])
    assert result.exit_code == 0
    json.loads(result.output)  # parses, so it emitted JSON without --json


def test_score_reports_the_winning_cve(monkeypatch):
    monkeypatch.setattr(main, "build_context", lambda: _fake_context())
    result = runner.invoke(main.app, ["score", "CVE-1", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["nvd_score"] == 9.8
    assert payload["winning_cve"] == "CVE-1"


def test_adjust_program_defaults_to_a_dry_run(monkeypatch):
    monkeypatch.setattr(main, "build_context", lambda: _fake_context())
    result = runner.invoke(main.app, ["adjust-program", "--program-id", "PRJ-1", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output)[0]["deviation_action"] == "would-create"


def test_adjust_program_writes_with_the_flag(monkeypatch):
    seen = {}

    class Writing(FakeParamify):
        def create_deviation(self, issue_id, body):
            seen["issue"] = issue_id
            return {"id": "dev-1", **body}

    ctx = _fake_context()
    ctx.paramify = Writing()
    monkeypatch.setattr(main, "build_context", lambda: ctx)
    result = runner.invoke(
        main.app, ["adjust-program", "--program-id", "PRJ-1", "--post-deviations", "--json"]
    )
    assert result.exit_code == 0
    assert seen["issue"] == "ISS-1"
    assert json.loads(result.output)[0]["deviation_action"] == "created"


def test_dry_run_overrides_post_deviations(monkeypatch):
    class Exploding(FakeParamify):
        def create_deviation(self, issue_id, body):  # pragma: no cover
            raise AssertionError("--dry-run must prevent all writes")

    ctx = _fake_context()
    ctx.paramify = Exploding()
    monkeypatch.setattr(main, "build_context", lambda: ctx)
    result = runner.invoke(
        main.app,
        ["adjust-program", "--program-id", "PRJ-1", "--post-deviations", "--dry-run", "--json"],
    )
    assert result.exit_code == 0
    assert json.loads(result.output)[0]["deviation_action"] == "would-create"


def test_empty_program_is_success_not_an_error(monkeypatch):
    """Nothing to do is exit 0. An empty result must never read as a failure."""

    class Empty(FakeParamify):
        def get_issues(self, **kwargs):
            return []

    ctx = _fake_context()
    ctx.paramify = Empty()
    monkeypatch.setattr(main, "build_context", lambda: ctx)
    result = runner.invoke(main.app, ["adjust-program", "--program-id", "PRJ-1", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output) == []


def test_unknown_command_is_a_usage_error():
    assert runner.invoke(main.app, ["nope"]).exit_code == 2


def test_missing_api_key_prints_a_clean_error_not_a_traceback(monkeypatch, capsys):
    def boom():
        raise ParamifyConfigError("PARAMIFY_API_KEY is not set")

    monkeypatch.setattr(main, "build_context", boom)
    monkeypatch.setattr("sys.argv", ["cvss-adjust", "programs"])
    with pytest.raises(SystemExit) as excinfo:
        main.run()
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "PARAMIFY_API_KEY is not set" in err
    assert "Traceback" not in err


def test_auth_error_hints_at_the_environment_mismatch(monkeypatch, capsys):
    def boom():
        raise ParamifyAuthError(401, "GET", "projects", {"error": "unauthorized"})

    monkeypatch.setattr(main, "build_context", boom)
    monkeypatch.setattr("sys.argv", ["cvss-adjust", "programs"])
    with pytest.raises(SystemExit) as excinfo:
        main.run()
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "Error:" in err
    assert "PARAMIFY_URL" in err
    assert "Traceback" not in err

