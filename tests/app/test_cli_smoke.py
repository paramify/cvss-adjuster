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
from cvss_adjuster.app import output
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
        return [
            {
                "id": "ISS-1",
                "poamId": "POAM-1",
                "title": "Log4j",
                "cveIds": ["CVE-1"],
                "level": "MODERATE",
            }
        ]

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
def _no_output_env(monkeypatch):
    """Both output-format env vars off, so a stray one cannot flip a test's format."""
    monkeypatch.delenv("CVSS_ADJUST_JSON", raising=False)
    monkeypatch.delenv("CVSS_ADJUST_PLAIN", raising=False)


def test_help_lists_every_command():
    result = runner.invoke(main.app, ["--help"])
    assert result.exit_code == 0
    out = _plain(result.output)
    for command in ("score", "set-original-levels", "programs"):
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



# -- text output form ----------------------------------------------------------


def test_table_columns_stay_aligned_when_cells_are_styled():
    """Padding before styling is what keeps ANSI codes out of the width maths.

    Style the raw value instead and every column after a coloured one drifts by
    the length of the escape sequence, which is invisible until output is wide.
    """
    rows = [["a", "CRITICAL"], ["bbbb", "LOW"]]
    captured: list[str] = []
    with_style = lambda i, raw, pad: f"\x1b[31m{pad}\x1b[0m" if i == 0 else pad  # noqa: E731

    import typer as _typer

    original = _typer.echo
    try:
        _typer.echo = lambda msg="", **kw: captured.append(str(msg))
        output.aligned(rows, ["ID", "LEVEL"], style=with_style)
    finally:
        _typer.echo = original

    plain = [_plain(line) for line in captured]
    starts = [
        line.index("CRITICAL") if "CRITICAL" in line else line.index("LOW")
        for line in plain[1:]
    ]
    assert starts[0] == starts[1], f"LEVEL column drifted: {plain}"
