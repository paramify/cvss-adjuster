"""Typer application root: build the Context, mount the commands, dispatch.

Three flat commands — the tool does one job, so there is no porcelain/plumbing
split to model:

    score                one-shot: max NVD CVSS base score across some CVEs
    set-original-levels  the workflow: resolve and sync each issue's originalLevel
    programs             list programs (also the cheapest authenticated call)

Exit codes are part of the contract: 0 = the run succeeded (*including* a run that
found nothing to do), 1 = a real error (auth/config/API), 2 = a usage error. An
empty result is never an error — check the payload, not the exit code.
"""

from __future__ import annotations

import typer

from cvss_adjuster.app.cli.commands import original_levels, programs, score
from cvss_adjuster.app.cli.context import build_context
from cvss_adjuster.app.clients.errors import (
    ParamifyAuthError,
    ParamifyConfigError,
    ParamifyError,
)
from cvss_adjuster.app.services import ScopeError

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    # Expected domain failures (missing/wrong auth, missing scope, 404s) are
    # rendered as a clean one-line message in run() below. Turning off Typer's
    # rich traceback lets those propagate there instead of being dumped as a
    # source-frame traceback the first time a cold-start user slips.
    pretty_exceptions_enable=False,
    help="Score Paramify issues from NVD CVSS data and sync their deviations.",
)


@app.callback()
def _root(ctx: typer.Context) -> None:
    context = build_context()
    ctx.obj = context
    ctx.call_on_close(context.close)  # close both HTTP pools on exit


# Registration order is the --help order (Typer preserves it).
app.command("score", help="Max NVD CVSS base score across the given CVEs.")(score.score)
app.command(
    "set-original-levels",
    help="Resolve originalLevel from NVD -> scanner CVSS -> scanner severity, and sync it.",
)(original_levels.set_original_levels)
app.command("programs", help="List programs (the cheapest authenticated call).")(
    programs.programs
)


def _fail(err: Exception, hint: str | None = None) -> None:
    """Print a domain error as ``Error: …`` (+ optional hint) to stderr, exit 1."""
    typer.echo(f"Error: {err}", err=True)
    if hint:
        typer.echo(f"Hint: {hint}", err=True)
    raise SystemExit(1)


def run() -> None:
    """Entrypoint. Turn expected, typed errors into a clean message and a non-zero
    exit, so a user with no prior knowledge gets guidance instead of a traceback on
    their first misstep. Unexpected errors still surface in full.
    """
    try:
        app()
    except ParamifyAuthError as e:
        _fail(
            e,
            "Check PARAMIFY_API_KEY, and that PARAMIFY_URL matches the token's "
            "environment — a production token against a staging URL (or the "
            "reverse) returns 401.",
        )
    except ParamifyConfigError as e:
        _fail(e, "See required settings in .env.example / the README.")
    except ScopeError as e:
        _fail(e, "Run `cvss-adjust programs` to check auth, then name an assessment.")
    except ParamifyError as e:
        _fail(e)


if __name__ == "__main__":
    run()
