# cvss-adjuster

Sets the **original risk rating** on Paramify issues from scanner and NVD data,
resolving each one down a three-rung ladder.

```bash
cvss-adjust set-original-levels --assessment my-scan --scan-dir ./scans           # dry run
cvss-adjust set-original-levels --assessment my-scan --scan-dir ./scans --apply   # write
```

## The ladder

For every in-scope issue, the first rung that yields an answer wins:

| | Source | Used when |
|---|---|---|
| 1 | NVD CVSS base score | A metric survives selection |
| 2 | The scanner's own CVSS | NVD has no usable score |
| 3 | The scanner's severity category | Neither score is usable |

Two rules run through all three:

**A CVSS of 0 means "absent", never "harmless."** Both NVD and the scanner use 0
to mean "no opinion". In real exports a large share of rows carry a CVSS of 0
while the scanner's own severity says `high` or `critical` — trusting the zero
would bury every one of them.

**Where evidence disagrees, the higher bar wins.** The same CVE often appears at
several severities across images; the most severe is taken, both when merging
scan rows and when an issue carries several CVEs.

Rung 1 needs a *usable score*, not merely a CVE that exists. CVEs marked
`Deferred` in NVD come back present with their metrics stripped, and treating
presence as an answer is what previously caused those issues to be skipped
rather than rated.

## Scope

Three filters narrow a run, and it is worth knowing exactly how far each one
reaches:

| Filter | Reaches |
|---|---|
| `--program-id` | Server-side. Issues outside the program are never fetched. |
| `--assessment` | Client-side, by `issue.origin.name`. |
| The supplied exports | Client-side. Only CVEs present in the scans. |

**Assessment-level scoping is not fully reachable through the API.** An issue
carries no `assessmentId` and no `cycleId`; `GET /issues` has no assessment
filter; and `/pipeline-jobs` reports counts rather than issue ids. The only link
from an issue back to an assessment is that the assessment's *mechanism element*
is what appears as `issue.origin.name` — and that mapping is many-to-one.

Scope is always named as an assessment — that is the unit the work is organized
around, and requiring it means every run records which assessment it adjusted.
`--assessment NAME` resolves to that assessment's mechanism and filters on it.

When another assessment shares the mechanism, the origin name cannot separate
them, and the run says so:

```
Assuming 'monthly-container-scan' is the only assessment on mechanism
'Twistlock' in this program. Also on that mechanism workspace-wide:
'staging-container-scan'.
Verify in Paramify if unsure — the API cannot confirm it.
```

That assumption holds whenever the others live in other programs, since
`--program-id` is enforced server-side. The API cannot confirm it — a program
carries no list of its assessments, and `GET /assessment` is workspace-wide with
no `projectId` — so it is stated on stderr every run, under `--json` too, where
an automated caller most needs it on the record.

`evaluationDate` looks like a way to map issues onto assessment cycles and is
not: issues carry dates outside any cycle's range, so filtering on it would
silently drop real findings.

## Writes

Dry run by default: `would-set` / `noop` / `skip`, with a summary broken down by
which rung resolved each issue. Nothing is written without `--apply`.

Reruns are no-ops for issues already at the resolved level. The ladder is
authoritative in both directions, so a run can lower a rating as well as raise
one; downgrades are counted and called out separately, and `--only-raise`
suppresses them entirely.


## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

No private dependencies and no credentials needed to build — clone it and it
installs. Add `pip install -e '.[dev]'` for the test/lint toolchain.

## Setup

Copy `.env.example` to `.env` and fill in your API key (or export the variables):

| Variable | Required | Default | Notes |
|---|---|---|---|
| `PARAMIFY_API_KEY` | yes | — | |
| `PARAMIFY_URL` | no | `https://app.paramify.com/api/v0` | Point at a staging tenant only with a staging token — a token from one environment against the other returns 401 |
| `PROGRAM_ID` | no | — | Default for `--program-id` |
| `NVD_API_KEY` | no | — | Optional but recommended, see below |
| `SCAN_DIR` | no | — | Scanner CSV exports for `set-original-levels`; without it the ladder is NVD-only |
| `ASSESSMENT` | no | — | Default for `--assessment` |
| `CVSS_ADJUST_JSON` | no | — | Set to `1` to make every command emit JSON |

Check it works:

```bash
cvss-adjust programs
```

That is the cheapest authenticated call, so it fails fast and clearly if the key
or URL is wrong.

### About the NVD API key

NVD rate-limits unauthenticated callers to **5 requests per 30 seconds**, versus
50 with a key. This tool batches 100 CVEs per request (NVD's `cveIds` parameter
batches; the repeated `cveId=A&cveId=B` form silently drops everything after the
first value) and paces itself to whichever limit applies — 0.6s between batches
with a key, 6.5s without. An unkeyed run is therefore slow rather than throttled:
a few thousand CVEs takes well under a minute keyed, and minutes without.

The key is sent as an HTTP header. Sent as a query parameter NVD answers
`404 Invalid parameter: apiKey.`, and a rejected key now fails immediately rather
than continuing anonymously. Keys are free:
<https://nvd.nist.gov/developers/request-an-api-key>

## Commands

```bash
cvss-adjust score CVE-2021-44228 CVE-2021-45046              # max base score across a set
cvss-adjust set-original-levels --assessment my-scan         # the workflow (dry run)
cvss-adjust programs                                         # list programs / verify auth
```

Every command takes `--json` for stable machine-readable output. Text output
adapts to where it is going: a terminal gets an aligned table — the issue's
`CURRENT` level beside the `TARGET`, which rung resolved it, and a summary of
how many the run raises, lowers, or leaves alone — while a pipe or redirect gets
the same rows tab-separated so `cut` and `awk` work unchanged. Set
`CVSS_ADJUST_PLAIN=1` to force the tab-separated form even on a terminal.

```bash
cvss-adjust set-original-levels --assessment my-scan --json \
  | jq -r '.[] | select(.plan.direction == "lower") | .poam_id'
```

**Exit codes.** `0` = the run succeeded, *including* a run that found nothing to
do. `1` = a real error (auth, config, API). `2` = a usage error. An empty result
is never an error — check the payload, not the exit code.

## What it writes, and when

Writes are **opt-in**. Without `--apply` the command is a dry run and reports
what it would do; `--dry-run` forces a dry run even if `--apply` is passed.

| Action | Meaning |
|---|---|
| `would-set` / `set` | The resolved level differs from the issue's `originalLevel` |
| `noop` | Already at the resolved level — nothing sent |
| `skip` | Nothing resolved, or a downgrade suppressed by `--only-raise` |

The only field written is `originalLevel`, via `PATCH /issues/{id}`. Nothing
else on the issue is touched, and an issue already at the resolved level is
skipped rather than rewritten — so a rerun is a no-op and costs no writes.

The ladder is authoritative in both directions, so a run can lower a rating as
well as raise one. Downgrades are counted separately in the summary and called
out in yellow; `--only-raise` suppresses them entirely for a run where a human
should see them first.

Score-to-level mapping:

| Base score | Level |
|---|---|
| ≥ 9.0 | `CRITICAL` |
| ≥ 7.0 | `HIGH` |
| ≥ 4.0 | `MODERATE` |
| > 0 | `LOW` |
| 0 | `CHILL` |

## How it works

```
scanner exports (CVSS + severity)  ──┐
issues for the program              ─┼──►  resolve  ──►  plan  ──►  apply
NVD metrics (one batched fetch)    ──┘
```

One Paramify read per run and one batched NVD fetch covering every CVE in scope,
deduplicated first — a large issue set typically collapses to far fewer distinct
CVEs, and NVD's `cveIds` parameter takes 100 per request.

Metric preference is CVSS **4.0** if present, else **3.1**; **Primary** over
**Secondary**; highest base score within that.

```
src/cvss_adjuster/
├── core/vuln/            # pure — no I/O, no HTTP, testable with plain dicts
│   ├── scanner.py        #   severity vocabulary, CVSS parsing, merge rules
│   ├── resolution.py     #   the three-rung ladder
│   ├── original_level.py #   set / noop / skip planning
│   └── selection.py      #   which CVSS metric wins; score -> level
└── app/                  # everything that touches the outside world
    ├── clients/          #   paramify.py (4 endpoints), nvd.py
    ├── scans.py          #   reading scanner exports off disk
    ├── services.py       #   the orchestration
    └── cli/              #   Typer surface
```

`core` never imports `app` — enforced in CI by `import-linter`. That is what
keeps the ladder and the planners testable with plain data, and liftable into a
scheduled job or another host later.

### The Paramify client

`app/clients/paramify.py` is a small first-party `httpx` client covering four
endpoints: `GET projects`, `GET assessment`, `GET issues`, and
`PATCH issues/{id}`. It is deliberately not a shared SDK dependency, so this repo
builds on any machine without private-repo access.

## For AI agents

Drive it by shelling out and parsing `--json`. The output and exit-code contract,
and the safety rules around writes, are in [AGENTS.md](AGENTS.md).

## Develop

```bash
pip install -e '.[dev]'
ruff check . && mypy && lint-imports && pytest -q
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
