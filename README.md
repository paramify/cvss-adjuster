# cvss-adjuster

Sets the **original risk rating** (`originalLevel`) on Paramify issues, resolving
each one from NVD and scanner data down a three-rung ladder.

```bash
cvss-adjust set-original-levels --assessment my-scan --scan-dir ./scans           # dry run
cvss-adjust set-original-levels --assessment my-scan --scan-dir ./scans --apply   # write
```

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
| `PARAMIFY_URL` | no | `https://app.paramify.com/api/v0` | A token from one environment against the other returns 401 |
| `PROGRAM_ID` | no | — | Default for `--program-id` |
| `ASSESSMENT` | no | — | Default for `--assessment` |
| `SCAN_DIR` | no | — | Scanner exports; without them only rung 1 is available |
| `NVD_API_KEY` | no | — | Free, and worth having — see below |
| `CVSS_ADJUST_JSON` | no | — | Set to `1` to make every command emit JSON |

`cvss-adjust programs` is the cheapest authenticated call, so use it to check the
key and URL.

**Get an NVD key.** Unauthenticated callers get 5 requests per 30 seconds versus
50 with one, and the client paces itself to whichever applies — so an unkeyed run
is slow rather than throttled, turning seconds into minutes on a few thousand
CVEs. Free at <https://nvd.nist.gov/developers/request-an-api-key>.

## How a level is resolved

For every in-scope issue, the first rung that yields an answer wins:

| | Source | Used when |
|---|---|---|
| 1 | NVD CVSS base score | A metric survives selection |
| 2 | The scanner's own CVSS | NVD has no usable score |
| 3 | The scanner's severity category | Neither score is usable |

Two rules run through all three:

**A CVSS of 0 means "absent", never "harmless."** Both NVD and the scanner use 0
to mean "no opinion". In real exports a large share of rows carry 0 while the
scanner's own severity says `high` or `critical` — trusting the zero would bury
every one of them.

**Where evidence disagrees, the higher bar wins.** The same CVE often appears at
several severities across images; the most severe is taken, both when merging
scan rows and when an issue carries several CVEs.

Rung 1 needs a *usable score*, not merely a CVE that exists — CVEs marked
`Deferred` in NVD come back present with their metrics stripped.

Scores map to levels on the standard CVSS bands: `≥9.0` CRITICAL, `≥7.0` HIGH,
`≥4.0` MODERATE, `>0` LOW.

## Scan files

`--scan-dir` is read **read-only**; nothing is written, moved, or uploaded. The
directory is searched recursively, and filenames are ignored — adding next
month's export means dropping the file in.

Three columns are read, matched case-insensitively against a set of aliases
rather than by exact header or position, because exports drift between versions:

| Column | Also accepted |
|---|---|
| `CVE ID` | `cveid`, `cve`, `cve_id` |
| `CVSS` | `cvss score`, `cvss_score`, `base score` |
| `Severity` | `sev`, `severity level` |

**Every file merges into one finding per CVE** — highest severity, highest
non-zero CVSS. That applies across months as well as across images, so a CVE
rated `high` in an older export stays `high` even if the latest one calls it
`low`. This is a current-worst-known view, not a point-in-time snapshot of the
most recent scan.

Rows whose CVE column holds something else — `GHSA-…`, `PRISMA-…`, `GO-…` — are
skipped. They carry real severities, but with no CVE ID they cannot be matched to
a Paramify issue.

Bad input fails loudly rather than yielding fewer findings: a missing CVE column,
a file with neither severity nor CVSS, and a severity word outside the known
vocabulary all raise. A new scanner vocabulary can never quietly score as `LOW`.

## Scope

Three filters narrow a run:

| Filter | Reaches |
|---|---|
| `--program-id` | Server-side. Issues outside the program are never fetched. |
| `--assessment` | Client-side, by `issue.origin.name`. |
| The supplied exports | Client-side. Only CVEs present in the scans. |

**Assessment-level scoping is not fully reachable through the API.** An issue
carries no `assessmentId`, `GET /issues` has no assessment filter, and
`/pipeline-jobs` reports counts rather than issue ids. The only link from an
issue back to an assessment is that the assessment's *mechanism element* appears
as `issue.origin.name` — and that mapping is many-to-one.

Scope is still always named as an assessment, so every run records which one it
adjusted. When another assessment shares the mechanism, the run says what it is
assuming:

```
Assuming 'monthly-container-scan' is the only assessment on mechanism
'Twistlock' in this program. Also on that mechanism workspace-wide:
'staging-container-scan'. Verify in Paramify if unsure — the API cannot
confirm it.
```

That holds whenever the others live in other programs, since `--program-id` is
enforced server-side. It prints on stderr every run, under `--json` too, where an
automated caller most needs it on the record.

(`evaluationDate` looks like a way to map issues onto assessment cycles and is
not — issues carry dates outside any cycle's range.)

## Writes

**Opt-in.** Without `--apply` the command is a dry run; `--dry-run` forces one
even if `--apply` is passed.

| Action | Meaning |
|---|---|
| `would-set` / `set` | The resolved level differs from the issue's `originalLevel` |
| `noop` | Already at the resolved level — nothing sent |
| `skip` | Nothing resolved, or a downgrade suppressed by `--only-raise` |

The only field written is `originalLevel`, via `PATCH /issues/{id}`. Nothing else
on the issue is touched, and anything already correct is skipped — so a rerun is
a no-op and costs no writes.

The ladder is authoritative in both directions, so a run can **lower** a rating
as well as raise one. Downgrades are counted separately in the summary and called
out in yellow; `--only-raise` suppresses them for a run where a human should see
them first.

## Commands and output

```bash
cvss-adjust programs                                         # list programs / verify auth
cvss-adjust score CVE-2021-44228 CVE-2021-45046              # max base score across a set
cvss-adjust set-original-levels --assessment my-scan         # the workflow (dry run)
```

Every command takes `--json`. Text output adapts to where it is going: a terminal
gets an aligned table with a summary, while a pipe or redirect gets the same rows
tab-separated so `cut` and `awk` work unchanged. `CVSS_ADJUST_PLAIN=1` forces the
tab-separated form even on a terminal.

```bash
cvss-adjust set-original-levels --assessment my-scan --json \
  | jq -r '.[] | select(.plan.direction == "lower") | .poam_id'
```

### Saving a run

`--out PATH` writes the whole run to a file. Redirecting `--json` captures the
per-issue rows only; the scope assumption, scan counts and summary go to stderr,
which is exactly the context needed to read the results later. `--out` keeps all
of it together.

```bash
cvss-adjust set-original-levels --assessment my-scan \
  --out run.json --out run.csv
```

Format follows the extension — `.json` for the full record, `.csv` for a flat
one-row-per-issue table that opens in a spreadsheet. The flag is repeatable, so
one run produces both; a run against a real program takes minutes, and needing
two of them for two formats is a tax.

Files are written before the results are rendered, so they survive a broken pipe
or an interrupted terminal.

**Exit codes.** `0` = success, *including* a run that found nothing to do. `1` =
a real error (auth, config, API). `2` = a usage error. An empty result is never
an error — check the payload, not the exit code.

## How it works

```
scanner exports (CVSS + severity)  ──┐
issues for the program              ─┼──►  resolve  ──►  plan  ──►  apply
NVD metrics (one batched fetch)    ──┘
```

One Paramify read per run, and one batched NVD fetch over the deduplicated CVE
set — a large issue set collapses to far fewer distinct CVEs, and NVD's `cveIds`
parameter takes 100 per request. Metric preference is CVSS **4.0** if present,
else **3.1**; **Primary** over **Secondary**; highest base score within that.

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

`core` never imports `app`, enforced in CI by `import-linter`. The Paramify
client is a small first-party `httpx` wrapper over four endpoints rather than a
shared SDK, so this repo builds anywhere without private-repo access.

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
