# cvss-adjuster

Scores Paramify issues against NVD's CVSS data and syncs a matching
risk-adjustment deviation onto each one.

For every issue in a program that carries CVE IDs, it takes the **highest NVD
base score** across those CVEs, maps it to a Paramify level, and records a
deviation saying so. Rerunning is safe: it only rewrites deviations whose score
actually moved, and it never touches a deviation it did not create.

```bash
cvss-adjust adjust-program --program-id PRJ-1                     # dry run
cvss-adjust adjust-program --program-id PRJ-1 --post-deviations   # apply
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
| `PARAMIFY_URL` | no | `https://app.paramify.com/api/v0` | Point at a staging tenant only with a staging token — a token from one environment against the other returns 401 |
| `PROGRAM_ID` | no | — | Default for `--program-id` |
| `NVD_API_KEY` | no | — | Optional but recommended, see below |
| `CVSS_ADJUST_JSON` | no | — | Set to `1` to make every command emit JSON |

Check it works:

```bash
cvss-adjust programs
```

That is the cheapest authenticated call, so it fails fast and clearly if the key
or URL is wrong.

### About the NVD API key

NVD rate-limits unauthenticated callers to **5 requests per 30 seconds**, versus
50 with a key. This tool batches 100 CVEs per request and pauses 0.6s between
batches — comfortable for a keyed caller, but a program with several hundred
distinct CVEs can be throttled without one. Keys are free:
<https://nvd.nist.gov/developers/request-an-api-key>

## Commands

```bash
cvss-adjust score CVE-2021-44228 CVE-2021-45046   # max base score across a CVE set
cvss-adjust adjust-program --program-id PRJ-1     # the workflow (dry run)
cvss-adjust programs                              # list programs / verify auth
```

Every command takes `--json` for stable machine-readable output. Text output
adapts to where it is going: a terminal gets a severity-sorted table — the
issue's `CURRENT` level beside the `ADJUSTED` level the deviation would record,
plus a summary of how many levels the run raises, lowers, or leaves alone —
while a pipe or a redirect gets the same rows tab-separated so `cut` and `awk`
work unchanged. Set `CVSS_ADJUST_PLAIN=1` to force the tab-separated form even
on a terminal.

```bash
cvss-adjust adjust-program --program-id PRJ-1 --json | jq -r '.[] | select(.deviation_action == "would-update") | .poam_id'
```

**Exit codes.** `0` = the run succeeded, *including* a run that found nothing to
do. `1` = a real error (auth, config, API). `2` = a usage error. An empty result
is never an error — check the payload, not the exit code.

## What it writes, and when

Writes are **opt-in**. Without `--post-deviations` the command is a dry run and
reports what it would do; `--dry-run` forces a dry run even if
`--post-deviations` is passed.

| Action | Meaning |
|---|---|
| `would-create` / `created` | No deviation from this tool on the issue yet |
| `would-update` / `updated` | Score or level moved since the last run |
| `unchanged` | Already correct — nothing sent |

Each deviation this tool writes has a description beginning with
`NVD CVSS max base score`. That prefix is the signature it matches on when it
runs again, which gives you two guarantees:

- **It updates its own row instead of stacking duplicates.**
- **It never modifies a deviation a human wrote.** An analyst's deviation has no
  signature, so the tool treats the issue as unmanaged and creates its own
  alongside it.

On update it also **preserves a human-set acceptance status** — if someone moved
a deviation from `PENDING` to `ACCEPTED`, a rescore updates the score and level
but leaves that status alone.

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
issues (with cveIds + inline deviations)  ──┐
                                            ├──►  score  ──►  plan  ──►  apply
NVD CVSS metrics (one batched fetch)      ──┘
```

One Paramify read per run (deviations ride along inline on each issue, so
planning never needs a second call) and one batched NVD fetch for every CVE in
the program. Metric preference is CVSS **4.0** if present, else **3.1**;
**Primary** over **Secondary**; highest base score within that.

```
src/cvss_adjuster/
├── core/vuln/          # pure — no I/O, no HTTP, testable with plain dicts
│   ├── selection.py    #   which CVSS metric wins; score -> level
│   ├── scoring.py      #   vector -> score (a swap seam; see below)
│   └── deviation.py    #   create / update / noop planning
└── app/                # everything that touches the outside world
    ├── clients/        #   paramify.py (4 endpoints), nvd.py
    ├── services.py     #   the orchestration
    └── cli/            #   Typer surface
```

`core` never imports `app` — enforced in CI by `import-linter`. That is what
keeps the scoring and planning logic testable with plain data, and liftable into
a scheduled job or another host later.

### The Paramify client

`app/clients/paramify.py` is a small first-party `httpx` client covering four
endpoints: `GET projects`, `GET issues`, `POST issues/{id}/deviations`, and
`PATCH issues/{id}/deviations/{devId}`. It is deliberately not a shared SDK
dependency, so this repo builds on any machine without private-repo access.

### The scoring seam

`core/vuln/scoring.py` is a placeholder: `recompute_from_vector` returns `None`,
so `computed_score` shows as n/a. Nothing depends on it — the workflow runs off
NVD's precomputed `baseScore`. Drop in the `cvss` package (or an in-house port)
there if you ever want to recompute a score from its vector locally, and the rest
of the pipeline picks it up unchanged.

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
