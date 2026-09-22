# cvss-adjuster — guide for AI agents

Sets the original risk rating on Paramify issues from scanner and NVD data.
This file tells an agent how to drive it. Humans: see `README.md`.

## How to drive it

Shell out to the CLI (`cvss-adjust …`) and parse `--json`. There is no MCP server
and no library API to import — the CLI is the whole interface.

## Auth

Set in the environment (or a `.env` in the working dir):

- `PARAMIFY_API_KEY` — required.
- `PARAMIFY_URL` — defaults to **production** (`https://app.paramify.com/api/v0`).
  A token from one environment against the other returns 401.

Smallest authenticated check: `cvss-adjust programs`.

## Output contract

- **Get JSON**: pass `--json`, **or** set `CVSS_ADJUST_JSON=1` once. Parse JSON,
  never the human tables.
- Human output is tab-separated whenever stdout is **not** a terminal — which is
  always the case when shelling out — so `cut`/`awk` work. On a terminal the same
  data renders as an aligned table with a summary; that form is for humans and
  is not a parsing target. `CVSS_ADJUST_PLAIN=1` forces the
  tab-separated form.
- **Exit codes**: `0` = success (*including* "nothing to do" — e.g. a program with
  no CVE-bearing issues), `1` = a real error (auth/config/API), `2` = a usage
  error. Do not treat exit `1` on an empty result as "the tool broke"; an empty
  result exits `0`.
- Errors print `Error: …` (+ a `Hint:`) to **stderr**, never a traceback.

## Commands

```bash
cvss-adjust programs --json                                    # auth check
cvss-adjust score CVE-2021-44228 --json                        # read-only, no Paramify call
cvss-adjust set-original-levels --assessment NAME --json       # dry run
cvss-adjust set-original-levels --assessment NAME --apply --json   # writes
```

`set-original-levels` returns one result per in-scope issue:

```json
[{"issue_id": "…", "poam_id": "FM-1", "title": "…", "cve_ids": ["CVE-…"],
  "current_level": "NOT_SET",
  "resolution": {"level": "HIGH", "source": "nvd", "score": 7.5,
                 "cve_id": "CVE-…", "detail": "NVD base score 7.5"},
  "plan": {"action": "set", "target_level": "HIGH", "direction": "unset",
           "reason": "NOT_SET -> HIGH"},
  "applied": "would-set", "error": null}]
```

`resolution.source` is which rung answered: `nvd`, `scanner_cvss`,
`scanner_severity`, or `unresolved`. `applied` is `would-set` on a dry run,
`set` after a write, or `noop` / `skip` / `error`.

## Saving a run

`--out PATH` writes the full record — scope, scan counts, summary and every
result — to `.json`, or a flat table to `.csv`. Repeatable, so one invocation can
write both. Prefer it over redirecting `--json`, which drops the scope assumption
and the summary. Files are written before rendering, so they survive an
interrupted pipe.

## Scope

- **Required**: `--assessment NAME` (or `ASSESSMENT`) and `--program-id` (or
  `PROGRAM_ID`). Scope is always an assessment, so every run records which one
  it adjusted. Omitting it is an error, not a whole-program run.
- **`--scan-dir`** supplies the scanner exports. Without it only the NVD rung is
  available and issues NVD cannot score come back `unresolved`.
- If another assessment shares the resolved mechanism, a line on **stderr** names
  it and states what the run assumes. Surface that to the user; do not suppress
  it. It appears under `--json` too — stdout stays clean JSON.

## Writing

`set-original-levels` mutates only with `--apply`, and only `originalLevel` via
`PATCH /issues/{id}`. Without the flag it is a dry run.

Reruns are no-ops for issues already at the resolved level. The ladder can lower
a rating as well as raise one: check `plan.direction == "lower"` before applying,
and pass `--only-raise` to suppress downgrades.

## Gotchas

- **`NVD_API_KEY` matters.** Without it NVD allows 5 requests/30s and the client
  paces to match — minutes rather than seconds on a few thousand CVEs.
- **A CVSS of 0 means absent**, at every rung. Do not read `resolution.score` of
  `null` as "no risk"; read `resolution.source`.
- **An empty result exits 0.** No in-scope issues is a valid outcome.
