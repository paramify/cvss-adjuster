# cvss-adjuster — guide for AI agents

Scores Paramify issues from NVD CVSS data and syncs their risk-adjustment
deviations. This file tells an agent how to drive it. Humans: see `README.md`.

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
- Human output is tab-separated, so `cut`/`awk` also work.
- **Exit codes**: `0` = success (*including* "nothing to do" — e.g. a program with
  no CVE-bearing issues), `1` = a real error (auth/config/API), `2` = a usage
  error. Do not treat exit `1` on an empty result as "the tool broke"; an empty
  result exits `0`.
- Errors print `Error: …` (+ a `Hint:`) to **stderr**, never a traceback.

## Commands

```bash
cvss-adjust score CVE-2021-44228 --json            # read-only, no Paramify call
cvss-adjust adjust-program --program-id PRJ-1 --json                    # dry run
cvss-adjust adjust-program --program-id PRJ-1 --post-deviations --json  # writes
cvss-adjust programs --json
```

`adjust-program` returns one result per CVE-bearing issue:

```json
[{"issue_id": "ISS-1", "poam_id": "POAM-1", "title": "Log4Shell",
  "cve_ids": ["CVE-2021-44228"], "current_level": "MODERATE",
  "score": {"nvd_score": 10.0, "computed_score": null, "winning_cve": "CVE-2021-44228",
            "winning_vector": "CVSS:3.1/AV:N/…", "selected": [], "warnings": []},
  "deviation_action": "would-create", "deviation": null}]
```

`deviation_action` is one of `would-create` / `would-update` / `unchanged` on a
dry run, and `created` / `updated` / `unchanged` when writing.

`computed_score` is always `null` — the local vector-recompute seam is
unimplemented on purpose. Use `nvd_score`.

## Writes — read this before calling with write enabled

`adjust-program` is the only command that mutates anything, and only with
`--post-deviations`. Without that flag it is a dry run.

The tool is idempotent and scoped: it only ever updates deviations whose
description begins with `NVD CVSS max base score`, so it cannot modify or
overwrite a deviation a human authored. On update it preserves a human-set
acceptance status.

**Run the dry run first and show the user the plan before writing.** A write
touches every CVE-bearing issue in the program, which can be hundreds of rows.

## Gotchas

- **NVD rate limits.** Without `NVD_API_KEY` you get 5 requests/30s instead of 50.
  A program with several hundred distinct CVEs may be throttled.
- **A scope is required.** `adjust-program` needs `--program-id` or `PROGRAM_ID`;
  without one it exits with a config error rather than scanning everything.
- **CVEs missing from NVD** are reported as warnings on stderr (and in
  `score.warnings`), not as failures. An issue whose CVEs all fail to score gets
  no deviation and a `null` `deviation_action`.
