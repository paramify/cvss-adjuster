"""Centralized configuration (pydantic-settings).

Resolution order, highest precedence first:
    explicit init args  >  environment variables  >  .env file  >  field defaults

``paramify_url`` defaults to **production**, because a production API key is what
most people running this tool will have. Point it at a staging tenant only if you
also have a staging token — a token from one environment against the other 401s,
which reads like a bad key but is really an environment mismatch.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Paramify
    paramify_url: str = "https://app.paramify.com/api/v0"
    paramify_api_key: str | None = None
    paramify_timeout: float = 60.0
    program_id: str | None = None

    # NVD. Without an api key NVD allows 5 requests / 30s instead of 50. The
    # client paces itself to whichever limit applies, so an unkeyed run is slow
    # rather than throttled — but a key is strongly recommended.
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str | None = None
    # CVEs per `cveIds` request. NVD accepts the comma-joined plural form; 100
    # keeps URLs well inside any server-side length limit.
    nvd_batch_size: int = 100

    # Scanner exports (Twistlock container scans). The scanner's own CVSS and
    # severity columns are rungs 2 and 3 of the fallback ladder and exist
    # nowhere in the Paramify API, so without this the ladder is NVD-only.
    scan_dir: str | None = None
    # Scope: the assessment whose issues get adjusted, by name or id. Resolved
    # to its mechanism element, which is what an issue carries as
    # `origin.name` — the only link the API offers from an issue back to an
    # assessment.
    assessment: str | None = None
    # Never lower an existing originalLevel. Off by default: the customer asked
    # for the ladder to set the original risk rating, which is authoritative in
    # both directions. Turn on for a run where downgrades need a human first.
    only_raise: bool = False

