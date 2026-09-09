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

    # NVD. Without an api key NVD allows 5 requests / 30s instead of 50; the
    # client's inter-batch pause is tuned for a keyed caller, so a large program
    # scanned without a key can be throttled.
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str | None = None

    # Deviation defaults — the shape of the row this tool writes back.
    deviation_type: str = "RISK_ADJUSTMENT"
    deviation_method: str = "EXAMINE"
    deviation_status: str = "PENDING"
