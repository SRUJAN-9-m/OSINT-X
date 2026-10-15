"""Central configuration for OSINT-X, loaded from environment / .env."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Optional API keys -- absence just disables the relevant adapter.
    github_token: str | None = None
    hibp_api_key: str | None = None
    search_api_key: str | None = None
    search_api_provider: str | None = None

    database_url: str = "sqlite:///./osint_x.db"
    request_timeout_seconds: float = 10.0
    rate_limit_per_host_per_minute: int = 20
    user_agent: str = (
        "OSINT-X/1.0 (+authorized-investigation-tool; contact: you@example.com)"
    )
    local_only_mode: bool = True
    data_retention_days: int = 90


settings = Settings()
