"""Application configuration.

All settings are read from environment variables (prefix ``FIRESTORM_``) or a
local ``.env`` file. Secrets are never committed: ``.env.example`` contains
placeholders only, and ``scripts/bootstrap.py`` generates a strong
``FIRESTORM_SECRET_KEY`` plus a one-time admin password on first run.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FIRESTORM_",
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Identity -------------------------------------------------------
    app_name: str = "FIRESTORM"
    app_env: Environment = "development"
    api_prefix: str = "/api/v1"
    secret_key: str = ""
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    mfa_issuer: str = "FIRESTORM"

    # --- Persistence ----------------------------------------------------
    database_url: str = "sqlite:///./data/firestorm.db"
    db_echo: bool = False
    sqlite_busy_timeout_ms: int = 5000

    # --- Optional infrastructure (degrades gracefully when absent) ------
    redis_url: str | None = None
    celery_broker_url: str | None = None
    celery_result_backend: str | None = None

    # --- HTTP / security ------------------------------------------------
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    allowed_hosts: str = "*"
    force_https: bool = False
    rate_limit_per_minute: int = 240
    login_attempts_per_15min: int = 10
    # Comma-separated extra proxies whose X-Forwarded-For header is trusted.
    # Loopback is always trusted, so a local reverse proxy works with no config.
    trusted_proxies: str = ""
    max_page_size: int = 200
    request_body_limit_bytes: int = 2_000_000

    # --- Seeding / demo -------------------------------------------------
    bootstrap_admin_email: str = "admin@firestorm.example.com"
    bootstrap_admin_password: str | None = None
    bootstrap_admin_name: str = "Firestorm Administrator"
    # Demo-mode convenience only. When unset, demo accounts receive random
    # one-time passwords printed by the bootstrap script.
    demo_password: str | None = None
    demo_mode: bool = True
    demo_data: bool = True
    demo_traffic: bool = True

    # --- Enforcement ----------------------------------------------------
    # "simulated" records actions against built-in adapters that never touch
    # a real device. "live" requires every adapter credential to be present.
    enforcement_mode: Literal["simulated", "live"] = "simulated"
    require_approval_for_containment: bool = True
    auto_containment_threshold: int = 85
    critical_asset_auto_containment: bool = False
    ingest_api_key: str = ""

    # --- Integration endpoints (empty = adapter reports not_configured) --
    firewall_endpoint: str | None = None
    firewall_token: str | None = None
    firewall_alias: str = "FIRESTORM_BLOCK"
    nac_endpoint: str | None = None
    nac_token: str | None = None
    nac_quarantine_vlan: int = 900
    edr_endpoint: str | None = None
    edr_token: str | None = None
    idp_endpoint: str | None = None
    idp_token: str | None = None
    suricata_eve_path: str | None = None
    zeek_log_dir: str | None = None
    wazuh_endpoint: str | None = None
    wazuh_token: str | None = None
    osquery_endpoint: str | None = None
    clamav_host: str | None = None
    clamav_port: int = 3310
    yara_rules_dir: str | None = None
    threat_feed_url: str | None = None
    threat_feed_token: str | None = None

    # --- Notifications --------------------------------------------------
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    smtp_from: str = "firestorm@localhost"
    smtp_recipients: str = ""
    notification_max_attempts: int = 3

    # --- Observability --------------------------------------------------
    log_level: str = "INFO"
    log_json: bool = True
    metrics_enabled: bool = True

    @field_validator("secret_key")
    @classmethod
    def _secret_strength(cls, value: str) -> str:
        if value and len(value) < 32:
            raise ValueError("FIRESTORM_SECRET_KEY must be at least 32 characters")
        return value

    @field_validator("database_url")
    @classmethod
    def _database_url(cls, value: str) -> str:
        if value.startswith("sqlite+aiosqlite://"):
            return value.replace("sqlite+aiosqlite://", "sqlite://")
        return value

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def allowed_host_list(self) -> list[str]:
        hosts = [h.strip() for h in self.allowed_hosts.split(",") if h.strip()]
        # Preview proxies and local development must always resolve.
        return hosts or ["*"]

    @property
    def smtp_recipient_list(self) -> list[str]:
        return [r.strip() for r in self.smtp_recipients.split(",") if r.strip()]

    def ensure_secret(self) -> str:
        """Return a usable secret key, generating an ephemeral one if needed.

        Production refuses to boot without an explicit key (enforced in
        ``app.main``); outside production an ephemeral key keeps local
        development frictionless and is logged as a warning.
        """
        if not self.secret_key:
            self.secret_key = secrets.token_urlsafe(48)
        return self.secret_key


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_secret()
    return settings


settings = get_settings()
