"""Layered application settings.

Order (later overrides earlier):
    1. Built-in defaults below
    2. /etc/huntersec/config.yaml (system)
    3. ~/.config/huntersec/config.yaml (user)
    4. ./.huntersec.yaml (project)
    5. Environment variables prefixed HUNTERSEC_
    6. CLI flags (passed to constructors directly)
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMSettings(BaseSettings):
    """LLM provider credentials and routing knobs."""

    model_config = SettingsConfigDict(env_prefix="HUNTERSEC_", extra="ignore")

    anthropic_api_key: SecretStr | None = None
    openai_api_key: SecretStr | None = None
    gemini_api_key: SecretStr | None = None
    ollama_host: str = "http://localhost:11434"

    default_provider: Literal["anthropic", "openai", "gemini", "ollama"] = "anthropic"
    smart_model: str = "claude-sonnet-4-6"
    cheap_model: str = "claude-haiku-4-5-20251001"
    local_model: str = "qwen2.5:14b"

    token_budget_per_session: int = Field(default=50_000, gt=0)
    request_timeout_seconds: float = Field(default=60.0, gt=0)


class SandboxSettings(BaseSettings):
    """Docker sandbox configuration. Safe defaults — fail closed."""

    model_config = SettingsConfigDict(env_prefix="HUNTERSEC_SANDBOX_", extra="ignore")

    image: str = "huntersec/kali:latest"
    runtime: Literal["runc", "runsc"] = "runc"  # runsc = gVisor
    network_mode: Literal["bridge", "internal", "none"] = "bridge"
    memory_limit: str = "2g"
    cpu_limit: float = 2.0
    pids_limit: int = 200
    default_timeout_seconds: int = Field(default=300, gt=0)
    rootless: bool = True


class SafetySettings(BaseSettings):
    """Safety-layer toggles. Most are intentionally non-configurable to runtime —
    only paths and thresholds are exposed."""

    model_config = SettingsConfigDict(env_prefix="HUNTERSEC_SAFETY_", extra="ignore")

    scope_file: Path = Path("configs/scope.yaml")
    blocklist_file: Path = Path("configs/blocklist.yaml")
    audit_log_dir: Path = Path("data/audit")

    rate_limit_per_target_rps: float = Field(default=10.0, gt=0)
    rate_limit_global_rps: float = Field(default=100.0, gt=0)

    dry_run_default: bool = True  # require explicit --execute
    require_scope: bool = True


class Settings(BaseSettings):
    """Top-level application settings."""

    model_config = SettingsConfigDict(env_prefix="HUNTERSEC_", extra="ignore")

    project_root: Path = Path(__file__).resolve().parent.parent.parent
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "console"] = "console"

    llm: LLMSettings = Field(default_factory=LLMSettings)
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    safety: SafetySettings = Field(default_factory=SafetySettings)


def get_settings() -> Settings:
    """Return a cached settings instance.

    Returns:
        Validated :class:`Settings`. Raises :class:`pydantic.ValidationError`
        on misconfiguration.
    """
    return Settings()
