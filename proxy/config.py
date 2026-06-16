"""Carga de configuración global (.env) y por caso (YAML/JSON)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv()

VALID_MODES = {"strict", "balanced", "reporting"}


@dataclass
class Settings:
    """Configuración global del proxy, leída del entorno."""

    anthropic_api_key: str = ""
    anthropic_base_url: str = "https://api.anthropic.com"
    anthropic_model: str = "claude-sonnet-4-6"
    proxy_local_api_key: str = "change-me"
    default_case_id: str = "default_case"
    storage_path: Path = field(default_factory=lambda: Path("./proxy_data"))
    encryption_key: str = ""
    default_mode: str = "strict"
    cases_path: Path = field(default_factory=lambda: Path("./cases"))


@dataclass
class CaseConfig:
    """Configuración de una auditoría concreta."""

    case_id: str
    provider: str = "claude"
    model: str | None = None
    mode: str = "strict"
    rehydrate_output: bool = False
    sensitive_domains: list[str] = field(default_factory=list)
    sensitive_keywords: list[str] = field(default_factory=list)


@lru_cache
def get_settings() -> Settings:
    mode = os.getenv("PROXY_MODE", "strict").strip().lower()
    if mode not in VALID_MODES:
        mode = "strict"
    return Settings(
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", "").strip(),
        anthropic_base_url=os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com").strip(),
        anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6").strip(),
        proxy_local_api_key=os.getenv("PROXY_LOCAL_API_KEY", "change-me"),
        default_case_id=os.getenv("PROXY_CASE_ID", "default_case").strip(),
        storage_path=Path(os.getenv("PROXY_STORAGE_PATH", "./proxy_data")),
        encryption_key=os.getenv("PROXY_ENCRYPTION_KEY", "").strip(),
        default_mode=mode,
        cases_path=Path(os.getenv("PROXY_CASES_PATH", "./cases")),
    )


def _load_case_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(text) or {}
    if path.suffix == ".json":
        return json.loads(text)
    return {}


def get_case_config(case_id: str) -> CaseConfig:
    """Devuelve la config del caso. Si no hay archivo, usa los defaults globales."""
    settings = get_settings()
    raw: dict = {}
    cases_dir = settings.cases_path
    if cases_dir.is_dir():
        for ext in (".yaml", ".yml", ".json"):
            candidate = cases_dir / f"{case_id}{ext}"
            if candidate.is_file():
                raw = _load_case_file(candidate)
                break

    mode = str(raw.get("mode", settings.default_mode)).strip().lower()
    if mode not in VALID_MODES:
        mode = settings.default_mode

    return CaseConfig(
        case_id=case_id,
        provider=str(raw.get("provider", "claude")),
        model=raw.get("model") or settings.anthropic_model,
        mode=mode,
        rehydrate_output=bool(raw.get("rehydrate_output", False)),
        sensitive_domains=[str(d).lower() for d in raw.get("sensitive_domains", [])],
        sensitive_keywords=[str(k) for k in raw.get("sensitive_keywords", [])],
    )
