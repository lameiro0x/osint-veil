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
VALID_EGRESS = {"off", "warn", "enforce"}


class ConfigError(RuntimeError):
    """Configuración inválida que impide arrancar de forma segura."""


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
    egress_mode: str = "warn"        # off | warn | enforce
    egress_locked: bool = False      # lo pone el despliegue tras aplicar el lockdown de red
    tools_user: str = ""             # usuario sin salida a la IA para herramientas externas


@dataclass
class CaseConfig:
    """Configuración de una auditoría concreta."""

    case_id: str
    provider: str = "claude"
    model: str | None = None
    mode: str = "strict"
    rehydrate_output: bool = False
    store_secrets: bool = False  # guardar secretos hallados en local cifrado (auditoría)
    sensitive_domains: list[str] = field(default_factory=list)
    sensitive_keywords: list[str] = field(default_factory=list)
    sensitive_names: list[str] = field(default_factory=list)  # nombres de persona conocidos


@lru_cache
def get_settings() -> Settings:
    mode = os.getenv("PROXY_MODE", "strict").strip().lower()
    if mode not in VALID_MODES:
        mode = "strict"
    egress = os.getenv("PROXY_EGRESS", "warn").strip().lower()
    if egress not in VALID_EGRESS:
        egress = "warn"
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
        egress_mode=egress,
        egress_locked=os.getenv("PROXY_EGRESS_LOCKED", "0").strip() == "1",
        tools_user=os.getenv("PROXY_TOOLS_USER", "").strip(),
    )


def validate_settings(settings: Settings | None = None, *, require_api_key: bool = False
                      ) -> tuple[list[str], list[str]]:
    """Valida la config. Devuelve (errores_duros, avisos).

    Errores duros = no arrancar de forma segura. Avisos = degradación aceptable.
    """
    s = settings or get_settings()
    errors: list[str] = []
    warnings: list[str] = []

    if s.proxy_local_api_key in ("", "change-me"):
        errors.append("PROXY_LOCAL_API_KEY sigue siendo el valor por defecto. "
                      "Cámbiala por una clave larga y aleatoria.")
    if require_api_key and not s.anthropic_api_key:
        errors.append("ANTHROPIC_API_KEY no configurada (necesaria para llamar a Claude).")
    if not s.encryption_key:
        warnings.append("PROXY_ENCRYPTION_KEY vacía: el vault se guarda EN CLARO. "
                        "Genera una con 'python -m proxy.keygen'.")
    if s.egress_mode == "enforce" and not s.egress_locked:
        warnings.append("PROXY_EGRESS=enforce pero PROXY_EGRESS_LOCKED!=1: el OSINT "
                        "autónomo se negará a arrancar hasta aplicar el lockdown de red.")
    if s.egress_mode == "enforce" and s.egress_locked and not s.tools_user:
        warnings.append("PROXY_EGRESS=enforce y lockdown aplicado, pero PROXY_TOOLS_USER "
                        "está vacío: las herramientas externas correrían como el usuario "
                        "del proxy (con salida a la IA). Fija PROXY_TOOLS_USER.")
    if s.egress_mode != "enforce":
        warnings.append(f"PROXY_EGRESS={s.egress_mode}: el egress no se fuerza. En "
                        "producción usa 'enforce' + deploy/egress_lockdown.sh.")
    return errors, warnings


def _load_case_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        if path.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(text) or {}
        elif path.suffix == ".json":
            data = json.loads(text)
        else:
            return {}
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Config de caso inválida en {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Config de caso inválida en {path}: se esperaba un objeto.")
    for key in ("sensitive_domains", "sensitive_keywords", "sensitive_names"):
        if key in data and not isinstance(data[key], list):
            raise ConfigError(f"Config de caso inválida en {path}: '{key}' debe ser una lista.")
    return data


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
        store_secrets=bool(raw.get("store_secrets", False)),
        sensitive_domains=[str(d).lower() for d in raw.get("sensitive_domains", [])],
        sensitive_keywords=[str(k) for k in raw.get("sensitive_keywords", [])],
        sensitive_names=[str(n) for n in raw.get("sensitive_names", [])],
    )
