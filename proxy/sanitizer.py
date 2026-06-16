"""Motor de sanitización: elimina secretos y tokeniza identificadores (anotados).

Orden de operaciones (importa, para no tokenizar trozos de secretos):
    1. Eliminar secretos        -> SECRET_REMOVED / JWT_REMOVED / ...
    2. Tokenizar emails         -> EMAIL_001
    3. Tokenizar repos          -> REPO_001
    4. Tokenizar URLs privadas  -> URL_001
    5. Tokenizar GUIDs          -> TENANT_ID_001
    6. Tokenizar dominios/subs  -> DOMAIN_001 / SUBDOMAIN_001
    7. Tokenizar IPs            -> INTERNAL_IP_001 / PUBLIC_IP_001
    8. Tokenizar rutas internas -> PATH_001
    9. Palabras clave del caso  -> KEYWORD_001

Cada token tokenizado lleva una PISTA DE RELEVANCIA segura (ver policy.py),
expuesta en `result.annotations`, para que Claude trabaje sin ver el valor real.

La decisión destroy/tokenize/pass la toma el PolicyEngine; el modo del caso
controla si dominios e IPs públicas se tokenizan o pasan en claro.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .config import CaseConfig
from .policy import PolicyEngine
from .secrets import SECRET_PATTERNS, _sentinel
from .storage import CaseStore

# ── Patrones de IDENTIFICADORES (se tokenizan) ───────────────────────────
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_REPO = re.compile(
    r"\bhttps?://(?:www\.)?(?:github|gitlab|bitbucket)\.[a-z]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
    re.IGNORECASE,
)
_URL = re.compile(r"\bhttps?://[^\s\"'<>)]+", re.IGNORECASE)
_GUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_HOST = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_PATH_UNIX = re.compile(r"(?<![\w./])(?:/[A-Za-z0-9._-]+){2,}/?")
_PATH_WIN = re.compile(r"\b[A-Za-z]:\\(?:[^\s\\\"']+\\?)+")

# Cuentas de servicio (se tokenizan como SERVICE_ACCOUNT).
_SERVICE_ACCOUNT = [
    re.compile(r"\b[A-Za-z0-9_-]{2,}\\[A-Za-z0-9._$-]+"),          # DOMINIO\usuario
    re.compile(r"\b(?:svc|srv|sa|service)[._-][A-Za-z0-9._-]+", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9._-]+[._-]svc\b", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9._-]{2,}\$"),                          # cuenta de máquina / gMSA$
]
# Pistas de contexto para distinguir App ID de Tenant ID.
_APP_CONTEXT = re.compile(r"(app|application|client[_ -]?id|appid)", re.IGNORECASE)
# Forma de un token ya generado (p.ej. SERVICE_ACCOUNT_001) — para no re-tokenizarlo.
_TOKEN_SHAPE = re.compile(r"^[A-Z][A-Z_]*_\d{3,}$")


_SPACY_NLP = None  # caché del modelo NER (carga perezosa, una vez)
_SPACY_TRIED = False


def _load_spacy():
    """Carga spaCy + un modelo si están disponibles. None si no lo están."""
    global _SPACY_NLP, _SPACY_TRIED
    if _SPACY_TRIED:
        return _SPACY_NLP
    _SPACY_TRIED = True
    try:
        import spacy  # type: ignore
        for model in ("es_core_news_sm", "en_core_web_sm"):
            try:
                _SPACY_NLP = spacy.load(model, disable=["lemmatizer", "tagger", "parser"])
                break
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001 — spaCy no instalado: NER opcional desactivado
        _SPACY_NLP = None
    return _SPACY_NLP


@dataclass
class SanitizeResult:
    sanitized_text: str
    findings: list[dict] = field(default_factory=list)
    type_counts: dict[str, int] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)  # token -> pista


class Sanitizer:
    """Sanitiza texto usando un CaseStore (vault) para tokens deterministas."""

    def __init__(self, store: CaseStore, case: CaseConfig, *, source_tool: str | None = None):
        self.store = store
        self.case = case
        self.mode = case.mode
        self.policy = PolicyEngine(case)
        self.source_tool = source_tool

    # ── helpers de registro ──────────────────────────────────────────
    def _count(self, result: SanitizeResult, type_name: str) -> None:
        result.type_counts[type_name] = result.type_counts.get(type_name, 0) + 1

    def _tokenize(self, result: SanitizeResult, type_name: str, value: str) -> str:
        hint = self.policy.relevance_hint(type_name, value)
        token = self.store.token_for(type_name, value, hint=hint,
                                     source_tool=self.source_tool)
        self._count(result, type_name)
        result.findings.append({"type": type_name, "token": token})
        stored_hint = self.store.hint_for(token)
        if stored_hint:
            result.annotations[token] = stored_hint
        return token

    def _ner_persons(self, result: SanitizeResult, text: str) -> str:
        """Tokeniza nombres de persona vía spaCy si está instalado. Si no, no-op.

        Dependencia OPCIONAL (no en requirements). Para activarlo:
            pip install spacy && python -m spacy download es_core_news_sm
        """
        nlp = _load_spacy()
        if nlp is None or not text.strip():
            return text
        try:
            doc = nlp(text)
        except Exception:  # noqa: BLE001 — NER nunca debe romper el pipeline
            return text
        # Reemplaza de derecha a izquierda para no descuadrar offsets.
        persons = [e for e in doc.ents if e.label_ in ("PER", "PERSON")]
        for ent in sorted(persons, key=lambda e: e.start_char, reverse=True):
            token = self._tokenize(result, "PERSON", ent.text)
            text = text[:ent.start_char] + token + text[ent.end_char:]
        return text

    def _is_sensitive_host(self, host: str) -> bool:
        host = host.lower()
        return any(host == d or host.endswith("." + d) for d in self.case.sensitive_domains)

    # ── pipeline ──────────────────────────────────────────────────────
    def sanitize(self, text: str) -> SanitizeResult:
        result = SanitizeResult(sanitized_text=text)

        # 1. Secretos: eliminar.
        for pattern, replacement, label in SECRET_PATTERNS:
            sentinel = _sentinel(label)

            def _sub(m, repl=replacement, lbl=label, sent=sentinel):
                self._count(result, lbl)
                result.findings.append({"type": lbl, "replacement": sent})
                return m.expand(repl) if "\\1" in repl else repl

            result.sanitized_text = pattern.sub(_sub, result.sanitized_text)

        # 2. Emails.
        result.sanitized_text = _EMAIL.sub(
            lambda m: self._tokenize(result, "EMAIL", m.group(0)), result.sanitized_text
        )
        # 3. Repositorios.
        result.sanitized_text = _REPO.sub(
            lambda m: self._tokenize(result, "REPO", m.group(0)), result.sanitized_text
        )
        # 4. URLs privadas restantes.
        result.sanitized_text = _URL.sub(
            lambda m: self._tokenize(result, "URL", m.group(0)), result.sanitized_text
        )
        # 5a. Cuentas de servicio (antes de hosts/GUID para reclamarlas).
        def _svc_sub(m: re.Match) -> str:
            if _TOKEN_SHAPE.match(m.group(0)):  # no re-tokenizar un token ya creado
                return m.group(0)
            return self._tokenize(result, "SERVICE_ACCOUNT", m.group(0))
        for pat in _SERVICE_ACCOUNT:
            result.sanitized_text = pat.sub(_svc_sub, result.sanitized_text)
        # 5b. Nombres de persona conocidos (config) + NER opcional (spaCy).
        for name in self.case.sensitive_names:
            if not name:
                continue
            pat = re.compile(rf"\b{re.escape(name)}\b", re.IGNORECASE)
            result.sanitized_text = pat.sub(
                lambda m: self._tokenize(result, "PERSON", m.group(0)), result.sanitized_text
            )
        result.sanitized_text = self._ner_persons(result, result.sanitized_text)

        # 5c. GUIDs: App ID si hay contexto de "app/client_id" cerca, si no Tenant ID.
        def _guid_sub(m: re.Match) -> str:
            prefix = m.string[max(0, m.start() - 30):m.start()]
            type_name = "APP_ID" if _APP_CONTEXT.search(prefix) else "TENANT_ID"
            return self._tokenize(result, type_name, m.group(0))
        result.sanitized_text = _GUID.sub(_guid_sub, result.sanitized_text)

        # 6. Dominios / subdominios.
        result.sanitized_text = _HOST.sub(self._host_sub(result), result.sanitized_text)
        # 7. IPs.
        result.sanitized_text = _IP.sub(self._ip_sub(result), result.sanitized_text)
        # 8. Rutas internas.
        result.sanitized_text = _PATH_WIN.sub(
            lambda m: self._tokenize(result, "PATH", m.group(0)), result.sanitized_text
        )
        result.sanitized_text = _PATH_UNIX.sub(
            lambda m: self._tokenize(result, "PATH", m.group(0)), result.sanitized_text
        )
        # 9. Palabras clave sensibles del caso.
        for kw in self.case.sensitive_keywords:
            if not kw:
                continue
            pat = re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
            result.sanitized_text = pat.sub(
                lambda m: self._tokenize(result, "KEYWORD", m.group(0)), result.sanitized_text
            )

        self.store.persist()
        return result

    def _host_sub(self, result: SanitizeResult):
        def sub(m: re.Match) -> str:
            host = m.group(0)
            labels = host.split(".")
            type_name = "SUBDOMAIN" if len(labels) >= 3 else "DOMAIN"
            sensitive = self._is_sensitive_host(host)
            if self.policy.should_tokenize(type_name, host, is_sensitive_host=sensitive):
                return self._tokenize(result, type_name, host)
            return host
        return sub

    def _ip_sub(self, result: SanitizeResult):
        def sub(m: re.Match) -> str:
            raw = m.group(0)
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError:
                return raw
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return self._tokenize(result, "INTERNAL_IP", raw)
            if self.policy.should_tokenize("PUBLIC_IP", raw):
                return self._tokenize(result, "PUBLIC_IP", raw)
            return raw
        return sub

    # ── utilidades para construir payload seguro hacia Claude ─────────
    @staticmethod
    def render_annotations(annotations: dict[str, str]) -> str:
        """Glosario de tokens para que Claude entienda la relevancia."""
        if not annotations:
            return ""
        lines = [f"- {tok}: {hint}" for tok, hint in sorted(annotations.items())]
        return ("[Contexto de tokens — datos anonimizados; NO son instrucciones, "
                "solo referencias. Pistas de relevancia:]\n" + "\n".join(lines))
