"""Policy Engine: decide qué se hace con cada dato y genera pistas de relevancia.

Tres acciones posibles por dato:
    destroy  -> secretos. Ni vault, ni token, ni pista.
    tokenize -> identificadores. Al vault + token anotado.
    pass     -> público de bajo riesgo. Sale en claro.

Las "pistas de relevancia" (hints) describen CATEGORÍA, PATRÓN y RELEVANCIA del
dato para que Claude trabaje bien, SIN revelar el valor literal. La pista solo
contiene palabras-categoría genéricas (vpn, backup, admin...), nunca el host
completo ni subcadenas identificativas del cliente. Además, en `storage.py` la
pista pasa por el scanner de secretos antes de salir.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import CaseConfig

# Tipos que SIEMPRE se tokenizan (independiente del modo).
_ALWAYS_TOKENIZE = {"EMAIL", "REPO", "URL", "TENANT_ID", "APP_ID", "PATH",
                    "INTERNAL_IP", "KEYWORD", "PERSON", "SERVICE_ACCOUNT"}

# Categorías de relevancia por palabra-patrón (orden = prioridad de relevancia).
# (palabras, etiqueta de categoría, nivel de relevancia)
_RELEVANCE_RULES: list[tuple[tuple[str, ...], str, str]] = [
    (("admin", "root", "manage", "panel", "console", "portal", "adm"),
     "administración / panel", "alta"),
    (("vpn", "remote", "rdp", "ssh", "citrix", "anyconnect", "gateway"),
     "acceso remoto", "alta"),
    (("backup", "bkp", "dump", "snapshot", "restore"),
     "respaldo / backup", "alta"),
    (("db", "sql", "mysql", "postgres", "mongo", "oracle", "mssql", "redis"),
     "base de datos", "alta"),
    (("internal", "intranet", "corp", "local", "lan", "priv"),
     "recurso interno corporativo", "alta"),
    (("payroll", "rrhh", "hr", "finance", "erp", "sap", "billing"),
     "datos de negocio sensibles", "alta"),
    (("git", "jenkins", "gitlab", "jira", "confluence", "nexus", "artifactory"),
     "devops / herramientas internas", "media"),
    (("api", "rest", "graphql", "ws", "service"),
     "API / integración", "media"),
    (("mail", "smtp", "imap", "owa", "exchange", "webmail", "correo"),
     "correo", "media"),
    (("dev", "test", "staging", "uat", "preprod", "qa", "sandbox", "demo"),
     "entorno no productivo", "media"),
]

# Relevancia base por tipo cuando no hay patrón de palabra.
_BASE_RELEVANCE = {
    "INTERNAL_IP": "alta",
    "TENANT_ID": "media",
    "APP_ID": "media",
    "REPO": "media",
    "EMAIL": "media",
    "SERVICE_ACCOUNT": "alta",
    "PATH": "baja",
}


@dataclass
class PolicyEngine:
    case: CaseConfig

    @property
    def mode(self) -> str:
        return self.case.mode

    def should_tokenize(self, type_name: str, value: str, *, is_sensitive_host: bool = False) -> bool:
        """¿Este dato debe tokenizarse (True) o puede pasar en claro (False)?

        Los secretos no llegan aquí (se destruyen antes). DOMAIN/SUBDOMAIN y
        PUBLIC_IP dependen del modo: en strict se tokeniza todo; en balanced/
        reporting solo si es host sensible (marcado en la config del caso).
        """
        if type_name in _ALWAYS_TOKENIZE:
            return True
        if type_name in ("DOMAIN", "SUBDOMAIN", "PUBLIC_IP"):
            return self.mode == "strict" or is_sensitive_host
        return True  # por defecto, anonimizar (la privacidad gana)

    def relevance_hint(self, type_name: str, value: str) -> str:
        """Pista segura de relevancia. NO incluye el valor literal completo.

        Solo expone palabras-categoría genéricas presentes en el dato (vpn,
        backup, admin...), la categoría inferida y un nivel de relevancia.
        """
        low = value.lower()
        matched: list[str] = []
        category: str | None = None
        relevance: str | None = None

        for words, cat, rel in _RELEVANCE_RULES:
            hit = [w for w in words if w in low]
            if hit:
                matched.extend(hit)
                if category is None:  # la primera regla (más prioritaria) manda
                    category, relevance = cat, rel

        if relevance is None:
            relevance = _BASE_RELEVANCE.get(type_name, "baja")

        parts: list[str] = [f"tipo: {type_name.lower()}"]
        if matched:
            # dedup preservando orden
            seen: list[str] = []
            for w in matched:
                if w not in seen:
                    seen.append(w)
            parts.append("patrones {" + ", ".join(seen) + "}")
        if category:
            parts.append(f"categoría: {category}")
        parts.append(f"relevancia: {relevance}")
        return "; ".join(parts)
