"""Patrones de secretos y utilidades de detección/eliminación.

Centraliza la definición de "qué es un secreto" para que la usen tanto el
sanitizer (eliminar secretos del texto) como el vault (garantizar que ni los
valores ni las pistas de relevancia contengan secretos).
"""

from __future__ import annotations

import re

# (regex, reemplazo, etiqueta para el audit log)
SECRET_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
                re.DOTALL), "SECRET_REMOVED", "PRIVATE_KEY"),
    (re.compile(r"Authorization:\s*Bearer\s+[^\s\"']+", re.IGNORECASE),
     "Authorization: Bearer SECRET_REMOVED", "BEARER"),
    (re.compile(r"Set-Cookie:\s*[^\r\n]+", re.IGNORECASE),
     "Set-Cookie: COOKIE_REMOVED", "COOKIE"),
    (re.compile(r"Cookie:\s*[^\r\n]+", re.IGNORECASE),
     "Cookie: COOKIE_REMOVED", "COOKIE"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
     "JWT_REMOVED", "JWT"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]+"), "SECRET_REMOVED", "GITHUB_TOKEN"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}"), "SECRET_REMOVED", "GITHUB_TOKEN"),
    (re.compile(r"\bgh[opsu]_[A-Za-z0-9]{20,}"), "SECRET_REMOVED", "GITHUB_TOKEN"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "SECRET_REMOVED", "API_KEY"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "SECRET_REMOVED", "AWS_KEY"),
    # Tokens de proveedores conocidos (prefijos -> muy bajo falso positivo).
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "SECRET_REMOVED", "SLACK_TOKEN"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "SECRET_REMOVED", "GOOGLE_API_KEY"),
    (re.compile(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}"), "SECRET_REMOVED", "STRIPE_KEY"),
    (re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
     "SECRET_REMOVED", "SENDGRID_KEY"),
    (re.compile(r"\bglpat-[0-9A-Za-z_-]{20,}"), "SECRET_REMOVED", "GITLAB_TOKEN"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "SECRET_REMOVED", "NPM_TOKEN"),
    (re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "SECRET_REMOVED", "TWILIO_KEY"),
    (re.compile(r"AccountKey=[A-Za-z0-9+/=]{20,}", re.IGNORECASE),
     "AccountKey=SECRET_REMOVED", "AZURE_KEY"),
    # Credenciales clásicas: cualquier valor no vacío.
    (re.compile(r"\b(client_secret|password|passwd|access_token|refresh_token)\s*=\s*[^\s&\"']+",
                re.IGNORECASE), r"\1=SECRET_REMOVED", "CREDENTIAL_PARAM"),
    # Claves genéricas (api_key, secret_key, auth_token...): exige valor largo (≥8) anti-FP.
    (re.compile(r"\b(api[_-]?key|apikey|secret[_-]?key|auth[_-]?token|aws_secret_access_key)"
                r"\s*[=:]\s*['\"]?[A-Za-z0-9_\-./+]{8,}", re.IGNORECASE),
     r"\1=SECRET_REMOVED", "CREDENTIAL_PARAM"),
]

# Forma genérica de "esto huele a secreto" (salvaguarda en el vault).
SECRET_SHAPED = re.compile(
    r"(sk-|ghp_|github_pat_|gh[opsu]_|AKIA|eyJ[A-Za-z0-9_-]{5,}|"
    r"BEGIN [A-Z ]*PRIVATE KEY|password=|passwd=|client_secret=|"
    r"access_token=|refresh_token=|xox[baprs]-|AIza[0-9A-Za-z_-]{20,}|"
    r"[rs]k_(?:live|test)_|SG\.[A-Za-z0-9_-]{10,}\.|glpat-|npm_[A-Za-z0-9]{20,}|"
    r"AccountKey=|api[_-]?key\s*[=:]|secret[_-]?key\s*[=:]|"
    r"\bSK[0-9a-fA-F]{32}\b|auth[_-]?token\s*[=:])",
    re.IGNORECASE,
)


def _sentinel(label: str) -> str:
    return "COOKIE_REMOVED" if label == "COOKIE" else (
        "JWT_REMOVED" if label == "JWT" else "SECRET_REMOVED")


def scrub_secrets(text: str) -> tuple[str, dict[str, int]]:
    """Elimina secretos del texto. Devuelve (texto_limpio, conteo_por_etiqueta)."""
    counts: dict[str, int] = {}
    for pattern, replacement, label in SECRET_PATTERNS:
        def _sub(m, repl=replacement, lbl=label):
            counts[lbl] = counts.get(lbl, 0) + 1
            return m.expand(repl) if "\\1" in repl else repl
        text = pattern.sub(_sub, text)
    return text, counts


def looks_like_secret(text: str) -> bool:
    """True si el texto contiene algo con forma de secreto."""
    return bool(SECRET_SHAPED.search(text))
