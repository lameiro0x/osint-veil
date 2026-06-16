#!/usr/bin/env bash
# Arranca el proxy en local. Requiere haber copiado .env.example a .env.
set -euo pipefail
cd "$(dirname "$0")"
exec uvicorn proxy.app:app --host 127.0.0.1 --port 8000 "$@"
