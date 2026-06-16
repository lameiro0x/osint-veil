"""Configuración común de tests: storage temporal y entorno controlado."""

import os
import tempfile

# Debe ejecutarse antes de importar cualquier módulo de `proxy` (lru_cache).
_TMP = tempfile.mkdtemp(prefix="proxy_test_")
os.environ["PROXY_STORAGE_PATH"] = _TMP
os.environ["PROXY_CASES_PATH"] = os.path.join(os.path.dirname(__file__), "fixtures_cases")
os.environ["PROXY_LOCAL_API_KEY"] = "test-key"
os.environ["PROXY_MODE"] = "strict"
os.environ.setdefault("ANTHROPIC_API_KEY", "")

os.makedirs(os.environ["PROXY_CASES_PATH"], exist_ok=True)
