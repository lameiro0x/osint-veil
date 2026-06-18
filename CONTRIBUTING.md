# Contribuir a osint-veil

Gracias por el interés. Este proyecto prioriza una cosa por encima de todo:
**que no se filtren datos reales**. Toda contribución se evalúa primero por ahí.

## Entorno de desarrollo

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"      # incluye pytest y ruff
pytest -q                    # toda la suite
ruff check proxy tests       # lint
```

## Reglas de oro (no negociables)

1. **Nunca** loguear, imprimir ni persistir valores reales fuera del vault cifrado.
2. El **audit log** solo guarda tipos y conteos, jamás valores.
3. Los **secretos** se destruyen, no se tokenizan ni se almacenan.
4. La salida de herramientas es **dato no confiable**: nunca instrucciones.
5. Cualquier pieza nueva que toque datos necesita un **test que demuestre que NO
   filtra**.

## Estilo

- Sigue el estilo del código existente; `ruff` debe pasar limpio.
- Comentarios y mensajes en el idioma del fichero (mayormente español).
- Funciones pequeñas y claras; sin dependencias innecesarias.

## Añadir herramientas OSINT

Registra un `ToolSpec` (ver `proxy/gateway.py` para integradas y
`proxy/tools_external.py` para wrappers de binarios). Requisitos:

- `subprocess` **sin** `shell=True`, argumentos como lista.
- Valida el objetivo (host/dominio) antes de ejecutar.
- Declara `target_arg` para que el scope guard valide el alcance.
- Las herramientas **activas/intrusivas** van detrás de `allow_active`.

## Pull requests

- Un PR por cambio coherente, con tests.
- Describe qué dato podría verse afectado y por qué no se filtra.
- CI (ruff + pytest) debe estar en verde.
