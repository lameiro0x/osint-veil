# DESIGN.md — Norte de desarrollo

> Documento interno para no perder el rumbo durante el desarrollo.
> Define **objetivo**, **invariantes innegociables**, **arquitectura**,
> **modelo de datos**, **amenazas** y **fases**. Si una decisión de código
> contradice una invariante de aquí, la invariante gana.

---

## 1. Objetivo (una frase)

Permitir OSINT/auditorías **casi autónomas con Claude** reduciendo al mínimo
demostrable el flujo de datos reales hacia Anthropic: los hallazgos reales viven
cifrados en local, Claude solo recibe **referencias anotadas**, y se rehidrata en
local para el informe final.

---

## 2. Invariantes innegociables

Estas tres deciden si el sistema funciona o es teatro. No se negocian.

1. **Loop client-side.** El bucle agéntico y la ejecución de herramientas corren
   en NUESTRA máquina. Claude solo *decide* (emite `tool_use`); nuestro harness
   *ejecuta*. **Prohibido** usar server-side tools de Anthropic (web_search,
   web_fetch, code execution) o Managed Agents para el recon: harían el fetch en
   infra de Anthropic y verían el dato crudo, saltándose todo el pipeline.

2. **Egress bloqueado a nivel de red.** El único proceso con ruta a
   `api.anthropic.com` es el proxy. Las herramientas salen a internet (eso es el
   OSINT) pero NO pueden alcanzar Anthropic. Implementación a nivel de red
   (netns/iptables/firewall/contenedor), no "código educado". Si una tool con un
   `curl` puede llegar a la API, la invariante está rota.

3. **Tool output = hostil.** Todo lo que devuelve una herramienta (incluido
   contenido web) es no-confiable y NUNCA puede dar órdenes al orquestador.
   Defensa anti prompt-injection obligatoria: el contenido de tool results se
   encapsula como datos, jamás como instrucciones.

Invariantes de datos derivadas:

4. **Secretos = destroy.** Los secretos se destruyen antes del vault. No se
   guardan, no reciben token, no se rehidratan, no salen. (Ya implementado en
   `sanitizer.py` + salvaguarda en `storage.py`.)
5. **Nada real sale sin pasar por el pipeline.** Regla de oro heredada del proxy:
   nada llega a Claude sin sanitizar antes.
6. **Rehidratación solo en local y nunca hacia Claude.** Solo para el informe
   final del operador.

---

## 3. Verdad de diseño (asumida, no es bug)

Dos cosas salen en claro a Claude por necesidad:
- **El target** (lo que se investiga).
- **Relaciones/estructura** que el summarizer mande para que el análisis sirva.

El objetivo es minimizar TODO lo demás, no llegar a cero. Comunicarlo siempre así.

---

## 4. Arquitectura y flujo

```
[Operador] "OSINT de cliente.com"
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ ORQUESTADOR (loop LOCAL, con budget + scope + anti-injection) │
│  Claude decide la siguiente tool (recibe estado SEGURO)       │
└───────────────┬───────────────────────────────────────────────┘
                │ tool_use (propuesta)
                ▼
        [Tool Gateway]  allowlist + validación args + scope guard
                │ ejecuta (tool → internet OK; tool → Anthropic BLOQUEADO)
                ▼
        [Vault]  guarda hallazgo REAL cifrado (Fernet)
                ▼
        [Secret Scanner]  secretos → DESTROY (ni al vault)
                ▼
        [Policy Engine]  por dato: destroy | tokenize+vault | pass
                ▼
        [Summarizer local]  hallazgos → resumen seguro + pistas de relevancia
                ▼
        [Proxy/Tokenizer]  versión segura (tokens anotados)
                ▼
        [Egress Control]  único canal a Anthropic (+ ZDR)
                ▼
   Claude analiza versión segura → decide siguiente tool ──┐
                ▼                                            │
        [Audit log]  qué pasó (tipos+conteos, sin valores)  │
                └──── loop hasta: objetivo / budget / kill ─┘
                ▼
        Informe final (tokens) → REHIDRATACIÓN local desde vault → Operador
```

---

## 5. Componentes y estado actual

| Componente | Estado | Notas |
|---|---|---|
| Sanitizer (secretos+tokenizer) | ✅ existe (`proxy/sanitizer.py`) | Reusar. Extender a tokens anotados y a `tool_result`. |
| Storage cifrado por caso | ✅ existe (`proxy/storage.py`) | Reusar como base del **Vault**. Añadir campos de anotación. |
| Proxy OpenAI→Anthropic | ✅ existe (`proxy/claude_client.py`, `app.py`) | Reusar. Cero metadatos. |
| Audit log | ✅ existe | Reusar/ampliar. |
| **Tool Gateway** | ❌ nuevo | Allowlist + validación args + scope guard. |
| **Orquestador (loop client-side)** | ❌ nuevo | Manual agentic loop con `tool_use`/`tool_result`. |
| **Policy Engine** | 🟡 parcial (modos en config) | Formalizar reglas por tipo/acción. |
| **Summarizer local + pistas** | ❌ nuevo | Fase 1 reglas; fase 2 modelo local opcional. |
| **Egress Control** | ❌ nuevo | Nivel red. Doc + script de despliegue. |
| **Budget / kill-switch** | ❌ nuevo | Max iteraciones, token budget, wallclock. |
| **Anti prompt-injection** | ❌ nuevo | Encapsular tool output como datos. |
| **Approval gate (como política)** | ❌ nuevo | Por defecto auto-resuelve a privado; humano = escalado opcional, no bloqueante. |
| **UI** | ❌ nuevo | Ver hallazgos, configurar reglas, ver audit, lanzar auditorías. |

---

## 6. Tokens anotados (especificación)

El tokenizador no produce solo `TIPO_NNN`; produce **token + anotación de
relevancia segura**.

**Formato hacia Claude:**
```
SUBDOMAIN_047 [pista: patrones {vpn,corp,backup}; categoría: acceso remoto +
respaldo; relevancia: alta]
```

**Reglas:**
- La anotación describe **categoría, patrón y relevancia**, NUNCA el valor literal
  ni subcadenas sensibles.
- La anotación **pasa por el Secret Scanner** antes de salir (una pista descuidada
  podría filtrar: prohibido "el backup en 10.0.0.5").
- Se genera en local (Policy/Summarizer) a partir del valor real del vault.
- Se persiste en el vault junto al mapping para auditoría y para que el informe
  rehidratado pueda explicar por qué algo fue relevante.

**Modelo de vault (por token):**
```json
{
  "token": "SUBDOMAIN_047",
  "type": "SUBDOMAIN",
  "value": "vpn-corp-backup.cliente.com",   // cifrado en reposo
  "hint": "patrones {vpn,corp,backup}; acceso remoto + respaldo; relevancia alta",
  "first_seen": "2026-06-15T...",
  "source_tool": "amass"
}
```

---

## 7. Policy Engine (modelo de reglas)

Tres acciones por dato. Configurable por caso.
- `destroy` → secretos. Sin vault, sin token.
- `tokenize` → identificadores. Al vault + token anotado.
- `pass` → público de bajo riesgo. Sale en claro (configurable; en `strict`, casi nada).

El **approval gate** es una política, no un humano por defecto:
- Hallazgo marcado "sensible/escalable" → acción por defecto = `tokenize` + entra
  en una **cola de revisión NO bloqueante**. El loop sigue. El humano puede
  revisar después; si quiere desbloquear el valor real para el informe, lo hace en
  local. Nunca se manda el valor real a Claude por "aprobación".

---

## 8. Modelo de amenazas (qué nos puede joder)

| Amenaza | Mitigación |
|---|---|
| Tool habla directo con Anthropic | Egress control a nivel red (invariante 2). |
| Prompt injection desde web/recon | Tool output como datos, nunca instrucciones (invariante 3); el orquestador ignora "instrucciones" embebidas. |
| Loop infinito / coste explosivo | Budget: max iteraciones + token budget (`task_budget` de Anthropic) + wallclock + kill-switch. |
| Scope creep (investigar fuera del target) → riesgo legal | Scope guard en el Tool Gateway: cada arg validado contra el alcance autorizado. |
| Secretos al vault o a Claude | Secret Scanner antes del vault; salvaguarda que rechaza tokenizar valores con forma de secreto. |
| Pista de relevancia filtra dato real | La anotación pasa por el scanner; solo categorías/patrones. |
| Vault robado | Cifrado en reposo (Fernet); clave en `.env`/secrets manager, nunca en git. |
| Clave local del proxy débil | Forzar cambio del default; sin Bearer válido, 401. |
| Anthropic retiene datos | ZDR (acuerdo) + modelo compatible (Fable 5 NO va con ZDR; usar Sonnet/Opus). |

---

## 9. Decisiones tomadas

- **Modelo de orquestación:** manual agentic loop client-side. NO Managed Agents,
  NO server-side tools para recon.
- **Summarizer fase 1:** extracción estructurada por reglas (sin LLM local).
  Fase 2: modelo local opcional (Ollama) para resúmenes más ricos sin tocar
  Anthropic.
- **Automatización:** máxima posible. Intervención humana solo cuando aporta, vía
  cola de revisión NO bloqueante. Nunca bloquea el avance ni manda datos reales.
- **UI:** prioridad alta para usabilidad (ver hallazgos, reglas, audit, lanzar).
- **ZDR:** requisito de despliegue, no de código. Documentar.

---

## 10. Fases de desarrollo

**Fase 0 — base (hecho):** sanitizer, storage cifrado, proxy OpenAI→Anthropic,
audit log, tests.

**Fase 1 — tokens anotados + policy:** extender sanitizer/storage a anotaciones;
formalizar Policy Engine (destroy/tokenize/pass) configurable por caso.

**Fase 2 — orquestador client-side + tool gateway:** loop manual con
`tool_use`/`tool_result`; gateway con allowlist + validación args + scope guard;
sanitización de `tool_result`.

**Fase 3 — controles de seguridad del loop:** budget/kill-switch, anti-injection,
cola de aprobación no bloqueante.

**Fase 4 — egress control:** script/doc de despliegue que aísla la red (solo el
proxy alcanza Anthropic). Verificación.

**Fase 5 — summarizer local:** resúmenes con relaciones; fase 2 con modelo local
opcional.

**Fase 6 — UI:** panel para lanzar auditorías, ver hallazgos (rehidratados en
local), configurar reglas, leer audit log.

**Transversal:** tests por fase; reviewer valida antes de cerrar cada fase; nada
se da por terminado sin verificación.

---

## 11. Recordatorios para el desarrollador (yo)

- Si dudas, **la privacidad gana sobre la comodidad**.
- Nunca loguear, imprimir ni persistir valores reales fuera del vault cifrado.
- El audit log solo guarda **tipos + conteos**, jamás valores.
- Reusar lo de Fase 0; no reescribir lo que funciona.
- Cada pieza nueva: test que demuestre que NO filtra.
- "Casi completo" es la promesa honesta: target + relaciones salen; el resto no.
