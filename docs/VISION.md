# Privacy Gateway para OSINT con IA — Visión y Valor

> Documento para entender **qué es**, **para qué sirve** y **por qué aporta**.
> Pensado para que lo entienda cualquiera, técnico o no.

---

## 1. El problema en una frase

Quieres usar una IA potente (Claude) para hacer OSINT y auditorías de seguridad
casi solas, **pero no quieres que los datos reales del cliente, de tu empresa o
tuyos salgan hacia la IA**. Hoy, si le pides a una IA "haz OSINT de esta web", la
IA ve y procesa todo lo que encuentra: correos, IPs internas, subdominios,
credenciales filtradas… Todo eso sale de tu máquina.

Este proyecto resuelve eso.

---

## 2. Qué es, explicado fácil

Imagina un **filtro de seguridad inteligente** que se sienta entre tus
herramientas de hacking y la IA. La IA dirige la investigación (decide qué mirar),
pero **nunca toca los datos crudos**. Todo lo sensible se queda en tu ordenador,
cifrado. A la IA solo le llegan **etiquetas con una pista de qué son**, nunca el
valor real.

Analogía: es como mandar a un detective a investigar un caso, pero en vez de
darle los expedientes con nombres reales, le das fichas anónimas tipo
*"Persona A: directivo con acceso a finanzas"*. El detective razona igual de bien,
resuelve el caso, y los nombres reales nunca salen de la caja fuerte. Al final,
**tú** cambias las fichas por los nombres reales en tu informe — en local.

---

## 3. Las 7 piezas (qué hace cada una)

| Pieza | Qué hace, en simple |
|---|---|
| **Tool Gateway** | Portero de herramientas. Decide qué herramientas puede usar la IA y revisa cómo las usa (que no se salga del objetivo autorizado). |
| **Vault local cifrado** | La caja fuerte. Guarda los hallazgos **reales** cifrados en tu máquina. La IA nunca entra aquí. |
| **Secret Scanner** | El detector de secretos. Antes de enviar nada, busca contraseñas, claves, tokens… y los **destruye** (ni se guardan). |
| **Policy Engine** | El motor de reglas. Decide, dato por dato: ¿esto se destruye, se anonimiza, o puede pasar tal cual? Tú configuras las reglas. |
| **Proxy / Tokenizador** | El traductor. Cambia datos reales por etiquetas anónimas (`EMAIL_001`) **con una pista de relevancia** para que la IA siga entendiendo. |
| **Egress Control** | El muro. Impide que cualquier herramienta hable directamente con la IA. El **único** camino hacia Claude es el filtro. |
| **Registro de privacidad** | El diario. Anota qué tipos de datos se censuraron y cuántas veces. Nunca guarda el dato real. Te da pruebas de qué salió y qué no. |

Encima de todo: **ZDR (Zero Data Retention)** — un acuerdo con Anthropic para que
**no guarden** nada de lo que llega. El filtro controla *qué sale*; ZDR garantiza
que *lo poco que sale no se queda* en sus servidores.

---

## 4. La idea clave: etiquetas con contexto (tokens anotados)

El mayor problema de anonimizar es perder calidad: si a la IA le das
`SUBDOMAIN_047` a secas, no puede saber que era importante.

**Solución:** cada etiqueta lleva una pista de relevancia, **sin revelar el dato real**.

Ejemplo real:

- Dato crudo (se queda en el vault, cifrado):
  `vpn-corp-backup.cliente.com`
- Lo que recibe Claude:
  `SUBDOMAIN_047 [pista: subdominio con patrones "vpn", "corp", "backup";
  sugiere acceso remoto + respaldo corporativo; posible objetivo de alto valor]`

Así Claude **entiende la relevancia y trabaja bien** ("ese host de backup VPN es
prioritario, profundiza ahí") sin haber visto nunca el nombre real. La pista la
genera tu máquina y también pasa por el detector de secretos, así que **la pista
tampoco filtra datos sensibles** — habla de categorías y patrones, no de valores.

---

## 5. Cómo funciona, paso a paso (con ejemplo)

**Tú dices:** *"Haz OSINT de cliente.com."*

1. **Claude (orquestador)** decide: "primero, enumerar subdominios". Pide ejecutar
   la herramienta `amass`.
2. **Tool Gateway** comprueba: ¿`amass` está permitida? ¿el objetivo está dentro
   del scope autorizado? Sí → la ejecuta **en tu máquina**.
3. La herramienta encuentra: `vpn-corp-backup.cliente.com`, `mail.cliente.com`,
   y un dump con `password=Sup3rSecret123`.
4. **Todo eso va al Vault** (cifrado, en local).
5. **Secret Scanner**: detecta `password=Sup3rSecret123` → **lo destruye**. No se
   guarda, no se etiqueta, no existe para Claude.
6. **Policy Engine**: decide que los subdominios del cliente son sensibles →
   anonimizar; un subdominio público genérico → puede pasar.
7. **Tokenizador**: `vpn-corp-backup.cliente.com` → `SUBDOMAIN_047` + pista de
   relevancia.
8. **Egress Control**: lo único que puede salir hacia Claude es esta versión
   segura, por el proxy. Las herramientas no tienen otra ruta.
9. **Claude recibe la versión segura**, la analiza: *"SUBDOMAIN_047 parece un
   backup de VPN, alta prioridad; recomiendo escanear puertos."* Decide la
   siguiente herramienta. **El bucle se repite solo.**
10. Cuando termina, Claude entrega un **informe final** con etiquetas. Tu máquina
    lo **rehidrata** desde el vault: `SUBDOMAIN_047` vuelve a ser
    `vpn-corp-backup.cliente.com`. **Solo tú ves el informe real.**

Durante todo el proceso, el **registro de privacidad** anota: "se censuraron 12
subdominios, 3 emails, 1 secreto; 0 datos reales enviados".

---

## 6. Qué aporta de verdad

- **OSINT y auditorías casi completas con IA**, con mínima intervención humana.
- **Reducción drástica y demostrable** del flujo de datos reales hacia la IA.
  No es "creo que no filtré nada": es "aquí está el registro que lo prueba".
- **No pierdes datos**: lo real se guarda cifrado en local y se recupera para el
  informe final.
- **La IA sigue siendo útil** gracias a las pistas de relevancia.
- **Automático pero con jaula**: avanza solo, pero con límites de gasto, control
  de alcance y defensa contra manipulación.
- **Fácil de usar y de ver**: interfaz amigable para lanzar auditorías, ver
  hallazgos, configurar reglas y revisar el registro.

---

## 7. Para quién es

- **Pentesters y equipos de auditoría** que quieren acelerar el OSINT con IA sin
  romper acuerdos de confidencialidad (NDA) con el cliente.
- **Analistas CTI / OSINT** que manejan datos sensibles y no pueden mandarlos en
  claro a servicios externos.
- **Empresas con datos regulados** (salud, banca, legal) que necesitan probar que
  controlan qué sale hacia proveedores de IA.

---

## 8. La verdad honesta (sin humo)

Esta herramienta logra **"casi"** completo, no "cero absoluto". Dos cosas salen
siempre en claro a la IA, **por diseño**:

1. **El objetivo** (`cliente.com`): es lo que se investiga; ocultarlo haría
   imposible el OSINT.
2. **Las relaciones/estructura** que el resumidor decida mandar para que el
   análisis sea útil.

Todo lo demás — secretos, IPs internas, credenciales, identificadores — se queda
en local. Eso es una **reducción enorme y auditada** del riesgo de fuga, no magia.
Con ZDR encima, lo poco que sale tampoco se retiene.

En resumen: **no elimina el riesgo al 100%, pero lo reduce al mínimo razonable y
te da pruebas de ello** — que es exactamente lo que necesitas para trabajar con IA
en auditorías reales.
