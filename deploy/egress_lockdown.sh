#!/usr/bin/env bash
#
# Egress lockdown (capa 2 de 2) — la GARANTÍA real de la invariante 2:
# "solo el proxy puede hablar con Anthropic; las herramientas no".
#
# La capa de software (proxy/egress.py) es una salvaguarda, pero no puede impedir
# que un binario externo abra su propio socket. Esto SÍ, a nivel de red.
#
# Modelo: dos usuarios del sistema.
#   - proxy_user  : ejecuta el proxy/orquestador. PUEDE salir a Anthropic.
#   - tools_user  : ejecuta las herramientas OSINT. NO puede salir a Anthropic,
#                   pero sí al resto de internet (eso es el OSINT).
#
# Uso (como root):
#   PROXY_USER=proxyuser TOOLS_USER=osinttools ./deploy/egress_lockdown.sh
#
# Requiere iptables con módulo owner (uid match) y resolución de los dominios
# del proveedor. Revisa/ajusta a tu entorno antes de aplicar en producción.
set -euo pipefail

PROXY_USER="${PROXY_USER:-proxyuser}"
TOOLS_USER="${TOOLS_USER:-osinttools}"

# Dominios del proveedor de IA que las herramientas NO pueden alcanzar.
AI_DOMAINS=("api.anthropic.com" "anthropic.com" "claude.ai")

echo "[*] Bloqueando egress de '$TOOLS_USER' hacia el proveedor de IA…"

for domain in "${AI_DOMAINS[@]}"; do
  # Resuelve todas las IPs actuales del dominio.
  for ip in $(getent ahosts "$domain" | awk '{print $1}' | sort -u); do
    iptables -A OUTPUT -m owner --uid-owner "$TOOLS_USER" -d "$ip" -p tcp --dport 443 \
      -j REJECT --reject-with icmp-admin-prohibited
    echo "    bloqueado $domain ($ip) para uid $TOOLS_USER"
  done
done

echo "[*] '$PROXY_USER' mantiene salida libre (incluida la API de Anthropic)."
echo "[!] NOTA: las IPs de Anthropic cambian. Reaplica este script periódicamente,"
echo "    o mejor aún, fuerza el tráfico del proxy por un egress proxy/allowlist"
echo "    de dominios (Squid, etc.) y deniega por defecto al resto."
echo "[✓] Lockdown aplicado. Verifícalo: como '$TOOLS_USER', un 'curl https://api.anthropic.com'"
echo "    debe fallar; el proxy debe funcionar."
