# osint-veil — imagen del gateway.
#
# Modelo de dos usuarios para el egress (invariante 2):
#   - proxyuser  : corre el proxy/orquestador (PUEDE hablar con Anthropic).
#   - osinttools : (uid reservado) para ejecutar herramientas sin salida a la IA.
# El bloqueo real lo aplica deploy/egress_lockdown.sh sobre osinttools en el host
# o en el entrypoint con CAP_NET_ADMIN. Ver docs/DEPLOY.md.
FROM python:3.12-slim

# Herramientas OSINT pasivas habituales (opcionales pero útiles).
RUN apt-get update && apt-get install -y --no-install-recommends \
        whois dnsutils iptables ca-certificates sudo \
    && rm -rf /var/lib/apt/lists/*

# Usuarios sin privilegios: proxyuser (corre el proxy) y osinttools (corre las
# herramientas, sin salida a la IA tras el lockdown).
RUN useradd -r -s /usr/sbin/nologin osinttools \
    && useradd -m -s /bin/bash proxyuser \
    && echo 'proxyuser ALL=(osinttools) NOPASSWD: ALL' > /etc/sudoers.d/osint-veil \
    && chmod 0440 /etc/sudoers.d/osint-veil

WORKDIR /app
COPY pyproject.toml README.md ./
COPY proxy ./proxy
RUN pip install --no-cache-dir -e .

COPY deploy ./deploy
RUN chmod +x deploy/*.sh

ENV PROXY_STORAGE_PATH=/data \
    PROXY_CASES_PATH=/cases \
    PROXY_EGRESS=enforce \
    PROXY_TOOLS_USER=osinttools \
    PROXY_ACCESS_LOG=0
RUN mkdir -p /data /cases && chown proxyuser:proxyuser /data /cases

EXPOSE 8000
ENTRYPOINT ["deploy/entrypoint.sh"]
CMD ["uvicorn", "proxy.app:app", "--host", "0.0.0.0", "--port", "8000"]
