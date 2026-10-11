FROM python:3.12-slim

# Usuario sin privilegios (no root dentro del contenedor)
RUN useradd -m -u 10001 scanner

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Nuclei (motor del modo activo; desactivado por defecto) ---
# Detectamos la arquitectura con dpkg (fiable también con el builder clásico de
# docker en la Raspberry Pi, donde TARGETARCH puede no estar definido). Las
# plantillas NO se clonan aquí: las precarga el entrypoint al arrancar, en /tmp.
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates && \
    ver=$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+' || true); \
    [ -z "$ver" ] && ver="3.3.9"; \
    case "$(dpkg --print-architecture)" in arm64) a=arm64;; armhf) a=armv6;; amd64) a=amd64;; *) a=amd64;; esac; \
    echo "Instalando Nuclei v${ver} para arch ${a}" && \
    curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${ver}/nuclei_${ver}_linux_${a}.zip" && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei && chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip && \
    apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# --- testssl.sh (análisis TLS a fondo; vendorizado en ./testssl.sh) ---
# Necesita bash, openssl (ya viene con ca-certificates), hexdump, ps y dig.
RUN apt-get update && apt-get install -y --no-install-recommends bsdextrautils procps dnsutils && \
    rm -rf /var/lib/apt/lists/*
COPY testssl.sh/testssl.sh /opt/testssl/testssl.sh
COPY testssl.sh/etc /opt/testssl/etc
RUN chmod +x /opt/testssl/testssl.sh

# Base de datos (historial, activos, auditoría): volumen montado en /data.
RUN mkdir -p /data && chown scanner:scanner /data

COPY app ./app
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER scanner
EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]
