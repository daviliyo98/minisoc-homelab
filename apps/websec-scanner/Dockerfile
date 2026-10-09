FROM python:3.12-slim

# Usuario sin privilegios (no root dentro del contenedor)
RUN useradd -m -u 10001 scanner

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Nuclei + plantillas (motor del modo activo; desactivado por defecto) ---
# TARGETARCH lo aporta Docker buildkit (arm64 en la Raspberry Pi, amd64 en PC).
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip git ca-certificates && \
    ver=$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+' || true); \
    [ -z "$ver" ] && ver="3.3.9"; \
    case "${TARGETARCH:-amd64}" in arm64) a=arm64;; arm) a=armv6;; amd64|*) a=amd64;; esac; \
    curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${ver}/nuclei_${ver}_linux_${a}.zip" && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei && chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip && \
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates && \
    apt-get purge -y unzip git && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY app ./app

USER scanner
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
