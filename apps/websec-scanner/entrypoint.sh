#!/bin/sh
set -e
export HOME=/tmp

# Precarga de plantillas de Nuclei al ARRANCAR el contenedor (solo si el modo
# activo está habilitado), para que el primer escaneo no pague la descarga de
# las ~6.600 plantillas y no se agote el tiempo límite.
if [ "${ACTIVE_SCAN_ENABLED}" = "1" ] && command -v nuclei >/dev/null 2>&1; then
  echo "[entrypoint] Precargando plantillas de Nuclei (una sola vez, ~30s)..."
  # OJO: sin -disable-update-check, que anula la descarga. -ut descarga las plantillas.
  nuclei -ut >/tmp/nuclei-templates.log 2>&1 || true
  echo "[entrypoint] Plantillas .yaml descargadas: $(find /tmp/nuclei-templates -name '*.yaml' 2>/dev/null | wc -l)"
fi

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
