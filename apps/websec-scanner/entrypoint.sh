#!/bin/sh
set -e
export HOME=/tmp

# Precarga de plantillas de Nuclei al ARRANCAR el contenedor (solo si el modo
# activo está habilitado), para que el primer escaneo no pague la descarga de
# las ~6.600 plantillas y no se agote el tiempo límite.
if [ "${ACTIVE_SCAN_ENABLED}" = "1" ] && command -v nuclei >/dev/null 2>&1; then
  echo "[entrypoint] Precargando plantillas de Nuclei (una sola vez)..."
  nuclei -update-templates -disable-update-check >/tmp/nuclei-templates.log 2>&1 || \
    echo "[entrypoint] aviso: no se pudieron precargar las plantillas; se bajarán en el primer escaneo."
fi

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
