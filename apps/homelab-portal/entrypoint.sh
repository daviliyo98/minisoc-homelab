#!/bin/sh
set -e

# El catálogo se lee al arrancar. Si está mal, que falle aquí y no en la primera
# petición, que es cuando el usuario ya está mirando la pantalla en blanco.
if [ ! -r /app/services.yaml ]; then
  echo "[entrypoint] ERROR: no se encuentra /app/services.yaml (¿volumen sin montar?)" >&2
  exit 1
fi

if [ -z "${PORTAL_PASSWORD:-}" ]; then
  echo "[entrypoint] AVISO: sin PORTAL_PASSWORD el portal queda SIN AUTENTICAR." >&2
  echo "[entrypoint]         Aceptable solo si es accesible únicamente por el tailnet." >&2
fi

# En red host, atar a 0.0.0.0 pondría el portal a tiro de anyone de la LAN. Por eso
# se ata a la IP del tailnet: desde casa se sigue entrando igual por Tailscale.
BIND_HOST="${BIND_HOST:-100.114.119.53}"
BIND_PORT="${BIND_PORT:-8080}"
echo "[entrypoint] Escuchando en http://${BIND_HOST}:${BIND_PORT} (solo tailnet, no 0.0.0.0)"

exec uvicorn app.main:app --host "$BIND_HOST" --port "$BIND_PORT" --no-server-header