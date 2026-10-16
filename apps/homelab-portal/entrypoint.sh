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

# Interfaz de escucha. 0.0.0.0 = LAN + tailnet (lo protege la clave de .env).
# Fijarlo a una IP concreta lo deja accesible solo por esa vía: p.ej. la del tailnet
# para no exponer el catálogo en la LAN.
# No se usa el 8080: crowdsec ya ocupa 127.0.0.1:8080 en el host, y atar a
# 0.0.0.0:8080 falla con EADDRINUSE ("address already in use").
BIND_HOST="${BIND_HOST:-0.0.0.0}"
BIND_PORT="${BIND_PORT:-8090}"
echo "[entrypoint] Escuchando en http://${BIND_HOST}:${BIND_PORT} (host=${BIND_HOST})"

exec uvicorn app.main:app --host "$BIND_HOST" --port "$BIND_PORT" --no-server-header