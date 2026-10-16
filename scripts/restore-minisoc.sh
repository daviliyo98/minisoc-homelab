#!/usr/bin/env bash
# MINISOC - restauracion de una copia de seguridad.
#
# ES DESTRUCTIVO: para el homelab, borra el estado actual y pone el de la copia.
# Por eso NO sobrescribe nada hasta haber verificado el paquete, y pide
# confirmacion explicita salvo que se le pase --si.
#
# Uso:
#   sudo ~/minisoc-homelab/scripts/restore-minisoc.sh              (lista y explica)
#   sudo ~/minisoc-homelab/scripts/restore-minisoc.sh <fichero>    (pregunta)
#   sudo ~/minisoc-homelab/scripts/restore-minisoc.sh <fichero> --si
#
# Se puede restaurar solo una parte con --solo repo|pihole|grafana|prometheus|portainer|scanner
set -euo pipefail

RAIZ="/home/pi/backups"
REPO="/home/pi/minisoc-homelab"
PIHOLE_DIR="/data/compose/1/etc-pihole"
STAGE="/tmp/restore-stage"

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }

declare -A CONTENEDOR=(
  [grafana]="grafana"
  [prometheus]="prometheus"
  [portainer]="portainer"
  [scanner]="websec-scanner"
)
declare -A VOLUMEN=(
  [grafana]="monitoring_grafana_data"
  [prometheus]="monitoring_prometheus_data"
  [portainer]="portainer_data"
  [scanner]="websec-scanner_websec-data"
)

# --- Sin argumentos: explicar y salir ---------------------------------------
if [ $# -eq 0 ]; then
  echo "Copias disponibles en $RAIZ:"
  ls -1t "$RAIZ"/minisoc-*.tar.zst 2>/dev/null | while read -r f; do
    printf "  %-40s %6s  %s\n" "$(basename "$f")" "$(du -h "$f" | cut -f1)" "$(date -r "$f" '+%F %T')"
  done
  echo
  echo "Uso: $0 <fichero.tar.zst> [--si] [--solo <parte>]"
  exit 0
fi

ARCHIVO="$1"; shift
ASUMIR=0; SOLO=""
while [ $# -gt 0 ]; do
  case "$1" in
    --si|--yes) ASUMIR=1 ;;
    --solo) SOLO="$2"; shift ;;
    *) echo "Opcion desconocida: $1" >&2; exit 1 ;;
  esac
  shift
done

[ -f "$ARCHIVO" ] || { echo "No existe: $ARCHIVO" >&2; exit 1; }

# --- 1. Verificar ANTES de tocar nada ---------------------------------------
log "Verificando el paquete (todavia no se ha tocado nada)"
( cd "$(dirname "$ARCHIVO")" && sha256sum -c "$(basename "$ARCHIVO").sha256" ) || {
  echo "ABORTO: el sha256 no cuadra. El paquete esta corrupto." >&2; exit 1; }
zstd -t "$ARCHIVO" >/dev/null 2>&1 || { echo "ABORTO: corrupto." >&2; exit 1; }

rm -rf "$STAGE"; mkdir -p "$STAGE"
tar --use-compress-program=unzstd -xf "$ARCHIVO" -C "$STAGE"
[ -f "$STAGE/minisoc/MANIFIESTO.txt" ] || { echo "ABORTO: sin manifiesto." >&2; exit 1; }

echo
echo "=== Que contiene esta copia ==="
cat "$STAGE/minisoc/MANIFIESTO.txt"
echo
echo "=== Que se va a SOBRESCRIBIR ==="
echo "  repo            $REPO"
echo "  pihole          $PIHOLE_DIR"
for k in "${!VOLUMEN[@]}"; do
  [ -n "$SOLO" ] && [ "$SOLO" != "$k" ] && continue
  echo "  volumen $k  (${VOLUMEN[$k]}) -> borra su contenido actual"
done

if [ "$ASUMIR" -ne 1 ]; then
  echo
  read -r -p "Escribe SI para continuar: " CONF
  [ "$CONF" = "SI" ] || { echo "Cancelado. No se ha tocado nada."; exit 1; }
fi

# --- 2. Parar contenedores ------------------------------------------------
PARADOS=()
trap 'if [ ${#PARADOS[@]} -gt 0 ]; then docker start "${PARADOS[@]}" >/dev/null 2>&1 || true; fi' EXIT

for k in "${!CONTENEDOR[@]}"; do
  [ -n "$SOLO" ] && [ "$SOLO" != "$k" ] && continue
  c="${CONTENEDOR[$k]}"
  if docker ps --format '{{.Names}}' | grep -qx "$c"; then
    log "Parando $c"; docker stop "$c" >/dev/null; PARADOS+=("$c")
  fi
done

# --- 3. Restaurar ----------------------------------------------------------
restaurar_repo() {
  log "Restaurando el repo"
  sudo -n rm -rf "$REPO.bak-restauracion"
  sudo -n mv "$REPO" "$REPO.bak-restauracion"
  sudo -n cp -a "$STAGE/minisoc/repo/minisoc-homelab" "$REPO"
  sudo -n chown -R pi:pi "$REPO"
  log "  el estado anterior queda en $REPO.bak-restauracion"
}

restaurar_volumen() {
  local v="$1" destino="/var/lib/docker/volumes/$1/_data"
  log "Restaurando el volumen $v"
  sudo -n rm -rf "${destino:?}"/* "${destino:?}"/.[!.]* 2>/dev/null || true
  sudo -n cp -a "$STAGE/minisoc/volumenes/$2/." "$destino/" 2>/dev/null || true
}

if [ -z "$SOLO" ] || [ "$SOLO" = "repo" ]; then restaurar_repo; fi
if [ -z "$SOLO" ] || [ "$SOLO" = "pihole" ]; then
  if [ -d "$STAGE/minisoc/pihole/etc-pihole" ]; then
    log "Restaurando la config de Pi-hole"
    sudo -n mkdir -p "$(dirname "$PIHOLE_DIR")"
    sudo -n rm -rf "${PIHOLE_DIR:?}"
    sudo -n cp -a "$STAGE/minisoc/pihole/etc-pihole" "$PIHOLE_DIR"
  fi
fi
for k in "${!VOLUMEN[@]}"; do
  if [ -z "$SOLO" ] || [ "$SOLO" = "$k" ]; then
    restaurar_volumen "${VOLUMEN[$k]}" "$k"
  fi
done

# --- 4. Arrancar -----------------------------------------------------------
log "Arrancando los contenedores"
docker start "${PARADOS[@]}" >/dev/null 2>&1 || true
PARADOS=()
# Lo que no estaba parado (pihole) tambien necesita arrancar tras restaurar su config
if [ -z "$SOLO" ] || [ "$SOLO" = "pihole" ]; then
  docker start pihole >/dev/null 2>&1 || true
fi
docker start grafana prometheus websec-scanner portainer >/dev/null 2>&1 || true

rm -rf "$STAGE"
log "=== Restauracion terminada ==="
log "En pie: $(docker ps --format '{{.Names}}' | tr '\n' ' ')"
log "Comprueba el portal: http://192.168.1.20:8090"