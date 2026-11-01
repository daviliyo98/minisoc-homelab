#!/usr/bin/env bash
# MINISOC - copia de seguridad verificada de todo el estado del homelab.
#
# Qué protege:
#   - el repo minisoc-homelab, INCLUIDOS los .env (si se pierden, se pierden las
#     claves de la API del scanner y del portal: no son recuperables)
#   - etc-pihole (config y blocklists de Pi-hole, vive FUERA del repo)
#   - los volúmenes Docker con estado persistente
#   - la configuración de host que no se regenera sola (nftables, sshd, cron)
#   - Home Assistant (su config/ va dentro del repo) y el historial del portal
#
# Por qué para los contenedores antes de copiar: Prometheus usa un TSDB con WAL
# y Grafana, Portainer, el scanner, Home Assistant y el portal usan SQLite. Copiar
# en caliente puede dar un fichero inconsistente que no restaura. La parada es de
# unos segundos.
#
# Riesgo aceptado: parar Pi-hole deja la red sin DNS ~4 s (a las 04:3x, cuando nadie
# navega). Se prefiere a una copia en caliente de su SQLite que podría no restaurar.
# El portal tiene una ventana de mantenimiento a esa hora (PORTAL_MANTENIMIENTO)
# para que estas paradas no salgan como caídas.
#
# "Verificada" significa que NO basta con generar el fichero: se comprueba el
# sha256, se lista el contenido y se extrae a un directorio temporal para
# confirmar que algo real sale de dentro.
#
# Uso:  sudo ~/minisoc-homelab/scripts/backup-minisoc.sh
set -euo pipefail

# El paquete lleva TODOS los .env con secretos. Sin esto, root crea el .tar.zst con
# permisos 644 (legible por cualquier usuario de la Pi) y lo mismo el directorio de
# trabajo en /tmp mientras dura la copia. Con 077 solo root puede leerlos.
umask 077

FECHA="$(date +%Y%m%d-%H%M)"
RAIZ="/home/pi/backups"
STAGE="/tmp/backup-stage-$FECHA"
PAQUETE="$RAIZ/minisoc-$FECHA.tar.zst"
LOG="/var/log/minisoc-backup.log"
RETENCION_DIAS="${RETENCION_DIAS:-7}"

REPO="/home/pi/minisoc-homelab"
PIHOLE_DIR="/data/compose/1/etc-pihole"

# Contenedores con estado persistente que hay que parar para copiar bien.
# Pi-hole va el último: así es el que menos tiempo pasa parado (DNS de toda la casa).
CONTAINERS=(grafana prometheus websec-scanner portainer homeassistant homelab-portal pihole)

# Volúmenes a copiar (nombre -> ruta en el paquete)
declare -A VOLUMENES=(
  [monitoring_grafana_data]="grafana"
  [monitoring_prometheus_data]="prometheus"
  [portainer_data]="portainer"
  [websec-scanner_websec-data]="websec-scanner"
  [homelab-portal_portal-data]="homelab-portal"   # historial, alertas, dispositivos vistos
)

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
die() { log "ERROR: $*"; exit 1; }

# --- Garantía de que los contenedores vuelven a estar en pie ---------------
# Si el script muere entre el stop y el arranque, un trap los levanta. Sin esto,
# un fallo a mitad de copia deja el homelab apagado.
PARADOS=()
restaurar() {
  local rc=$?
  if [ ${#PARADOS[@]} -gt 0 ]; then
    log "Restaurando contenedores: ${PARADOS[*]}"
    docker start "${PARADOS[@]}" >/dev/null 2>&1 || true
  fi
  [ $rc -ne 0 ] && log "El backup fallo con codigo $rc"
  exit $rc
}
trap restaurar EXIT

mkdir -p "$RAIZ"
# El directorio y los paquetes que ya existían (creados antes del umask) solo para root.
chmod 700 "$RAIZ"
find "$RAIZ" -maxdepth 1 -type f -name 'minisoc-*' -exec chmod 600 {} +

# --- 1. Preflight ----------------------------------------------------------
log "=== Backup $FECHA ==="
for c in zstd sha256sum tar; do
  command -v "$c" >/dev/null || die "falta la herramienta $c"
done
LIBRE_GB=$(df --output=avail -BG / | tail -1 | tr -dc '0-9')
[ "$LIBRE_GB" -ge 2 ] || die "solo ${LIBRE_GB}G libres; hacen falta 2G"
log "Espacio libre: ${LIBRE_GB}G"

rm -rf "$STAGE"; mkdir -p "$STAGE/minisoc"/{repo,pihole,volumenes,host,volumenes}

# --- 2. Manifiesto: qué se ha copiado y con qué versiones ------------------
{
  echo "MINISOC - copia de seguridad"
  echo "Fecha:       $(date -Is)"
  echo "Host:        $(hostname)"
  echo "Kernel:      $(uname -r)"
  echo "SO:          $(. /etc/os-release && echo "$PRETTY_NAME")"
  echo "Paquetes:    $(dpkg -l | grep -c '^ii') instalados"
  echo
  echo "Contenedores:"
  for c in "${CONTAINERS[@]}"; do
    echo "  $c -> $(docker inspect "$c" --format '{{.Config.Image}}' 2>/dev/null || echo AUSENTE)"
  done
  echo
  echo "Volumenes:"
  for v in "${!VOLUMENES[@]}"; do echo "  $v"; done
} > "$STAGE/minisoc/MANIFIESTO.txt"

# --- 3. Parar contenedores con estado -------------------------------------
for c in "${CONTAINERS[@]}"; do
  if docker ps --format '{{.Names}}' | grep -qx "$c"; then
    log "Parando $c"
    docker stop "$c" >/dev/null
    PARADOS+=("$c")
  fi
done

# --- 4. Copiar -------------------------------------------------------------
log "Copiando el repo (incluye .env con secretos)"
cp -a "$REPO" "$STAGE/minisoc/repo/minisoc-homelab"

if [ -d "$PIHOLE_DIR" ]; then
  log "Copiando la config de Pi-hole (71 MB, fuera del repo)"
  cp -a "$PIHOLE_DIR" "$STAGE/minisoc/pihole/etc-pihole"
else
  log "AVISO: $PIHOLE_DIR no existe; el backup de Pi-hole queda vacio"
fi

for v in "${!VOLUMENES[@]}"; do
  ORIGEN="/var/lib/docker/volumes/$v/_data"
  if [ -d "$ORIGEN" ]; then
    log "Copiando volumen $v -> ${VOLUMENES[$v]}"
    mkdir -p "$STAGE/minisoc/volumenes/${VOLUMENES[$v]}"
    cp -a "$ORIGEN/." "$STAGE/minisoc/volumenes/${VOLUMENES[$v]}/"
  else
    log "AVISO: el volumen $v no existe"
  fi
done

log "Copiando configuracion de host"
mkdir -p "$STAGE/minisoc/host"
for f in /etc/nftables.conf /etc/ssh/sshd_config; do
  [ -f "$f" ] && cp -a "$f" "$STAGE/minisoc/host/" || log "  (no existe $f)"
done
[ -d /etc/cron.d ] && cp -a /etc/cron.d "$STAGE/minisoc/host/cron.d"
# Configuracion de CrowdSec: decisiones del bouncer, no se regeneran solas
if [ -d /etc/crowdsec ]; then
  cp -a /etc/crowdsec "$STAGE/minisoc/host/crowdsec"
fi

# --- 5. Volver a levantar --------------------------------------------------
log "Arrancando los contenedores"
docker start "${PARADOS[@]}" >/dev/null 2>&1 || true
PARADOS=()   # ya arrancados: el trap ya no tiene nada que hacer
log "Contenedores en pie: $(docker ps --format '{{.Names}}' | wc -l)"

# --- 6. Comprimir ----------------------------------------------------------
log "Comprimiendo (zstd -10)"
tar -C "$STAGE" -cf - minisoc | zstd -10 -T0 -o "$PAQUETE" -q
rm -rf "$STAGE"
TAM="$(du -h "$PAQUETE" | cut -f1)"
log "Paquete: $PAQUETE ($TAM)"

# --- 7. VERIFICAR (esto es lo que la hoja de ruta daba por hecho) ---------
log "--- verificacion ---"

sha256sum "$PAQUETE" > "$PAQUETE.sha256"
sha256sum -c "$PAQUETE.sha256" >> "$LOG" 2>&1 || die "el sha256 no cuadra"
log "  sha256 correcto"

zstd -t "$PAQUETE" >/dev/null 2>&1 || die "el archivo comprimido esta corrupto"
log "  integridad zstd correcta"

N_ENTRADAS=$(tar --use-compress-program=unzstd -tf "$PAQUETE" | wc -l)
[ "$N_ENTRADAS" -gt 100 ] || die "solo $N_ENTRADAS entradas; suspiciously pocas"
log "  $N_ENTRADAS entradas en el archivo"

# La prueba que de verdad importa: extraer y comprobar que sale contenido real.
TMPV=$(mktemp -d)
tar --use-compress-program=unzstd -xf "$PAQUETE" -C "$TMPV"
for ESPERADO in \
  "minisoc/MANIFIESTO.txt" \
  "minisoc/repo/minisoc-homelab/apps/homelab-portal/.env" \
  "minisoc/repo/minisoc-homelab/apps/websec-scanner/.env" \
  "minisoc/pihole/etc-pihole" \
  "minisoc/host/nftables.conf"
do
  [ -e "$TMPV/$ESPERADO" ] || die "en la prueba de restauracion falta: $ESPERADO"
done
REALES=$(find "$TMPV" -type f | wc -l)
rm -rf "$TMPV"
log "  restauracion de prueba correcta ($REALES ficheros extraidos)"
log "  los .env con secretos estan dentro"

# --- 8. Retencion ----------------------------------------------------------
log "--- retencion: ultimos $RETENCION_DIAS dias ---"
find "$RAIZ" -name 'minisoc-*.tar.zst' -mtime "+$RETENCION_DIAS" -print -delete | while read -r v; do
  log "  borrado $(basename "$v")"; rm -f "$v.sha256"
done

ln -sfn "$PAQUETE" "$RAIZ/ultimo-minisoc.tar.zst"
log "=== Backup correcto: $PAQUETE ($TAM) ==="
