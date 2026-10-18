#!/usr/bin/env bash
# MINISOC - Fase 2: desactiva la autenticación por contraseña en SSH.
#
# EL RIESGO: si algo va mal, te quedas sin acceso a la Pi por red, y la única
# salida es un teclado y una pantalla. Por eso NO es un simple "cambiar una
# línea": este script se autodeshace solo si no confirmas el acceso.
#
# Red de seguridad en tres capas:
#   1. Exige que exista una clave autorizada antes de tocar nada.
#   2. Valida la sintaxis con `sshd -t` ANTES de recargar.
#   3. Programa un revert automático a 10 minutos con systemd-run. Si el script
#      termina bien, cancela el revert. Si mueres a mitad o no te entra, la
#      configuración anterior vuelve sola.
set -euo pipefail

SSHD=/etc/ssh/sshd_config
DROPIN_DIR=/etc/ssh/sshd_config.d
STAMP="$(date +%Y%m%d-%H%M)"
BAK="/etc/ssh/sshd_config.bak-$STAMP"
REVERT_MIN=10

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }

# --- 0. ¿Hay clave autorizada? Sin esto, no tocamos nada. ------------------
if [ ! -s /home/pi/.ssh/authorized_keys ]; then
  log "ABORTO: /home/pi/.ssh/authorized_keys vacio o inexistente."
  log "Si no hay clave, desactivar contrasenas te deja FUERA de la Pi."
  exit 1
fi
N_CLAVES=$(grep -c '^ssh-' /home/pi/.ssh/authorized_keys || echo 0)
log "Claves autorizadas en el usuario pi: $N_CLAVES"
[ "$N_CLAVES" -gt 0 ] || { log "ABORTO: authorized_keys no contiene ninguna clave."; exit 1; }

sudo -n cp -a "$SSHD" "$BAK"
log "Copia de seguridad: $BAK"

# --- 1. Revert automático ANTES de tocar nada ------------------------------
# Si este script muere despues de aplicar los cambios, systemd lo revierte.
cat > /tmp/revert-sshd.sh <<EOF
#!/bin/sh
cp -a "$BAK" "$SSHD"
/usr/sbin/sshd -t && systemctl reload ssh 2>/dev/null || systemctl restart ssh
logger -t minisoc-backup "REVERT automatico: se ha restaurado $SSHD (las contrasenas vuelven a aceptarse)"
EOF
chmod +x /tmp/revert-sshd.sh

# systemd-run con un nombre fijo: si ya existe uno vivo, lo mata antes.
systemd-run --unit=minisoc-revert-sshd --on-active="${REVERT_MIN}min" \
  /tmp/revert-sshd.sh >/dev/null 2>&1
log "Revert automatico programado en ${REVERT_MIN} min (systemd: minisoc-revert-sshd)"

# --- 2. Aplicar ------------------------------------------------------------
# Se usa un drop-in propio en vez de editar sshd_config a pelo: alarser un
# fichero independiente, el revert es borrar ese fichero, no reescribir el
# principal. Ademas una distro que actualice sshd_config no se pelea con esto.
DROPIN="$DROPIN_DIR/50-minisoc-hardening.conf"
sudo -n mkdir -p "$DROPIN_DIR"
sudo -n tee "$DROPIN" >/dev/null <<'EOF'
# MINISOC - endurecimiento de SSH.
# Las contrasenas se desactivan porque la Pi esta expuesta a la LAN y un
# servicio SSH con contrasenas es atacable por fuerza bruta. La clave ya esta
# habilitada y hay authorized_keys con claves reales.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 20
EOF
log "Drop-in creado: $DROPIN"

# --- 3. Validar antes de recargar -----------------------------------------
if ! sudo -n /usr/sbin/sshd -t; then
  log "ABORTO: la sintaxis no valida. Se retira el drop-in."
  sudo -n rm -f "$DROPIN"
  exit 1
fi
log "Sintaxis de sshd correcta"

sudo -n systemctl reload ssh
log "sshd recargado"

# --- 4. Comprobacion real: una conexion NUEVA con clave -------------------
# La clave privada esta en el portatil, NO en la Pi (la Pi solo guarda la
# publica en authorized_keys). Asi que desde aqui no siempre se puede verificar:
# si no hay una clave privada utilizable, no se inventa un "ok".
VERIFICADO=0
if [ -f /home/pi/.ssh/id_ed25519_pi ]; then
  sleep 3
  if timeout 12 ssh -o BatchMode=yes -o ConnectTimeout=8 \
        -i /home/pi/.ssh/id_ed25519_pi pi@127.0.0.1 true 2>/dev/null; then
    VERIFICADO=1
    log "Verificado localmente: la clave sigue entrando tras el cambio."
  fi
else
  log "No hay clave privada en la Pi (lo normal): no se puede verificar aqui."
fi

# --- 5. Confirmacion -------------------------------------------------------
# Si NO se ha verificado, el revert se queda ARMADO a proposito. Cancelarlo sin
# haber comprobado el acceso seria justo el fallo que este script evita.
if [ "$VERIFICADO" -eq 1 ]; then
  systemctl stop minisoc-revert-sshd.timer 2>/dev/null || true
  systemctl reset-failed minisoc-revert-sshd.timer 2>/dev/null || true
  log "Revert cancelado: el cambio es definitivo."
else
  log "*** REVERT ARMADO: el acceso aun NO esta verificado. ***"
  log "Confirma desde otro equipo que puedes entrar con clave. Si entras:"
  log "    sudo systemctl stop minisoc-revert-sshd.timer"
  log "Si no confirmas en ${REVERT_MIN} min, la configuracion se revierte sola."
fi

log ""
log "Para volver atras a mano:  rm $DROPIN && systemctl reload ssh"
log ""
log "=== Configuracion SSH resultante ==="
sudo -n /usr/sbin/sshd -T | grep -iE '^(passwordauthentication|permitrootlogin|pubkeyauthentication|x11forwarding|maxauthtries|logingracetime)' | sed 's/^/  /'
[ "$VERIFICADO" -eq 1 ] || exit 2