# HL-010: SSH con autenticación por contraseña activa

| Campo | Valor |
|---|---|
| Fecha | 2026-10-16 |
| Severidad | **Alta** |
| Activo afectado | Host (sshd) |
| Estado | Resuelto |

## Resumen

`sshd` aceptaba autenticación por contraseña y escuchaba en todas las
interfaces, dentro de una red doméstica. Cualquier dispositivo del wifi podía
someter la Pi a intentos de acceso.

## Evidencia

```
$ sudo sshd -T | grep -E '^(passwordauthentication|permitrootlogin)'
passwordauthentication yes
permitrootlogin without-password
$ ss -tuln | grep ':22'
tcp  LISTEN  0  4096  0.0.0.0:22  0.0.0.0:*
```

La clave pública ya estaba autorizada (una clave en
`/home/pi/.ssh/authorized_keys`), es decir, el trabajo difícil estaba hecho: lo
que faltaba era **desactivar** el método alternativo.

## Análisis

La IP de la Pi es privada y el CGNAT impide alcanzarla desde internet, así que no
hay exposición directa. El vector es la red local: contraseñas filtradas en otro
servicio, phishing, alguien que la ve teclearla, o un dispositivo de la red ya
comprometido barriendo contraseñas. La clave pública no es atacable por fuerza
bruta: es criptografía, no una cadena que se adivine.

La hoja de ruta ya listaba "Hardening del host: SSH con claves" como pendiente,
lo que describe mal el estado: las claves funcionaban; lo que faltaba era
apagar las contraseñas.

## Impacto

Compromiso total de la Pi si se obtiene la contraseña. Desde ahí: acceso a los
`.env` con todas las claves de la API, lectura de consultas DNS, modificación de
las blocklists de Pi-hole y control de los contenedores vía Portainer.

## Remediación

Drop-in `/etc/ssh/sshd_config.d/50-minisoc-hardening.conf` (en fichero aparte y
no editando `sshd_config`, para que una actualización del paquete no se pelee con
ello y para que revertir sea borrar un fichero).

```
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 20
```

Aplicado con `scripts/hardening-ssh.sh`, que protege contra el peor resultado
posible —quedarse fuera de la propia máquina— en tres capas:

1. Aborta sin tocar nada si `authorized_keys` está vacío.
2. Valida con `sshd -t` antes de recargar.
3. Programa un revert automático a 10 minutos con `systemd-run`; solo lo cancela
   si ha verificado que una conexión con clave sigue entrando. Si el script muere
   a mitad, o la verificación falla, la configuración anterior vuelve sola.

El rollback manual es borrar el drop-in y recargar; queda además una copia de
`sshd_config` en `/etc/ssh/sshd_config.bak-<fecha>`.

## Verificación

```
$ ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no pi@192.168.1.20
Permission denied (publickey).

$ sudo sshd -T | grep -E '^(passwordauthentication|permitrootlogin|pubkeyauthentication)'
passwordauthentication no
permitrootlogin no
pubkeyauthentication yes
```

Y una sesión nueva con clave entrando con normalidad tras el cambio.

## Lección aprendida

Un script de endurecimiento que aplica el cambio pero no verifica el resultado
es peor que no ejecutarlo: aparenta haber hecho el trabajo. La red de seguridad
del revert automático solo sirve si el script es honesto sobre lo que ha
podido comprobar y lo que no.