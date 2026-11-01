# HL-014: Deriva entre el repositorio y lo que de verdad corre en la Pi

| Campo | Valor |
|---|---|
| Fecha | 2026-11-01 |
| Severidad | Media |
| Activo afectado | Raspberry Pi: Pi-hole, copias de seguridad, portal |
| Estado | Parcialmente remediado; unificación de Pi-hole pendiente |

## Resumen

El repositorio `minisoc-homelab` describe el homelab, pero varias piezas en producción
no coincidían con él. Se detectó al depurar fallos que no tenían sentido mirando el
repo: lo que se cambiaba en el repo no afectaba al servicio real, y lo que corría en
la Pi no estaba en el repo.

## Evidencia

**1. Pi-hole lo gestiona Portainer, no el compose del repo.**

```
$ sudo docker inspect pihole --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{end}}'
/data/compose/1/etc-pihole -> /etc/pihole        # stack 1 de Portainer

$ ls stacks/pihole/etc-pihole/pihole.toml
No such file or directory                         # la carpeta del repo no se usa

$ sudo docker inspect pihole --format '{{range .Config.Env}}{{println .}}{{end}}' | grep FTLCONF
(nada)
```

El `docker-compose.yml` del repo define `FTLCONF_dns_upstreams: 127.0.0.1#5335` (Unbound),
`FTLCONF_dns_listeningMode: LOCAL` y la contraseña por variable. El contenedor real no
tiene ninguna de ellas: lo que tenga configurado se hizo a mano desde la web.

**2. Un control que fallaba en silencio.** La contraseña de aplicación de Pi-hole se
"activaba" desde la web, pero `pihole.toml` seguía con `app_pwhash = ""` y la API
respondía `password incorrect`. Solo se resolvió fijando el hash con
`pihole-FTL --config webserver.api.app_pwhash` y comprobando el fichero.

**3. El script de copias y su runbook solo existían en la Pi.** `scripts/backup-minisoc.sh`
y `docs/runbooks/backups.md` estaban dentro del repo, pero la regla `*backup*` del
`.gitignore` (pensada para no subir los paquetes con secretos) los ignoraba sin avisar.
Si el disco de la Pi fallaba, se perdían las copias **y** el procedimiento para usarlas.
Las unidades de systemd (`minisoc-backup.service`/`.timer`) tampoco estaban versionadas.

**4. Caídas diarias a las 04:3x que eran la propia copia.** El portal registraba cada
madrugada todos los servicios "caídos" 1 minuto. `systemctl list-timers` y
`journalctl -u minisoc-backup` mostraron que era el backup parando contenedores ~4-10 s.

## Análisis

- La causa común es que hay **más de una fuente de verdad**: Portainer, el repo y
  cambios hechos a mano en la Pi o en las webs de los servicios.
- Una regla de `.gitignore` demasiado amplia es un control que oculta información:
  protegía los secretos, pero también escondía código necesario.
- Sin contexto, las tareas programadas generan alertas falsas cada día, y con el
  tiempo eso enseña a ignorar las alertas reales.
- Al revisar el script de copias aparecieron además: paquetes con todos los `.env`
  creados con permisos 644 (legibles por cualquier usuario), Home Assistant copiado en
  caliente (SQLite sin parar el contenedor) y el historial del portal fuera de la copia.

## Remediación

Aplicado:

- `.gitignore`: excepciones explícitas para `scripts/backup-minisoc.sh` y
  `docs/runbooks/backups.md`; los paquetes `.tar.zst` siguen excluidos.
- Script de copias versionado tal cual corría y después corregido: `umask 077`,
  `/home/pi/backups` en 700, se paran `homeassistant` y `homelab-portal`, y se copia el
  volumen del portal.
- `host/systemd/minisoc-backup.service` versionado (falta añadir el `.timer` desde la Pi).
- Portal: ventana de mantenimiento `PORTAL_MANTENIMIENTO=04:25-04:50`; las paradas de la
  copia ya no se registran como caídas.

Pendiente:

- **Unificar Pi-hole en una sola fuente de verdad**: o se gestiona desde el repo
  (`stacks/pihole`) y se retira el stack de Portainer, o se documenta en el repo que
  Portainer es la fuente y se exporta su compose. Hasta entonces, revisar en la web de
  Pi-hole que el upstream es Unbound (`127.0.0.1#5335`).
- Copia fuera de la Pi y cifrada (regla 3-2-1): hoy las 7 copias están en el mismo disco.

## Verificación

```bash
git check-ignore -v scripts/backup-minisoc.sh          # no debe salir nada
ls -ld /home/pi/backups && ls -l /home/pi/backups      # drwx------ y -rw-------
sudo journalctl -u minisoc-backup -n 30                # "Parando homeassistant", "homelab-portal"
diff <(sudo cat /etc/systemd/system/minisoc-backup.service | grep -v '^#') \
     <(grep -v '^#' host/systemd/minisoc-backup.service)   # sin diferencias
```

## Lección aprendida

El repositorio solo sirve si describe lo que de verdad corre. Cada cambio hecho "a mano"
o desde una interfaz web es una deriva hasta que vuelve al repo. Y como en HL-004 y
HL-013: un control configurado no es un control aplicado; se comprueba en el sistema
real (`docker inspect`, el fichero de configuración, el log), no en lo que dice el repo.
