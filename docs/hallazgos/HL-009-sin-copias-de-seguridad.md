# HL-009: Copias de seguridad inexistentes pese a marcarse como hechas

| Campo | Valor |
|---|---|
| Fecha | 2026-10-16 |
| Severidad | **Alta** |
| Activo afectado | Homelab completo |
| Estado | Resuelto (copia local; falta la externa) |

## Resumen

La hoja de ruta marcaba `[x] Backups verificados de Pi-hole y Portainer`. No
existía ninguna copia de seguridad: ni de esos componentes ni de nada más. Todo
el estado del homelab vivía en la microSD sin ninguna red.

## Evidencia

```
$ crontab -l                      # vacío
$ sudo crontab -l                # vacío
$ ls /etc/cron.d/                # solo e2scrub_all
$ systemctl list-timers | grep -i backup   # nada
$ command -v restic rclone       # no instalados
$ sudo find / -maxdepth 5 -name "*teleporter*"   # nada
```

Los únicos ficheros comprimidos en todo el árbol eran addons de Kodi. Los volúmenes
con el estado real — `monitoring_grafana_data` (52 MB de dashboards),
`monitoring_prometheus_data` (92 MB de series temporales), `portainer_data` y
`websec-scanner_websec-data` — no se copiaban en ningún sitio.

## Análisis

El riesgo no es solo lahwastura de la microSD. Dentro de los datos no copiados
estaban los dos ficheros `.env` del repositorio, que contienen `API_KEY` del
scanner y `PORTAL_PASSWORD` del portal. Son claves que **no se regeneran solas**:
perderlas obliga a reconfigurar la autenticación de ambos servicios a mano.

Que la hoja de ruta marcara la casilla como cumplida es lo más grave: una tarea
declarada hecha que no lo estaba hace que nadie la vuelva a mirar.

## Impacto

Un fallo de la microSD, un incendio o un robo eliminarían de golpe los
dashboards, el histórico de métricas, las blocklists de Pi-hole, el historial de
escaneos y las claves de autenticación.

## Remediación

`scripts/backup-minisoc.sh` y `scripts/restore-minisoc.sh`, programados con un
timer de systemd a las 04:30 con `Persistent=true` (si la Pi estaba apagada, se
ejecuta al encender; cron no lo hace).

Copia el repo con sus `.env`, `etc-pihole` (que vive fuera del repo, en
`/data/compose/1`), los cuatro volúmenes con estado y la configuración de host
(`nftables.conf`, `sshd_config`, `cron.d`, `crowdsec/`).

Verificación de verdad, no solo generar el fichero: sha256, integridad zstd,
recuento de entradas y **extracción real** a un directorio temporal confirmando
que están el manifiesto, los dos `.env` con secretos, `etc-pihole` y
`nftables.conf`.

## Verificación

```
[22:53:20] Paquete: /home/pi/backups/minisoc-20261016-2252.tar.zst (96M)
[22:53:22]   sha256 correcto
[22:53:23]   integridad zstd correcta
[22:53:24]   1847 entradas en el archivo
[22:53:26]   restauracion de prueba correcta (1342 ficheros extraidos)
[22:53:26]   los .env con secretos estan dentro
```

Comprobado además sobre la copia extraída que `PORTAL_PASSWORD` y `API_KEY` se
recuperan, y que las 71 MB de `etc-pihole` y los 144 MB de volúmenes están.

## Pendiente

La copia es **local**: protege de un error de configuración o un borrado
accidental, pero no de la muerte de la microSD. Falta una copia fuera de casa
(cifrada), que requiere decidir destino y credenciales.

## Lección aprendida

"Generar un backup" y "tener un backup verificado" no son lo mismo. Marcar una
casilla como cumplida sin haber ejecutado la restauración de prueba es lo que
permite que una tarea se degrade en silencio durante años.