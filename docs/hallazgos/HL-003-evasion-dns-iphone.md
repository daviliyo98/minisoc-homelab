# HL-003: Evasión del DNS en iOS mediante cifrado

| Campo | Valor |
|---|---|
| Fecha | 2026-09-29 |
| Severidad | Media |
| Activo afectado | iPhone (192.168.1.XXX) |
| Estado | En investigación |

## Resumen

Con el DNS del iPhone configurado manualmente hacia Pi-hole, un dominio bloqueado (`doubleclick.net`) seguía cargando en el navegador.

## Método

Correlación en directo entre el endpoint y el sensor: se genera un evento conocido en el iPhone y se comprueba si aparece en el log de Pi-hole.

```bash
docker exec pihole tail -f /var/log/pihole/pihole.log \
  | grep --line-buffered -E "192.168.1.XXX|doubleclick"
```

## Evidencia

```
query[A]     mask.icloud.com      from 192.168.1.XXX
query[HTTPS] fonts.googleapis.com from 192.168.1.XXX
```

No aparece **ninguna** consulta a `doubleclick.net`, a pesar de haber cargado la página.

## Análisis

- `mask.icloud.com` indica que el dispositivo intenta usar **iCloud Private Relay**, que envía el DNS de Safari cifrado a Apple.
- Detección **por ausencia**: el tráfico existe, pero el sensor no lo ve.
- Hipótesis pendientes de descartar: caché del navegador, uso de datos móviles (Asistencia para Wi-Fi), VPN o perfil de DNS instalado.

## Remediación propuesta

| Acción | Alcance |
|---|---|
| Desactivar Relay privado y "Limitar rastreo de IP" | Un dispositivo |
| `dns.specialDomains.iCloudPrivateRelay = true` en Pi-hole | Todos los dispositivos Apple de la red |
| Bloquear DoH/DoT a nivel de firewall (router neutro) | Toda la red |

## Próximos pasos

- [ ] Repetir la prueba con datos móviles desactivados y un dominio nunca visitado
- [ ] Revisar VPN y perfiles del dispositivo
- [ ] Investigar el dominio `hemihydro.com` observado en el log (¿patrón periódico?)
