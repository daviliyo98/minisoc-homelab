# HL-005: Sistema de detección activo pero sin visibilidad de SSH

| Campo | Valor |
|---|---|
| Fecha | 2026-10-02 |
| Severidad | Alta |
| Activo afectado | CrowdSec en la Raspberry Pi |
| Estado | Remediado |

## Resumen

Tras instalar CrowdSec, el servicio, el bouncer de firewall y las colecciones de detección de SSH aparecían activos. Sin embargo, el sistema **no recibía ningún log de SSH**, por lo que un ataque de fuerza bruta no se habría detectado.

## Evidencia

```
$ systemctl is-active crowdsec crowdsec-firewall-bouncer
active
active

$ cscli collections list
crowdsecurity/sshd   ✔️ enabled

$ ls -l /var/log/auth.log
ls: cannot access '/var/log/auth.log': No such file or directory
```

## Análisis

- Raspberry Pi OS (Debian 12) no incluye `rsyslog`: los logs de autenticación solo existen en **journald**.
- La configuración por defecto de la colección SSH espera leer `/var/log/auth.log`.
- Resultado: todos los indicadores de estado en verde, pero **cobertura de log nula** para el servicio más expuesto del host.

## Impacto

Ataques de fuerza bruta o de relleno de credenciales contra SSH sin detectar ni bloquear.

## Remediación

Nueva fuente de adquisición desde journald ([`host/crowdsec/acquis.d/ssh-journald.yaml`](../../host/crowdsec/acquis.d/ssh-journald.yaml)):

```yaml
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=ssh.service"
labels:
  type: syslog
```

## Verificación

Se generan intentos de acceso con un usuario inexistente desde la LAN y se comprueban las métricas:

```
$ cscli metrics show acquisition parsers
Source                                           Lines read  Lines parsed  Lines unparsed  Lines whitelisted
journalctl:journalctl-_SYSTEMD_UNIT=ssh.service  20          12            8               12
```

- Los eventos llegan y se interpretan (`crowdsecurity/sshd-logs`).
- Se descartan por la lista blanca de IPs privadas (`crowdsecurity/whitelists`), comportamiento esperado para evitar autobloqueos.

Cadena de bloqueo verificada con una decisión manual sobre una IP de documentación (RFC 5737): decisión → bouncer → regla nftables.

## Lección aprendida

Un control "activo" no es un control "que ve". En toda revisión de detección la primera pregunta es: **¿están llegando realmente los logs de esta fuente?** Es el mismo patrón que HL-001 (DNS) y HL-004 (límites de memoria).
