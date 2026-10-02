# MINISOC: homelab de ciberseguridad

Laboratorio doméstico en el que diseño, despliego, **verifico** y documento controles de seguridad reales sobre una Raspberry Pi 4. El objetivo es practicar el trabajo diario de un analista SOC: detectar puntos ciegos, validar que los controles ven el tráfico, investigar hallazgos y documentarlos.

> Cada cambio sigue el mismo ciclo: **desplegar aislado → validar → integrar → verificar de extremo a extremo → documentar**, siempre con un plan de rollback.

## Arquitectura actual

```mermaid
flowchart LR
    D[Dispositivos de casa] -->|DNS :53| P[Pi-hole v6<br/>filtrado]
    P -->|127.0.0.1:5335| U[Unbound<br/>recursivo + DNSSEC]
    U --> R[(Servidores raíz DNS)]
    D -. fuga IPv6 .-> X[DNS del router ISP]
    PT[Portainer CE] -. gestiona .-> P
    PT -. gestiona .-> U
    NE[node-exporter] --> PR[Prometheus] --> G[Grafana]
    J[journald SSH] --> CS[CrowdSec] --> FW[Bouncer nftables]
    CS -->|métricas 172.17.0.1:6060| PR
```

| Componente | Función | Estado |
|---|---|---|
| Raspberry Pi 4 (8 GB), Debian 12 | Host de Docker | ✅ Parcheado |
| Pi-hole v6 | Sinkhole DNS: publicidad, rastreo y amenazas | ✅ |
| Unbound | Resolución recursiva sin terceros, validación DNSSEC | ✅ |
| Portainer CE | Gestión de contenedores | ✅ (pendiente de hardening) |
| Prometheus + node-exporter | Métricas del host (línea base) | ✅ |
| Grafana | Dashboards y alertas | ✅ |
| CrowdSec + firewall bouncer (nftables) | Detección de ataques y bloqueo automático, inteligencia colaborativa; métricas en Grafana | ✅ |
| websec-scanner (FastAPI) | Analizador pasivo de postura de seguridad web (cabeceras, TLS, security.txt) | ✅ |

### Listas de bloqueo

| Lista | Propósito |
|---|---|
| StevenBlack hosts | Base de publicidad y malware |
| Hagezi Pro | Publicidad, rastreo y telemetría |
| Hagezi TIF | Threat intelligence: malware, phishing y C2 |
| Hagezi DoH/VPN/Proxy bypass | Impedir la evasión del DNS mediante DoH |

## Hallazgos documentados

Cada hallazgo sigue el formato de un informe: evidencia, análisis, impacto, remediación y verificación.

| ID | Hallazgo | Severidad | Estado |
|---|---|---|---|
| [HL-001](docs/hallazgos/HL-001-fuga-dns-ipv6.md) | Fuga de DNS por IPv6: el router del ISP anuncia su propio DNS | Alta | Mitigado parcialmente |
| [HL-002](docs/hallazgos/HL-002-parche-no-aplicado.md) | Kernel parcheado en disco pero vulnerable en memoria | Media | Resuelto |
| [HL-003](docs/hallazgos/HL-003-evasion-dns-iphone.md) | Evasión del DNS en iOS mediante cifrado (iCloud Private Relay) | Media | En investigación |
| [HL-004](docs/hallazgos/HL-004-limites-memoria-ignorados.md) | Límites de memoria de contenedores descartados en silencio | Media | Remediado |
| [HL-005](docs/hallazgos/HL-005-crowdsec-sin-logs-ssh.md) | Sistema de detección activo pero sin visibilidad de los logs de SSH | Alta | Remediado |
| [HL-006](docs/hallazgos/HL-006-contenedor-sin-salida-ipv6.md) | Contenedor sin salida de red por preferencia de IPv6 | Media | Resuelto |
| [HL-007](docs/hallazgos/HL-007-falso-positivo-securitytxt.md) | Falso positivo en la detección de security.txt (soft-404) | Media | Resuelto |

## Runbooks

- [Verificación del filtrado DNS por dispositivo](docs/runbooks/verificacion-dns.md)

## Competencias demostradas

- **Seguridad de red:** DNS, DNSSEC, IPv6 (SLAAC/RDNSS), evasión mediante DoH/DoT y relays cifrados
- **Gestión de vulnerabilidades:** parcheo, diferencia entre parche instalado y aplicado
- **Análisis de logs y threat hunting:** correlación endpoint ↔ sensor, detección por ausencia de eventos
- **Gestión del cambio:** despliegue aislado, pruebas, rollback, backups verificados (regla 3-2-1)
- **Contenedores:** Docker, Compose, Portainer, principio de mínimo privilegio
- **Gestión de secretos:** ningún secreto en el repositorio; variables en `.env` excluido
- **Desarrollo seguro:** API propia en Python/FastAPI, contenedor sin privilegios y solo lectura, autenticación por API key

## Hoja de ruta

- [x] Filtrado DNS con Pi-hole + Unbound + DNSSEC
- [x] Parcheo del sistema y limpieza
- [x] Backups verificados de Pi-hole y Portainer
- [ ] Cerrar la fuga IPv6 en toda la red (router neutro con OpenWrt/OPNsense)
- [x] Parches automáticos con ventana de mantenimiento (`unattended-upgrades`, reinicio a las 04:00)
- [x] Acceso remoto Zero Trust con Tailscale (sin puertos abiertos a Internet)
- [ ] Hardening del host: SSH con claves, UFW, mínimo privilegio
- [ ] Migración del sistema a SSD
- [x] Detección y respuesta: CrowdSec
- [x] Métricas: Prometheus + node-exporter + Grafana
- [ ] Logs: Loki + Grafana Alloy (mini-SIEM)
- [ ] Segmentación de red con VLANs (IoT / invitados / confianza)

## Estructura del repositorio

```
stacks/        Docker Compose de cada servicio (sin secretos)
apps/          Aplicaciones propias (websec-scanner)
host/          Configuración del sistema operativo del host
scripts/       Utilidades de operación
subir.ps1      Publicación en GitHub con control de secretos
docs/hallazgos Informes de hallazgos
docs/runbooks  Procedimientos de verificación y operación
```

## Aviso

Las direcciones IP son de una red privada doméstica. El repositorio no contiene contraseñas, claves ni backups.
