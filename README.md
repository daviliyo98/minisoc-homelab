# MINISOC: homelab de ciberseguridad

Laboratorio doméstico en el que diseño, despliego, **verifico** y documento controles de seguridad reales sobre una Raspberry Pi 4. El objetivo es practicar el trabajo diario de un analista SOC: detectar puntos ciegos, validar que los controles ven el tráfico, investigar hallazgos y documentarlos.

> Cada cambio sigue el mismo ciclo: **desplegar aislado → validar → integrar → verificar de extremo a extremo → documentar**, siempre con un plan de rollback.

## Arquitectura actual

```mermaid
flowchart LR
    %% Leyenda: solido = flujo de datos · discontinuo = gestion, observacion o sondeo.
    %% Las IPs van en las etiquetas de nodo, nunca en las de arista: en el texto de
    %% un enlace punteado, un "127.0.0.1" rompe el parser (lo que rompio el diagrama).

    D["Dispositivos de casa"]
    J["journald SSH"]
    TS["Tailscale<br/>sin puertos abiertos"]
    X["DNS del router ISP"]
    W["websec-scanner"]

    subgraph dns["DNS"]
        direction LR
        P["Pi-hole v6<br/>filtrado"]
        U["Unbound<br/>recursivo + DNSSEC"]
        R[("Servidores raíz DNS")]
    end

    subgraph metricas["Observabilidad"]
        direction LR
        NE["node-exporter"]
        PR["Prometheus<br/>solo loopback"]
        G["Grafana"]
    end

    subgraph defensa["Seguridad"]
        direction LR
        CS["CrowdSec"]
        FW["Bouncer<br/>nftables"]
    end

    subgraph gestion["Gestión y acceso"]
        direction LR
        PT["Portainer CE"]
        LP["homelab-portal<br/>puerto 8090"]
    end

    %% --- plano de datos ---
    D -->|"DNS :53"| P
    P -->|"loopback :5335"| U
    U --> R
    PR --> G

    %% --- deteccion y contencion ---
    J --> CS
    CS --> FW

    %% --- observacion: telemetria hacia Prometheus ---
    NE -.-> PR
    CS -.->|"métricas"| PR

    %% --- gestion y sondeo ---
    TS --> LP
    PT -.-> P
    PT -.-> U
    LP -.-> P
    LP -.-> U
    LP -.-> G
    LP -.-> W
    LP -.-> PR

    %% --- fuga conocida, no resuelta ---
    D -.->|"fuga IPv6"| X
```

**Leyenda:** línea sólida = flujo de datos · línea discontinua = gestión, observación o sondeo. Por eso el portal no enruta tráfico: lo vigila.

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
| homelab-portal (FastAPI) | Catálogo de los servicios con estado de salud en vivo y sus endpoints de API | ✅ |

### Listas de bloqueo

| Lista | Propósito |
|---|---|
| StevenBlack hosts | Base de publicidad y malware |
| Hagezi Pro | Publicidad, rastreo y telemetría |
| Hagezi TIF | Threat intelligence: malware, phishing y C2 |
| Hagezi DoH/VPN/Proxy bypass | Impedir la evasión del DNS mediante DoH |

## Acceso

Todo se maneja desde **homelab-portal** (puerto `8090`), que además comprueba que cada
servicio responde. Se llega por la IP de casa o por Tailscale; no hay ningún puerto
abierto a Internet.

| Servicio | Desde casa | Por tailnet |
|---|---|---|
| Portal | `http://192.168.1.20:8090` | `http://100.114.119.53:8090` |
| Grafana | `http://192.168.1.20:3000` | `http://100.114.119.53:3000` |
| Pi-hole | `https://192.168.1.20:443/admin` | `https://100.114.119.53:443/admin` |
| Portainer | `https://192.168.1.20:9443` | `https://100.114.119.53:9443` |
| websec-scanner | `http://192.168.1.20:8001` | `http://100.114.119.53:8001` |
| Prometheus | solo `127.0.0.1:9090` en la Pi | — |

Prometheus y Unbound escuchan **solo en loopback**: los sondea el portal desde el host y
no se exponen. Para consultar la interfaz de diagnóstico de Prometheus sin tocar la
configuración: `ssh -N -L 9090:127.0.0.1:9090 pi@192.168.1.20`.

> Pi-hole y Portainer usan **certificados autofirmados**: el navegador avisará una vez
> por servicio. Es esperable en un homelab.

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
| [HL-008](docs/hallazgos/HL-008-grafana-provisioning-sin-permisos.md) | Grafana sin acceso a su carpeta de provisioning (permisos 700) | Media | Resuelto |

## Runbooks

- [Verificación del filtrado DNS por dispositivo](docs/runbooks/verificacion-dns.md)
- [homelab-portal: catálogo de servicios, endpoints de API y sondas](apps/homelab-portal/README.md)

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
- [x] Copias de seguridad verificadas y programadas (repo, .env, etc-pihole,
      volúmenes Docker y configuración de host; diario a las 04:30)
- [ ] Cerrar la fuga IPv6 en toda la red (router neutro con OpenWrt/OPNsense)
- [x] Parches automáticos con ventana de mantenimiento (`unattended-upgrades`, reinicio a las 04:00)
- [x] Acceso remoto Zero Trust con Tailscale (sin puertos abiertos a Internet)
- [ ] Hardening del host: SSH con claves, UFW, mínimo privilegio
- [ ] Migración del sistema a SSD
- [x] Detección y respuesta: CrowdSec
- [x] Métricas: Prometheus + node-exporter + Grafana
- [x] Catálogo de servicios con estado de salud (homelab-portal)
- [ ] Logs: Loki + Grafana Alloy (mini-SIEM)
- [ ] Segmentación de red con VLANs (IoT / invitados / confianza)

## Estructura del repositorio

```
stacks/        Docker Compose de cada servicio (sin secretos)
apps/          Aplicaciones propias (websec-scanner, homelab-portal)
host/          Configuración del sistema operativo del host
scripts/       Utilidades de operación
subir.ps1      Publicación en GitHub con control de secretos
docs/hallazgos Informes de hallazgos
docs/runbooks  Procedimientos de verificación y operación
```

## Aviso

Las direcciones IP son de una red privada doméstica. El repositorio no contiene contraseñas, claves ni backups.
