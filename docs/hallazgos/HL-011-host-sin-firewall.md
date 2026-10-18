# HL-011: Host sin filtrado de tráfico (política accept)

| Campo | Valor |
|---|---|
| Fecha | 2026-10-16 |
| Severidad | **Alta** |
| Activo afectado | Host (nftables) |
| Estado | **Pendiente** |

## Resumen

Todas las cadenas de entrada de `nftables` están en `policy accept`. No hay
filtrado por defecto: todo lo que escucha en `0.0.0.0` es alcanzable desde
cualquier dispositivo de la LAN.

## Evidencia

```
$ sudo nft list ruleset | grep 'hook input'
        type filter hook input priority filter; policy accept;   (x2)
        type filter hook input priority filter - 10; policy accept;  (x2)

$ sudo nft list ruleset | grep -cE 'policy drop|policy reject'
1
```

Puertos alcanzables desde toda la LAN:

| Puerto | Servicio | Autenticación |
|---|---|---|
| 22 | SSH | sí (desde HL-010, solo clave) |
| 53 | Pi-hole DNS | n/a |
| 80 / 443 | Pi-hole panel | sí |
| 3000 | Grafana | sí |
| 8000 / 9443 | Portainer | sí |
| 8001 | websec-scanner | API key |
| 8090 | homelab-portal | sí |
| 123 | NTP (pihole-FTL) | n/a |
| 5353 / 37333 / 60253 | avahi mDNS | n/a |

## Análisis

El `crowdsec-firewall-bouncer` está activo, pero **no es un firewall**: inserta
reglas `drop` para IPs que ya están en su lista de baneados. Si una IP no ha
disparado ninguna detección, pasa sin filtro. Es detección reactiva, no
preventiva.

Que los servicios tengan contraseña no cierra el problema: reduce el impacto de
alcanzarlos, pero convierte cada puerto en objetivo de fuerza bruta o de
vulnerabilidad en el servicio.

## Por qué no se ha remediado todavía

Es la fase más delicada del plan por una razón concreta: **Docker gestiona sus
propias reglas de red**. Los puertos publicados se resuelven con DNAT en la tabla
`nat` y el tráfico acaba en la cadena `FORWARD`, no en `INPUT`. Poner
`policy drop` en `INPUT` no corta los puertos publicados de Docker, pero sí
puede cortar el tráfico de los contenedores hacia el host, y hay que permitir
explícitamente las interfaces `docker0` y `br-*`.

El riesgo real es quedarse sin acceso a la Pi, o sin DNS, por una regla mal
pensada.

## Remediación propuesto (pendiente de ejecutar)

Cadena de base con política `drop` y allowlist explícita:

- `iif lo` aceptar, y `ct state established,related` aceptar
- `iifname tailscale0` aceptar (acceso remoto por VPN)
- Subred `192.168.1.0/24` solo a los puertos que realmente se usan desde casa
- ICMP aceptado, para no romper la Path MTU y el ping de diagnóstico
- Interfaces de Docker (`docker0`, `br-*`) aceptadas en `INPUT`
- Filtrado de puertos publicados en la cadena `DOCKER-USER`, que es donde deben
  ir, no en `INPUT`

Con el mismo esquema de seguridad que SSH: revert automático y verificación
antes de cancelar el revert.

## Lección aprendida

Detección reactiva y prevención no son intercambiables. CrowdSec respuesta a lo
que ya ha pasado; un `policy drop` es lo que impide que algo llegue a intentarlo.