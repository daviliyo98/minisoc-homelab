# HL-012: Hardening desigual entre contenedores

| Campo | Valor |
|---|---|
| Fecha | 2026-10-16 |
| Severidad | Media |
| Activo afectado | Grafana, Prometheus, Pi-hole, Unbound, Portainer, node-exporter, ZAP |
| Estado | **Pendiente** |

## Resumen

Dos de los nueve contenedores están endurecidos (`read_only`, `cap_drop: ALL`,
`no-new-privileges`). Los otros siete se ejecutan con el sistema de archivos
escribible, todas las capacidades por defecto y sin `no-new-privileges`.

## Evidencia

```
CONTENEDOR         PRIV   RO     CAPS   NO-NEW-PRIV
homelab-portal     false  true   1      [no-new-privileges:true]
websec-scanner     false  true   1      [no-new-privileges:true]
websec-zap         false  false  0      [no-new-privileges:true]
node-exporter      false  false  0      [label=disable]
grafana            false  false  0      []
prometheus         false  false  0      []
unbound            false  false  0      []
pihole             false  false  0      []
portainer          false  false  0      []
```

Ningún contenedor es `privileged`, que es lo importante: ninguno tiene acceso
directo al host.

## Análisis

`read_only` no es un detalle menor: con el rootfs escribible, una vulnerabilidad
en el proceso del contenedor puede escribir un binario en su propio disco y
persistir entre reinicios. En Grafana o Portainer, una escalada a root dentro del
contenedor parte de un punto de partida mucho más cómodo para el atacante.

`cap_drop: ALL` reduce lo que el proceso puede hacer aunque get lo controle: por
defecto Docker concede unas 14 capacidades (`CAP_NET_RAW`, `CAP_CHOWN`,
`CAP_DAC_OVERRIDE`...) que casi ninguna aplicación necesita.

El patrón correcto ya existe en el repo (`websec-scanner`, `homelab-portal`); lo
que falta es aplicarlo al resto, que son servicios de terceros.

## Complicación real: Pi-hole

Pi-hole es el caso difícil. Usa `network_mode: host` y necesita `CAP_NET_ADMIN`
para hablar con la interfaz, y `CAP_NET_RAW` para enviar paquetes forjados. Un
`cap_drop: ALL` plano lo rompería. La solución correcta es `cap_drop: ALL` más
`cap_add` de las dos capacidades que realmente necesita, y documentar por qué.

## Remediación propuesto (pendiente)

Empezar por los que son seguros de tocar (Prometheus, Unbound, node-exporter) y
verificar en cada paso que el servicio sigue respondiendo. Pi-hole aparte, con
las capacidades explícitas.

## Lección aprendida

El endurecimiento que no se aplica a los servicios que importan deja la misma
impresión de seguridad que no hacer nada, porque el repositorio sí contiene
ejemplos correctos.