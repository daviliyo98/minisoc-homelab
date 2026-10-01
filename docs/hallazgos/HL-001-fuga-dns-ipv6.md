# HL-001: Fuga de DNS por IPv6 hacia el router del ISP

| Campo | Valor |
|---|---|
| Fecha | 2026-09-29 |
| Severidad | Alta |
| Activo afectado | Todos los clientes con doble pila (IPv4 + IPv6) |
| Estado | Mitigado parcialmente (por dispositivo) |

## Resumen

Pi-hole estaba desplegado y funcionando, pero una parte importante del tráfico DNS no pasaba por él. El control estaba **instalado** pero no **veía** el tráfico.

## Evidencia

`ipconfig /all` en un cliente Windows:

```
Servidores DNS . . . : fe80::1%20        <- router, anunciado por IPv6
                       192.168.1.20      <- Pi-hole
```

Comprobación:

```
nslookup doubleclick.net                 -> IP real (sin filtrar)
nslookup doubleclick.net 192.168.1.20    -> 0.0.0.0 (bloqueado)
```

## Análisis

- El DHCPv4 del router entregaba correctamente solo la IP de Pi-hole.
- El router del ISP (ZTE H3600P) anuncia además su propio DNS por IPv6 (Router Advertisement / RDNSS).
- Los sistemas con doble pila **priorizan IPv6**, así que la mayoría de consultas eludían el filtrado.
- El firmware del ISP no permite desactivar el anuncio de DNS por IPv6 desde la interfaz de usuario.

## Impacto

Los dispositivos quedaban sin filtrado de publicidad ni de dominios maliciosos (lista TIF), y el historial DNS llegaba al ISP.

## Remediación

| Acción | Alcance | Estado |
|---|---|---|
| Desactivar IPv6 en el adaptador del PC | Un equipo | ✅ |
| DNS manual en iOS | Un equipo | ⏳ |
| Solicitar al ISP la desactivación de IPv6 | Toda la red | ⏳ |
| Router neutro detrás del del ISP (OpenWrt/OPNsense) | Toda la red | Planificado |

## Verificación

Tras la mitigación en el PC: `nslookup doubleclick.net` → `0.0.0.0`, y `ipconfig /all` muestra solo `192.168.1.20`.

## Lección aprendida

"El control está desplegado" y "el control ve el tráfico" son afirmaciones distintas. La segunda siempre se verifica con evidencias.
