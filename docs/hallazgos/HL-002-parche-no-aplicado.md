# HL-002: Kernel parcheado en disco pero vulnerable en memoria

| Campo | Valor |
|---|---|
| Fecha | 2026-09-29 |
| Severidad | Media |
| Activo afectado | Raspberry Pi (host DNS de la red) |
| Estado | Resuelto |

## Resumen

Un error de APT (`404 Not Found` en `bookworm-security`) reveló que el host llevaba tiempo sin parchear. Tras actualizar, el kernel nuevo quedó instalado pero el sistema seguía ejecutando el antiguo.

## Evidencia

```
$ uname -r
6.12.34+rpt-rpi-v8                         <- en ejecución

$ dpkg -l 'linux-image*' | grep ^ii
linux-image-6.12.109+rpt-rpi-v8 ...        <- instalado
```

Los contenedores mostraban un *uptime* reciente porque Docker se reinició durante la actualización, no el sistema. Esto podía llevar a pensar erróneamente que ya se había reiniciado.

## Análisis

Un parche de kernel no tiene efecto hasta reiniciar. Verificar con el gestor de paquetes (`dpkg`) solo confirma lo **instalado**; lo **ejecutado** se verifica con `uname -r`.

## Remediación

1. `apt update && apt full-upgrade -y`
2. `reboot`
3. Limpieza: `apt autoremove`, purga del kernel antiguo, retención de logs a 30 días.

## Verificación

```
$ uname -r
6.12.109+rpt-rpi-v8
```

Servicios operativos tras el reinicio y filtrado DNS verificado (`dig @127.0.0.1 doubleclick.net` → `0.0.0.0`).

## Acciones preventivas

- [ ] `unattended-upgrades` para parches de seguridad automáticos
- [ ] Operaciones largas por SSH dentro de `tmux` (una sesión se cortó durante la actualización)

## Lección aprendida

Un parche instalado no es un parche aplicado. Los escáneres de vulnerabilidades distinguen exactamente esto.
