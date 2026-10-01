# HL-004: Límites de memoria de contenedores descartados en silencio

| Campo | Valor |
|---|---|
| Fecha | 2026-09-30 |
| Severidad | Media |
| Activo afectado | Raspberry Pi (host Docker) |
| Estado | Remediación aplicada, pendiente de verificación |

## Resumen

El stack de monitorización definía límites de memoria (`mem_limit`) para que Prometheus, Grafana y node-exporter nunca pudieran dejar sin recursos al servicio DNS de la red. Docker arrancó los contenedores correctamente, pero **descartó los límites**, mostrando solo un aviso.

## Evidencia

```
! prometheus  Your kernel does not support memory limit capabilities
              or the cgroup is not mounted. Limitation discarded.
```

## Análisis

- Raspberry Pi OS arranca por defecto con el controlador de memoria de cgroups desactivado.
- El despliegue termina con éxito y los servicios funcionan, así que el fallo **no es visible** salvo leyendo la salida completa.
- Consecuencia: un consumo descontrolado de memoria (por ejemplo, una consulta pesada en Prometheus) podría afectar a Pi-hole y dejar sin DNS a toda la red.

## Remediación

Activar el controlador de memoria en la línea de arranque del kernel:

```bash
cp /boot/firmware/cmdline.txt /boot/firmware/cmdline.txt.bak
sed -i '1 s/$/ cgroup_enable=memory cgroup_memory=1/' /boot/firmware/cmdline.txt
reboot
```

## Verificación

```bash
docker stats --no-stream   # la columna LIMIT debe mostrar 512MiB / 256MiB / 64MiB
```

## Lección aprendida

Un control que se desactiva en silencio es más peligroso que uno que falla con error: da una falsa sensación de protección. Los avisos de un despliegue se leen siempre, y los controles se verifican después de desplegar, no solo antes.
