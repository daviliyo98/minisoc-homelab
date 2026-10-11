# HL-008: Grafana sin acceso a su carpeta de provisioning

| Campo | Valor |
|---|---|
| Fecha | 2026-10-11 |
| Severidad | Media |
| Activo afectado | Grafana (stack de monitorización) |
| Estado | Resuelto |

## Resumen

Al añadir el dashboard de websec-scanner se comprobó que Grafana **nunca había cargado su provisioning**: ni datasources ni dashboards. Todo parecía funcionar porque el datasource se había creado a mano.

## Evidencia

```
logger=provisioning.datasources level=error msg="can't read datasource provisioning files from directory"
  path=/etc/grafana/provisioning/datasources error="open ...: permission denied"
$ docker exec grafana id
uid=472(grafana) gid=0(root)
$ ls -ld grafana/provisioning grafana/provisioning/datasources
drwx------ pi pi ...
```

## Análisis

Las carpetas montadas tenían modo `700` y pertenecían a `pi` (uid 1000). Grafana corre como uid 472, así que no podía ni listarlas. El error solo aparece en los logs de arranque.

## Impacto

La configuración declarada en el repositorio no era la que estaba en ejecución: un despliegue limpio se habría quedado sin datasource, y ningún dashboard versionado llegaba a cargarse.

## Remediación

`chmod 755` en `provisioning/`, `datasources/` y `dashboards/` (no contienen secretos) y reinicio de Grafana.

## Verificación

```
logger=provisioning.datasources level=info msg="inserting datasource from configuration" name=Prometheus
```

Sin errores de provisioning de datasources ni de dashboards tras el reinicio.

## Lección aprendida

Mismo patrón que HL-004 y HL-005: un control en verde no garantiza que la configuración se aplique. Hay que revisar los logs de arranque de cada servicio al desplegarlo.
