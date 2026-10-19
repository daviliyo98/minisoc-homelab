# HL-013: OWASP ZAP encendido de forma permanente, con procesos zombi y límite de heap ignorado

| Campo | Valor |
|---|---|
| Fecha | 2026-10-19 |
| Severidad | Media |
| Activo afectado | Raspberry Pi (host Docker), contenedor `websec-zap` |
| Estado | Mitigado (contenedor detenido); remediación en el repo, pendiente de verificación |

## Resumen

Al revisar la carga de la Pi durante el despliegue de Home Assistant, `top` mostró **127 procesos zombi**. Todos eran hijos de OWASP ZAP, el escáner de vulnerabilidades del `websec-scanner`, que llevaba **encendido desde el 10 de octubre** aunque está pensado para arrancarse solo bajo demanda. Además usaba un heap de casi 2 GB en lugar del 1 GB configurado.

## Evidencia

```
$ top -bn1 | head -3
load average: 4.97, 4.73, 2.96
Tasks: 350 total,   1 running, 222 sleeping,   0 stopped, 127 zombie

$ ps -fp 495414
UID   PID     PPID    C STIME TIME     CMD
pi    495414  495391  2 Oct10 04:12:43 java -Xmx1954m -jar /zap/zap-2.17.0.jar -daemon -host ...

$ ps -o pid,stat,comm --ppid 495414 | head
 509685 Z    crashhelper
 510115 Z    forkserver
 510137 Z    Socket Process
 510367 Z    RDD Process
 ...
```

`crashhelper`, `forkserver`, `Socket Process` y `RDD Process` son procesos auxiliares de Firefox, el navegador sin interfaz que ZAP usa para el spider.

## Análisis

Tres fallos encadenados:

1. **Java como PID 1 del contenedor.** `zap.sh` termina con `exec java ...`, así que Java pasa a ser el PID 1. Cuando un proceso de Firefox se queda huérfano, el kernel lo reasigna al PID 1, y Java no está programado para recoger (`wait()`) procesos que no lanzó él. Resultado: zombis que se acumulan mientras el contenedor viva.
2. **Herramienta convertida en servicio.** El servicio está en el `profile: zap` para arrancarse solo cuando se pide, pero tenía `restart: unless-stopped`. Bastó levantarlo una vez para que Docker lo mantuviera encendido indefinidamente, también tras reiniciar la Pi. Un escáner activo corriendo 24/7 sin uso es superficie de ataque y consumo de recursos sin beneficio.
3. **Límite de heap ignorado en silencio.** El compose definía `JAVA_TOOL_OPTIONS=-Xmx1g`, pero `zap.sh` calcula su propio `-Xmx` (1/4 de la RAM: 1954 MB en la Pi de 8 GB) y lo pasa por línea de comandos, que tiene prioridad. No ve el límite del contenedor porque el kernel no tiene activo el cgroup de memoria (**HL-004**).

Impacto: unos 2 GB de RAM ocupados de forma permanente, swap casi agotado (388 de 512 MB) y una tabla de procesos creciendo sin control. Si llega al límite de PID, el host no podría crear procesos nuevos, incluido el DNS de la red.

## Remediación

Mitigación inmediata:

```bash
sudo docker stop websec-zap
```

Corrección en `apps/websec-scanner/docker-compose.yml`:

- `init: true`: tini pasa a ser el PID 1 y recoge los huérfanos.
- `-Xmx1g` como argumento de `zap.sh`, que sí lo respeta, en lugar de `JAVA_TOOL_OPTIONS`.
- `restart: "no"`: ZAP se levanta para escanear y se apaga al terminar.

```bash
docker compose --profile zap up -d zap    # para escanear
docker compose stop zap                   # al terminar
```

## Verificación

```bash
top -bn1 | head -3                        # 0 zombie tras parar ZAP
docker compose --profile zap up -d zap
ps -o args= -C java | grep -o -- '-Xmx[^ ]*'   # debe decir -Xmx1g
docker exec websec-zap ps -o pid,comm -p 1      # PID 1 debe ser tini (docker-init)
```

## Lección aprendida

Un contenedor no es una máquina: si el proceso principal hace de PID 1 sin estar preparado para ello, nadie recoge los procesos huérfanos. Y las herramientas ofensivas (ZAP, Nuclei) deben vivir **apagadas por defecto**: un `restart` olvidado convierte una herramienta puntual en un servicio permanente que nadie vigila. Igual que en HL-004, un control configurado no es un control aplicado: hay que comprobar el proceso real (`ps`), no el fichero de configuración.
