# homelab-portal

Catálogo de los servicios del homelab con **estado de salud en vivo**. Un único punto
de entrada a lo que hay montado en la Raspberry Pi: cada tarjeta enlaza a su servicio y
a sus endpoints de API, y comprueba si responde.

No guarda estado propio: la configuración vive en `services.yaml`. Es un sitio más
donde escribir, no una base de datos más que mantener.

## Por qué existe

Cada servicio tenía su URL y sus credenciales repartidas. Este portal hace tres cosas
concretas:

1. **Un sitio donde están todos**, incluidos los endpoints de API y cómo autenticarse.
2. **Estado de salud en vivo**, para saber de un vistazo qué se ha caído.
3. **Enlaces correctos según dónde estés**: la IP de casa no existe fuera de la LAN, y
   el hostname público del tailnet no es una vía fiable. El catálogo guarda el
   **puerto** y compone la URL, con un conmutador LAN / tailnet.

## Despliegue

```bash
cp .env.example .env
# genera la contraseña:  openssl rand -hex 24
docker compose up -d --build
```

Acceso: `http://100.114.119.53:8080` (solo por Tailscale).

## Añadir un servicio

Solo editar `services.yaml` y recargar el navegador. **No hay que reconstruir la
imagen ni reiniciar**: el catálogo va montado en solo lectura y se recarga al detectar
que cambia el `mtime` del fichero.

```yaml
  - name: Mi servicio
    description: Qué hace
    port: 8080
    icon: "🔧"
    stack: utilidades
    health: { type: http, path: /health }   # http | tcp | none
    tags: [etiqueta]
    apis:
      - path: "/api/v1/recurso"
        note: "Autenticación: cabecera X-Api-Key"
```

| Clave | Para qué |
|---|---|
| `port` | obligatorio; el portal compone la URL a partir del host y este número |
| `health.type` | `http` · `tcp` · `none` |
| `health.expect` | código esperado si el de por defecto (200) no vale |
| `host` | solo si el servicio **no** está en la IP de la Pi (Prometheus, en `127.0.0.1`) |
| `apis` | endpoints que se listan en la tarjeta, con la nota de autenticación |

Un servicio con `host` propio se marca como `solo_destino` y **no se muestra en modo
LAN**, porque su enlace solo abre desde la propia Pi. En el JSON sí aparece siempre:
un script corriendo en la Pi sí puede usar `127.0.0.1`.

## API

Pensada para scripts, no para el navegador:

```bash
# catálogo completo, con estado
curl -s -u admin:CLAVE http://100.114.119.53:8080/api/services | jq '.servicios[].name'

# instantáneo, sin sondear (para un cron que no debe depender de otros servicios)
curl -s -u admin:CLAVE 'http://100.114.119.53:8080/api/services?salud=false'

# solo los que están caídos
curl -s -u admin:CLAVE http://100.114.119.53:8080/api/services \
  | jq -r '.servicios[] | select(.salud.ok == false) | .name'
```

| Ruta | Para qué |
|---|---|
| `/` | Catálogo (HTML) |
| `/api/services` | Catálogo en JSON, con sondas opcionales |
| `/api/config` | Chequeo de configuración del despliegue |
| `/healthz` | Salud del propio portal |

## Red: por qué `network_mode: host`

Prometheus y Unbound escuchan en el **loopback del host** (`127.0.0.1:9090` y
`127.0.0.1:5335`). El loopback del host está aislado del de los contenedores: no se
alcanza ni por `host.docker.internal` (que resuelve a `172.17.0.1`) ni por el propio
`127.0.0.1` del contenedor. Se comprobó: `Connection refused` por ambos caminos.

En red host el portal sí llega a todo eso. Para que eso no lo abra a la LAN,
`entrypoint.sh` ata uvicorn **a la IP del tailnet**, nunca a `0.0.0.0`. Verificado:
`192.168.1.20:8080` da conexión rechazada.

## Sondas: por qué hay caché

`PORTAL_HEALTH_TTL` (20 s por defecto) cachea los resultados. Sin caché, cargar la
página sondea los cinco servicios a la vez, y en la microSD de la Pi eso **se nota en
el servicio observado**: Grafana devolvió `503` con las cinco sondas simultáneas y
`200` en 24/24 sondeos seguidos. No estaba caído, estaba saturado; el propio portal se
midiendo en la concurrencia provocaba el falso positivo.

## Seguridad

- **Solo tailnet**: uvicorn ata a `100.114.119.53`, no a `0.0.0.0`. No es visible ni
  desde la LAN ni desde internet (CGNAT).
- **HTTP básico** con clave en `.env`. Si se deja vacía, el portal **arranca sin
  autenticar y lo avisa por log**.
- `read_only`, `cap_drop: ALL`, `no-new-privileges`, usuario no root (UID 10001).
- `mem_limit: 256m` — ojo: **este kernel no soporta límites de memoria en contenedores**
  y Docker lo descarta con un aviso. Es una limitación del host, no del compose.
- Catálogo montado en solo lectura: el contenedor no puede reescribir su propia config.

## Notas de operación

- Las sondas corren **en paralelo** (`asyncio.gather`): en secuencial la página tarda
  lo que el servicio más lento.
- `crowdsec` ya ocupa `127.0.0.1:8080` en el host. El portal ata a la IP del tailnet,
  así que no chocan, pero si cambias `BIND_HOST` a `127.0.0.1` habrá conflicto.
- Si Tailscale reasigna la IP del nodo, hay que actualizar `BIND_HOST` en `compose.yaml`
  y reconstruir (el `environment` está en la imagen, no en un volumen).