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

Acceso: `http://192.168.1.20:8090` en casa, `http://100.114.119.53:8090` por tailnet.

## Añadir un servicio

Solo editar `services.yaml` y recargar el navegador. **No hay que reconstruir la
imagen ni reiniciar**: el catálogo va montado en solo lectura y se recarga al detectar
que cambia el `mtime` del fichero.

```yaml
  - name: Mi servicio
    description: Qué hace
    port: 3000
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
| `scheme` | `http` (por defecto) o `https`. **No siempre es `http`**: Portainer devuelve `400` si le hablas en claro |
| `path` | subruta. Necesaria en Pi-hole, cuyo panel está en `/admin` (la raíz da `403`) |
| `health.type` | `http` · `tcp` · `none` |
| `health.expect` | código esperado si el de por defecto (200) no vale |
| `health.verify` | `false` si el servicio usa certificado autofirmado; si no, la sonda lo daría por caído |
| `host` | solo si el servicio **no** está en la IP de la Pi (Prometheus, en `127.0.0.1`) |
| `apis` | endpoints que se listan en la tarjeta, con la nota de autenticación |

Un servicio con `host` propio se marca como `solo_destino` y **no se muestra en modo
LAN**, porque su enlace solo abre desde la propia Pi. En el JSON sí aparece siempre:
un script corriendo en la Pi sí puede usar `127.0.0.1`.

## API

Pensada para scripts, no para el navegador:

```bash
# catálogo completo, con estado
curl -s -u admin:CLAVE http://100.114.119.53:8090/api/services | jq '.servicios[].name'

# instantáneo, sin sondear (para un cron que no debe depender de otros servicios)
curl -s -u admin:CLAVE 'http://100.114.119.53:8090/api/services?salud=false'

# solo los que están caídos
curl -s -u admin:CLAVE http://100.114.119.53:8090/api/services \
  | jq -r '.servicios[] | select(.salud.ok == false) | .name'
```

| Ruta | Para qué |
|---|---|
| `/` | Servicios (HTML): lista y ficha del servicio elegido (`?sel=Grafana`) |
| `/alertas` | Registro de caídas y recuperaciones de los últimos días |
| `/apis` | Todos los endpoints de API del catálogo, con la URL completa |
| `/entorno` | Tiempo, terremotos cercanos y noticias de la zona de la Pi |
| `/dispositivos` | Aparatos de la red: conectados o no y qué consultan por DNS |
| `/api/services` | Catálogo en JSON, con sondas opcionales |
| `/api/eventos` | Cambios de estado en JSON (`?servicio=`, `?limite=`) |
| `/api/config` | Chequeo de configuración del despliegue |
| `/healthz` | Salud del propio portal |

## Red: por qué `network_mode: host`

Prometheus y Unbound escuchan en el **loopback del host** (`127.0.0.1:9090` y
`127.0.0.1:5335`). El loopback del host está aislado del de los contenedores: no se
alcanza ni por `host.docker.internal` (que resuelve a `172.17.0.1`) ni por el propio
`127.0.0.1` del contenedor. Se comprobó: `Connection refused` por ambos caminos.

En red host el portal sí llega a todo eso. En red host no hay `ports:`: la exposición la
controla uvicorn con `BIND_HOST` (por defecto `0.0.0.0`, o sea LAN + tailnet).

Ojo con una trampa: `crowdsec` ya ocupa `127.0.0.1:8080` en el host. Si fijaras
`BIND_HOST=127.0.0.1` habría conflicto de puerto.

## Sondas: por qué hay caché

`PORTAL_HEALTH_TTL` (20 s por defecto) cachea los resultados. Sin caché, cargar la
página sondea los cinco servicios a la vez, y en la microSD de la Pi eso **se nota en
el servicio observado**: Grafana devolvió `503` con las cinco sondas simultáneas y
`200` en 24/24 sondeos seguidos. No estaba caído, estaba saturado; el propio portal se
midiendo en la concurrencia provocaba el falso positivo.

## Historial: disponibilidad y alertas

Un muestreador en segundo plano (`app/history.py`) sondea todos los servicios cada
`PORTAL_POLL` segundos (60 por defecto) **haya o no alguien mirando el portal**, y lo
guarda en una SQLite en el volumen `portal-data` (`/data/portal.db`). Si el dato
dependiera de cuándo abres la página, una caída de madrugada no existiría.

- `sondas`: una fila por servicio y muestra. Alimenta la barra de **disponibilidad 24 h**.
- `eventos`: una fila solo cuando un servicio **cambia** de estado. Alimenta
  "Caído desde las 21:06" y la página de Alertas.
- Se purga lo anterior a `PORTAL_RETENCION_DIAS` (7 por defecto): unos pocos MB.
- Si `/data` no es escribible, el portal sigue funcionando sin historial y lo dice.

`/api/eventos` sirve para enganchar un aviso (Telegram, ntfy) o mandar los cambios a
un SIEM sin tocar el portal.

## Entorno: tiempo, terremotos y noticias

`app/entorno.py` consulta tres fuentes públicas **sin clave de API** cada
`PORTAL_ENTORNO_CADA` segundos (900 por defecto):

| Bloque | Fuente |
|---|---|
| Tiempo y previsión de 7 días | [Open-Meteo](https://open-meteo.com) |
| Terremotos en un radio | [EMSC / seismicportal.eu](https://www.seismicportal.eu) (incluye datos del IGN) |
| Noticias | RSS; por defecto Google News de la ciudad |

La ubicación por defecto es Granada a nivel de ciudad. **Las coordenadas de casa van
en el `.env`, nunca en `services.yaml`**: el repositorio es público y el `.env` está
en `.gitignore`.

```bash
# apps/homelab-portal/.env
ENTORNO_NOMBRE=Granada
ENTORNO_LAT=37.18
ENTORNO_LON=-3.60
ENTORNO_RADIO_KM=150
```

Tras cambiarlo: `docker compose up -d` (recrea el contenedor con las variables nuevas).
El resto de opciones, que no son sensibles, pueden ir en `services.yaml`:

```yaml
entorno:
  dias_sismos: 7         # terremotos de los últimos N días
  noticias:              # opcional: tus propios RSS en vez de Google News
    - https://www.ideal.es/rss/2.0/?section=granada
```

Decisiones de seguridad, porque esto es lo único del portal que lee datos de internet:

- **La consulta la hace la Pi, no el navegador.** La CSP sigue en `'self'` y el
  navegador no avisa a terceros de que estás mirando el panel.
- **Lo que llega de fuera es dato no confiable.** RSS con `defusedxml` (bloquea XXE y
  "billion laughs"), tamaño máximo por respuesta, enlaces solo `http`/`https` (un
  `javascript:` se descarta) y autoescape de Jinja en los titulares.
- **Una fuente caída no rompe nada**: se conserva el último dato bueno y se indica
  la hora y el error del último intento.

## Dispositivos: inventario IoT

`app/dispositivos.py` cruza dos fuentes cada minuto:

- **Tabla ARP del host** (`/proc/net/arp`): quién está conectado. El portal va en red
  host, así que la lee sin enviar paquetes y sin `NET_RAW` (sigue con `cap_drop: ALL`).
- **API de Pi-hole v6**: dispositivos, consultas DNS de las últimas 24 h, dominios más
  consultados y cuántos bloqueó Pi-hole. Es la telemetría que el robot o la Alexa
  mandan "a casa".

Configuración (en el `.env` del portal):

```bash
PIHOLE_API=http://127.0.0.1/api
PIHOLE_PASSWORD=<contraseña de aplicación de Pi-hole>
```

Usa una **contraseña de aplicación** (*Pi-hole → Settings → Web interface / API →
Configure app password*), no la de administrador: se revoca sin tocar la principal.
El portal abre **una** sesión y la reutiliza (Pi-hole limita las sesiones
simultáneas) y la cierra al apagarse.

**Los nombres los pone Pi-hole**: *Group Management → Clients*, se da de alta la MAC
del aparato con un comentario (`Robot aspirador`, o `Robot aspirador | Xiaomi T12`
para añadir el modelo). El portal solo los lee, así que sigue sin escribir nada a
partir del navegador: sin formularios, sin CSRF y sin permisos de escritura. Además,
el mismo cliente sirve para aplicarle en Pi-hole grupos de bloqueo propios (por
ejemplo, uno más estricto para el IoT). También vale un cliente dado de alta por IP
si el aparato la tiene reservada en el router.

Lo que no está dado de alta aparece como *sin identificar*, en ámbar: un aparato
desconocido en la red es lo primero que hay que mirar.

Para que la lista no se llene de aparatos de paso (el móvil de una visita), lo que
**no** está dado de alta en Pi-hole solo se muestra si se ha visto en las últimas
`PORTAL_DISPOSITIVOS_VENTANA_H` horas (3 por defecto): en la tabla ARP o con alguna
consulta DNS. Los dados de alta se muestran siempre, aunque estén apagados. Al pie de
la lista se indica cuántos quedan ocultos.

Si un aparato está conectado pero no tiene consultas DNS, probablemente usa un DNS
fijado de fábrica y se salta Pi-hole (como el iPhone en HL-003).

El control de los aparatos (encender el robot, avisos por Alexa) no está en el
portal: está en `stacks/homeassistant`, aislado, porque guarda tokens de Xiaomi y Amazon.

## Seguridad

- **Accesible por la LAN y por el tailnet**: `http://192.168.1.20:8090` y
  `http://100.114.119.53:8090`. Lo protege la contraseña, no la red. Fijando
  `BIND_HOST` a una IP concreta se restringe a esa vía.
- **HTTP básico** con clave en `.env`. Si se deja vacía, el portal **arranca sin
  autenticar y lo avisa por log**.
- `read_only`, `cap_drop: ALL`, `no-new-privileges`, usuario no root (UID 10001).
- `mem_limit: 256m` — ojo: **este kernel no soporta límites de memoria en contenedores**
  y Docker lo descarta con un aviso. Es una limitación del host, no del compose.
- Catálogo montado en solo lectura: el contenedor no puede reescribir su propia config.
- **Cabeceras**: CSP estricta (`script-src 'self'`, sin scripts en línea; todo el
  CSS, JS y las fuentes se sirven desde el propio portal), `X-Frame-Options: DENY`
  contra clickjacking, `nosniff` y `Referrer-Policy: no-referrer`. `/api/docs` queda
  fuera de la CSP porque Swagger carga recursos de un CDN.
- **Credenciales comparadas en tiempo constante** (`secrets.compare_digest`): con `==`
  el tiempo de respuesta revela cuántos caracteres de la clave son correctos.
- Fuentes Barlow (licencia OFL, en `app/static/fonts/`) autoalojadas: el portal no
  depende de internet ni filtra visitas a Google Fonts.

## Notas de operación

- Las sondas corren **en paralelo** (`asyncio.gather`): en secuencial la página tarda
  lo que el servicio más lento.
- `crowdsec` ya ocupa `127.0.0.1:8080` en el host, y por eso el portal usa el
  `8090`: atar a `0.0.0.0:8080` falla con `address already in use`. No pongas
  `BIND_PORT=8080` sin mover antes crowdsec.
- Si Tailscale reasigna la IP del nodo, hay que actualizar `BIND_HOST` en `compose.yaml`
  y reconstruir (el `environment` está en la imagen, no en un volumen).