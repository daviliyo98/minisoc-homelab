"""Portal del homelab: catálogo de servicios con estado de salud e historial.

Un punto de entrada único a lo que hay montado en la Raspberry Pi. La configuración
vive en services.yaml; el historial de sondas, en una SQLite pequeña (ver history.py).
Las sondas van en paralelo para que la página no se quede pensando en una Pi con
microSD lenta.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import catalog, dispositivos, entorno, health, history, salud

# Rutas relativas al propio paquete, no al WORKDIR: el Dockerfile hace
# `COPY app ./app`, así que el código vive en /app/app y los estáticos en
# /app/app/static. Hardcodear "/app/static" rompía el arranque.
RAIZ_APP = Path(__file__).resolve().parent

# --- Autenticación -------------------------------------------------------------
# Solo para uso propio por tailnet, pero HTTP básico evita que el portal quede
# abierto a cualquiera que alcance la IP. La clave va en .env (fuera del repo).
USUARIO = os.environ.get("PORTAL_USER", "admin")
CLAVE = os.environ.get("PORTAL_PASSWORD", "")
SIN_CLAVE = not CLAVE  # si no hay clave, se avisa al arrancar en vez de fallar

seguridad = HTTPBasic(auto_error=False)


@contextlib.asynccontextmanager
async def ciclo_de_vida(_app: FastAPI):
    """Arranca las tareas de fondo (historial y entorno) y las para limpio al apagar."""
    tareas = [
        asyncio.create_task(history.muestreador()),
        asyncio.create_task(entorno.actualizador()),
        asyncio.create_task(dispositivos.actualizador()),
        asyncio.create_task(salud.actualizador()),
    ]
    try:
        yield
    finally:
        for tarea in tareas:
            tarea.cancel()
        for tarea in tareas:
            with contextlib.suppress(asyncio.CancelledError):
                await tarea


app = FastAPI(
    title="Portal MINISOC",
    description="Catálogo de servicios del homelab con estado de salud",
    version="2.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    lifespan=ciclo_de_vida,
)

# --- Cabeceras de seguridad --------------------------------------------------
# El portal enlaza a paneles de administración: que no se pueda enmarcar
# (clickjacking) ni ejecutar script inyectado. Todo el CSS/JS/fuentes es propio,
# así que la CSP puede ser estricta. /api/docs (Swagger) carga de CDN: se excluye.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'"
)


@app.middleware("http")
async def cabeceras_seguridad(request: Request, call_next):
    respuesta = await call_next(request)
    respuesta.headers.setdefault("X-Content-Type-Options", "nosniff")
    respuesta.headers.setdefault("Referrer-Policy", "no-referrer")
    respuesta.headers.setdefault("X-Frame-Options", "DENY")
    if not request.url.path.startswith("/api/docs"):
        respuesta.headers.setdefault("Content-Security-Policy", CSP)
    return respuesta


app.mount("/static", StaticFiles(directory=str(RAIZ_APP / "static")), name="static")
plantillas = Jinja2Templates(directory=str(RAIZ_APP / "templates"))


# --- Formato de horas --------------------------------------------------------
# La imagen slim no trae tzdata: la zona llega por TZ en formato POSIX
# (ver compose.yaml) y time.localtime la entiende sin base de datos de zonas.
time.tzset()


def _hora(ts: int | None, ahora: float | None = None) -> str:
    if not ts:
        return "—"
    ahora = ahora or time.time()
    t, hoy = time.localtime(ts), time.localtime(ahora)
    hhmm = time.strftime("%H:%M", t)
    if t.tm_yday == hoy.tm_yday and t.tm_year == hoy.tm_year:
        return hhmm
    if ahora - ts < 2 * 86400 and time.localtime(ahora - 86400).tm_yday == t.tm_yday:
        return f"ayer {hhmm}"
    return time.strftime("%d/%m %H:%M", t)


def _duracion(segundos: int | float | None) -> str:
    if segundos is None:
        return ""
    s = int(segundos)
    if s < 90:
        return "1 min"
    if s < 3600:
        return f"{s // 60} min"
    if s < 86400:
        return f"{s // 3600} h {s % 3600 // 60:02d} min"
    return f"{s // 86400} d {s % 86400 // 3600} h"


plantillas.env.filters["hora"] = _hora
plantillas.env.filters["duracion"] = _duracion
plantillas.env.globals["ahora"] = lambda: int(time.time())


def _exigir(credenciales: HTTPBasicCredentials | None = Depends(seguridad)) -> str:
    if SIN_CLAVE:
        return USUARIO
    # compare_digest en tiempo constante: con `==` la comparación se corta en el
    # primer carácter distinto y el tiempo de respuesta filtra cuánto has acertado.
    # Se evalúan las dos comparaciones siempre (& en vez de and) por el mismo motivo.
    correcto = credenciales is not None and (
        secrets.compare_digest(credenciales.username.encode(), USUARIO.encode())
        & secrets.compare_digest(credenciales.password.encode(), CLAVE.encode())
    )
    if not correcto:
        raise HTTPException(
            status_code=401,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": 'Basic realm="Portal MINISOC"'},
        )
    return USUARIO


# Orden de gravedad: lo caído arriba, que es lo que se viene a mirar.
ORDEN_ESTADO = {"error": 0, "nd": 1, "ok": 2}


def _clase(estado: str | None) -> str:
    """health devuelve 'n/d', que no vale como clase CSS (`estado-n/d`)."""
    return estado if estado in ("ok", "error") else "nd"


def _catalogo(destino: str) -> list[dict[str, Any]]:
    try:
        servicios = catalog.servicios(destino)
    except catalog.CatalogoError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    # Los servicios que solo viven en el loopback del host (Prometheus) no tienen
    # sentido en LAN: se ocultan para no mostrar un enlace que no abre nada.
    if destino == "lan":
        servicios = [s for s in servicios if not s["solo_destino"]]
    return servicios


async def _comun(request: Request, destino: str, seccion: str) -> dict[str, Any]:
    """Contexto que comparten todas las páginas: menú, contadores y destino."""
    servicios = _catalogo(destino)
    estados = await health.comprobar_todos(servicios)
    for e in estados.values():
        e["clase"] = _clase(e.get("estado"))
    caidos = [s["name"] for s in servicios if estados[s["name"]]["clase"] == "error"]
    for s in servicios:
        # Base sin ruta: los endpoints de API cuelgan de la raíz, no de /admin.
        partes = urlsplit(s["url"])
        s["base"] = f"{partes.scheme}://{partes.netloc}"
    return {
        "request": request,
        "seccion": seccion,
        "destino": destino,
        "red": catalog.redes(),
        "stacks": catalog.stacks(),
        "sin_clave": SIN_CLAVE,
        "historial": history.disponible(),
        "entorno": entorno.estado(),
        "dispositivos": dispositivos.estado(),
        "salud": salud.estado(),
        "todos": servicios,
        "estados": estados,
        "caidos": caidos,
        "generado": time.strftime("%H:%M:%S"),
        "q": "",
        "stack": "",
        "ver": "todos",
    }


DESTINO = Query("tailnet", pattern="^(tailnet|lan)$")


@app.get("/", response_class=HTMLResponse)
async def inicio(
    request: Request,
    destino: str = DESTINO,
    q: str = Query("", max_length=100),
    stack: str = Query("", max_length=50),
    ver: str = Query("todos", pattern="^(todos|caidos)$"),
    sel: str = Query("", max_length=100),
    _user: str = Depends(_exigir),
):
    """Servicios: lista a la izquierda y ficha del seleccionado a la derecha."""
    ctx = await _comun(request, destino, "servicios")
    estados = ctx["estados"]
    visibles = list(ctx["todos"])

    if q:
        aguja = q.casefold()
        visibles = [
            s for s in visibles
            if aguja in s["name"].casefold()
            or aguja in s.get("description", "").casefold()
            or any(aguja in t.casefold() for t in s.get("tags", []))
        ]
    if stack:
        visibles = [s for s in visibles if s.get("stack") == stack]
    if ver == "caidos":
        visibles = [s for s in visibles if estados[s["name"]]["clase"] == "error"]
    visibles.sort(key=lambda s: ORDEN_ESTADO[estados[s["name"]]["clase"]])

    # Ficha: la pedida; si no, la del primer caído; si no, la primera de la lista.
    elegido = next((s for s in visibles if s["name"] == sel), None) or (visibles[0] if visibles else None)
    ficha = None
    if elegido:
        nombre = elegido["name"]
        ficha = {
            "s": elegido,
            "e": estados[nombre],
            "dispo": history.disponibilidad_24h(nombre),
            "eventos": history.eventos(nombre, limite=5),
            "desde": history.desde(nombre),
        }

    ctx.update({
        "servicios": visibles,
        "ficha": ficha,
        "q": q,
        "stack": stack,
        "ver": ver,
        "total": len(ctx["todos"]),
    })
    return plantillas.TemplateResponse(request, "index.html", ctx)


@app.get("/alertas", response_class=HTMLResponse)
async def alertas(request: Request, destino: str = DESTINO, _user: str = Depends(_exigir)):
    """Registro de cambios de estado: cuándo cayó cada cosa y cuándo volvió."""
    ctx = await _comun(request, destino, "alertas")
    # Aparatos nuevos aún sin dar de alta en Pi-hole (los ya registrados se dan por revisados).
    revisados = {d["mac"] for d in dispositivos.estado()["lista"] if d["conocido"]}
    ctx.update({
        "nuevos_disp": [n for n in history.dispositivos_nuevos(dias=7) if n["mac"] not in revisados],
        "eventos": _con_duracion(history.eventos(limite=200)),
        "retencion": history.RETENCION_DIAS,
        "intervalo": history.INTERVALO,
    })
    return plantillas.TemplateResponse(request, "alertas.html", ctx)


def _con_duracion(evs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cuánto duró cada estado: hasta el siguiente evento del mismo servicio.

    Si es el último evento del servicio, el estado sigue vigente: `dura` es None y
    `vigente` True (la plantilla lo pinta como "sigue así").
    """
    siguiente: dict[str, int] = {}
    for ev in evs:  # vienen del más reciente al más antiguo
        fin = siguiente.get(ev["servicio"])
        ev["vigente"] = fin is None
        ev["dura"] = (fin - ev["ts"]) if fin else None
        siguiente[ev["servicio"]] = ev["ts"]
    return evs


@app.get("/entorno", response_class=HTMLResponse)
async def pagina_entorno(request: Request, destino: str = DESTINO, _user: str = Depends(_exigir)):
    """Tiempo, terremotos cercanos y noticias de la zona de la Pi."""
    ctx = await _comun(request, destino, "entorno")
    return plantillas.TemplateResponse(request, "entorno.html", ctx)


@app.get("/dispositivos", response_class=HTMLResponse)
async def pagina_dispositivos(
    request: Request,
    destino: str = DESTINO,
    sel: str = Query("", max_length=17),
    _user: str = Depends(_exigir),
):
    """Aparatos de la red: conectados o no, y qué consultan por DNS."""
    ctx = await _comun(request, destino, "dispositivos")
    lista = ctx["dispositivos"]["lista"]
    ctx["ficha_disp"] = next((d for d in lista if d["mac"] == sel.lower()), None) or (lista[0] if lista else None)
    return plantillas.TemplateResponse(request, "dispositivos.html", ctx)


@app.get("/salud", response_class=HTMLResponse)
async def pagina_salud(request: Request, destino: str = DESTINO, _user: str = Depends(_exigir)):
    """Estado de la propia Pi (CPU, temperatura, memoria, disco) desde Prometheus."""
    ctx = await _comun(request, destino, "salud")
    grafana = next((s for s in ctx["todos"] if s["name"] == "Grafana"), None)
    ctx["url_grafana"] = grafana["url"] if grafana else None
    return plantillas.TemplateResponse(request, "salud.html", ctx)


@app.get("/api/salud")
async def api_salud(_user: str = Depends(_exigir)):
    """Valores actuales de salud de la Pi en JSON (sin las series)."""
    e = salud.estado()
    return {
        "ts": e["ts"], "error": e["error"], "extra": e["extra"],
        "metricas": [{k: m[k] for k in ("clave", "nombre", "unidad", "valor", "nivel", "min", "max")}
                     for m in e["metricas"]],
    }


@app.get("/apis", response_class=HTMLResponse)
async def apis(request: Request, destino: str = DESTINO, _user: str = Depends(_exigir)):
    """Todos los endpoints de API del catálogo en una sola página."""
    ctx = await _comun(request, destino, "apis")
    ctx["con_api"] = [s for s in ctx["todos"] if s.get("apis")]
    return plantillas.TemplateResponse(request, "apis.html", ctx)


@app.get("/api/services")
async def api_servicios(
    destino: str = DESTINO,
    salud: bool = Query(True, description="Incluir el sondeo de estado"),
    _user: str = Depends(_exigir),
):
    """El catálogo en JSON. Pensado para scripts, no para el navegador.

    `salud=false` omite el sondeo: instantáneo, para consultar desde un cron sin
    depender de que los otros servicios estén levantados.
    """
    try:
        servicios = catalog.servicios(destino)
    except catalog.CatalogoError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if salud:
        estados = await health.comprobar_todos(servicios)
        for s in servicios:
            s["salud"] = estados.get(s["name"])
    return {
        "destino": destino,
        "red": catalog.redes(),
        "servicios": servicios,
    }


@app.get("/api/eventos")
async def api_eventos(
    servicio: str = Query("", max_length=100),
    limite: int = Query(50, ge=1, le=500),
    _user: str = Depends(_exigir),
):
    """Cambios de estado en JSON: para un script de alertas o para mandarlos a un SIEM."""
    return {"eventos": history.eventos(servicio or None, limite=limite)}


@app.get("/api/dispositivos/nuevos")
async def api_dispositivos_nuevos(
    dias: int = Query(7, ge=1, le=30),
    _user: str = Depends(_exigir),
):
    """Aparatos nuevos en la red sin dar de alta en Pi-hole (para un aviso por Telegram/ntfy)."""
    revisados = {d["mac"] for d in dispositivos.estado()["lista"] if d["conocido"]}
    return {"nuevos": [n for n in history.dispositivos_nuevos(dias=dias) if n["mac"] not in revisados]}


@app.get("/healthz", include_in_schema=False)
async def healthz():
    """Salud del propio portal. Lo consume el balanceador o el monitor."""
    return JSONResponse({"ok": True, "servicio": "homelab-portal"})


@app.get("/api/config", include_in_schema=False)
async def config(_user: str = Depends(_exigir)):
    """Chequeo de la configuración, para detectar errores de despliegue."""
    try:
        red = catalog.redes()
        n = len(catalog.servicios())
    except catalog.CatalogoError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
    return {
        "ok": True,
        "servicios": n,
        "red": red,
        "autenticacion": "desactivada (sin PORTAL_PASSWORD)" if SIN_CLAVE else "http-básica",
        "historial": str(history.RUTA_DB) if history.disponible() else "desactivado",
    }
