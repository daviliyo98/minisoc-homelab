"""Portal del homelab: catálogo de servicios con estado de salud.

Un punto de entrada único a lo que hay montado en la Raspberry Pi. Sin estado propio
(la configuración vive en services.yaml) y con las sondas en paralelo para que la
página no se quede pensando en una Pi con microSD lenta.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import catalog, health

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

app = FastAPI(
    title="Portal MINISOC",
    description="Catálogo de servicios del homelab con estado de salud",
    version="1.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.mount("/static", StaticFiles(directory=str(RAIZ_APP / "static")), name="static")
plantillas = Jinja2Templates(directory=str(RAIZ_APP / "templates"))


def _exigir(credenciales: HTTPBasicCredentials | None = Depends(seguridad)) -> str:
    if SIN_CLAVE:
        return USUARIO
    correcto = (
        credenciales is not None
        and credenciales.username == USUARIO
        and credenciales.password == CLAVE
    )
    if not correcto:
        raise HTTPException(
            status_code=401,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": 'Basic realm="Portal MINISOC"'},
        )
    return USUARIO


@app.get("/", response_class=HTMLResponse)
async def inicio(
    request: Request,
    destino: str = Query("tailnet", pattern="^(tailnet|lan)$"),
    q: str = Query("", max_length=100),
    stack: str = Query("", max_length=50),
    _user: str = Depends(_exigir),
):
    """Catálogo. `destino` decide si los enlaces salen por LAN o por tailnet."""
    try:
        servicios = catalog.servicios(destino)
    except catalog.CatalogoError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    # Los servicios que solo viven dentro de Docker (p.ej. Prometheus en loopback)
    # no tienen sentido en LAN: se ocultan para no mostrar un enlace que no abre nada.
    visibles = servicios if destino == "tailnet" else [s for s in servicios if not s["solo_destino"]]

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

    estados = await health.comprobar_todos(visibles)

    return plantillas.TemplateResponse(
        "index.html",
        {
            "request": request,
            "servicios": visibles,
            "estados": estados,
            "destino": destino,
            "q": q,
            "stack": stack,
            "stacks": catalog.stacks(),
            "red": catalog.redes(),
            "sin_clave": SIN_CLAVE,
            "generado": datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S"),
            "total": len(servicios),
        },
    )


@app.get("/api/services")
async def api_servicios(
    destino: str = Query("tailnet", pattern="^(tailnet|lan)$"),
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
    }