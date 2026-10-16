"""Sondas de salud de los servicios del catálogo.

Dos decisiones que vinieron de observar la Pi en marcha, no de la teoría:

1. **Van en paralelo** (`asyncio.gather`). En secuencial, la página tarda lo que el
   servicio más lento y se nota como "se queda pensando".

2. **Los resultados se cachean** (TTL por defecto 20 s). Sin caché, cargar la página
   cinco veces por minuto sondea cinco veces, y peor: las sondas en paralelo compiten
   entre sí por el I/O de la microSD. Se observó a Grafana devolver 503 con las cinco
   sondas simultáneas y 200 en 24/24 sondeos seguidos: no estaba caído, estaba
   saturado. Con la caché, el portal deja de medirse a sí mismo.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

TIMEOUT = 3.0                  # lectura de la respuesta
SEMILLA_TIMEOUT = 2.0          # apertura de conexión TCP
TTL = float(os.environ.get("PORTAL_HEALTH_TTL", "20"))

# Alias de red interna de Docker. Los contenedores en modo bridge no llegan al
# loopback del host por nombre, pero sí por 127.0.0.1 porque el gateway de Docker
# reenvía. Es lo que permite sondear Prometheus, publicado solo en 127.0.0.1.
ALIAS_DOCKER = "host.docker.internal"

_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def _a_loopback(url: str) -> str:
    partes = urlsplit(url)
    if partes.hostname == ALIAS_DOCKER:
        puerto = f":{partes.port}" if partes.port else ""
        return urlunsplit((partes.scheme, f"127.0.0.1{puerto}", partes.path, partes.query, ""))
    return url


async def _sonda_http(url: str, path: str, esperado: Any) -> dict[str, Any]:
    destino = _a_loopback(url.rstrip("/") + path)
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(SEMILLA_TIMEOUT, read=TIMEOUT),
            follow_redirects=True,
            trust_env=False,  # no heredamos proxies ni certificados del host
        ) as cliente:
            r = await cliente.get(destino)
        ok = r.status_code == esperado
        return {
            "ok": ok,
            "detalle": f"HTTP {r.status_code}" + ("" if ok else f" (esperaba {esperado})"),
            "ms": int(r.elapsed.total_seconds() * 1000),
        }
    except httpx.HTTPError as exc:
        return {"ok": False, "detalle": type(exc).__name__, "ms": None}


async def _sonda_tcp(url: str) -> dict[str, Any]:
    partes = urlsplit(_a_loopback(url))
    host, puerto = partes.hostname, partes.port or 80
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, puerto), timeout=TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.CancelledError):
            pass
        return {"ok": True, "detalle": f"acepta en {puerto}", "ms": None}
    except (OSError, asyncio.TimeoutError) as exc:
        return {"ok": False, "detalle": type(exc).__name__, "ms": None}


async def comprobar(servicio: dict[str, Any], usar_cache: bool = True) -> dict[str, Any]:
    """Sondea un servicio. Nunca lanza excepciones: un fallo es un dato, no un error."""
    cfg = servicio.get("health") or {"type": "none"}
    tipo = cfg.get("type", "none")
    if tipo == "none":
        return {"estado": "n/d", "ok": None, "detalle": "sin sonda", "ms": None, "cacheado": False}

    clave = f"{servicio['name']}|{servicio['url']}|{tipo}|{cfg.get('path','')}|{cfg.get('expect','')}"

    if usar_cache:
        previo = _cache.get(clave)
        if previo and (time.monotonic() - previo[0]) < TTL:
            return {**previo[1], "cacheado": True}

    if tipo == "http":
        r = await _sonda_http(servicio["url"], cfg.get("path", "/"), cfg.get("expect", 200))
    else:
        r = await _sonda_tcp(servicio["url"])

    salida = {
        "estado": "ok" if r["ok"] else "error",
        "ok": r["ok"],
        "detalle": r["detalle"],
        "ms": r["ms"],
        "cacheado": False,
    }
    _cache[clave] = (time.monotonic(), salida)
    return salida


async def comprobar_todos(servicios: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Sondea en paralelo lo que no esté en caché. Clave de vuelta: nombre del servicio."""
    if not servicios:
        return {}
    resultados = await asyncio.gather(*(comprobar(s) for s in servicios))
    return {s["name"]: r for s, r in zip(servicios, resultados)}


def invalidar_cache() -> None:
    _cache.clear()


__all__ = ["comprobar", "comprobar_todos", "invalidar_cache", "TTL"]