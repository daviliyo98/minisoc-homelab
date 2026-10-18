"""Entorno de la Pi: tiempo, terremotos cercanos y noticias locales.

Tres decisiones de seguridad y de robustez, por este orden:

1. **El navegador nunca habla con terceros.** Es la Pi la que consulta las fuentes,
   en segundo plano y cada PORTAL_ENTORNO_CADA segundos (15 min por defecto). La
   página solo pinta lo que ya está en memoria: la CSP sigue siendo `'self'` y, si se
   cae internet, el portal no se queda esperando a nadie.

2. **Todo lo que llega de fuera es dato no confiable.** Los RSS se parsean con
   defusedxml (sin entidades externas ni "billion laughs"), cada respuesta tiene un
   tamaño máximo, los enlaces solo se aceptan si son http/https (nada de
   `javascript:`) y los textos los escapa Jinja al pintarlos.

3. **Un fallo de una fuente no tumba las otras.** Cada bloque guarda su propio
   error y conserva el último dato bueno, marcado con su hora.

Fuentes sin clave de API:
- Tiempo: Open-Meteo (https://open-meteo.com).
- Terremotos: EMSC/seismicportal.eu (FDSN), que agrega al IGN para la península.
- Noticias: RSS (por defecto, Google News en español para la ciudad).
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import quote_plus, urlsplit

import httpx
from defusedxml import ElementTree as XML

from . import catalog

log = logging.getLogger("portal.entorno")

CADA = max(300, int(os.environ.get("PORTAL_ENTORNO_CADA", "900")))
TIMEOUT = httpx.Timeout(10.0, connect=5.0)
MAX_BYTES = 2_000_000          # ninguna de estas respuestas legítimas pasa de unos KB
USER_AGENT = "MINISOC-homelab-portal/2.1 (+https://github.com/daviliyo98/minisoc-homelab)"

# Ubicación por defecto: Granada (nivel ciudad, no la dirección de casa).
# Se cambia con un bloque `entorno:` en services.yaml, sin reconstruir la imagen.
POR_DEFECTO: dict[str, Any] = {
    "nombre": "Granada",
    "lat": 37.1773,
    "lon": -3.5986,
    "radio_km": 150,
    "dias_sismos": 7,
    "noticias": [],            # vacío = Google News de `nombre`
    "max_noticias": 12,
}

_estado: dict[str, dict[str, Any]] = {
    "tiempo": {"datos": None, "ts": None, "error": None},
    "sismos": {"datos": None, "ts": None, "error": None},
    "noticias": {"datos": None, "ts": None, "error": None},
}


def config() -> dict[str, Any]:
    try:
        propia = catalog._cargar().get("entorno") or {}
    except catalog.CatalogoError:
        propia = {}
    return {**POR_DEFECTO, **{k: v for k, v in propia.items() if v is not None}}


def estado() -> dict[str, Any]:
    return {"config": config(), "cada": CADA, **_estado}


# --- Utilidades -----------------------------------------------------------------

async def _get(cliente: httpx.AsyncClient, url: str, **params: Any) -> bytes:
    r = await cliente.get(url, params=params or None)
    r.raise_for_status()
    if len(r.content) > MAX_BYTES:
        raise ValueError(f"respuesta demasiado grande ({len(r.content)} bytes)")
    return r.content


def _enlace_seguro(url: str | None) -> str | None:
    """Solo http/https. Un RSS con `javascript:alert(1)` como enlace se descarta."""
    if not url:
        return None
    url = url.strip()
    return url if urlsplit(url).scheme in ("http", "https") else None


def distancia_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Haversine: distancia sobre la superficie terrestre."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


# Códigos WMO de Open-Meteo -> (texto, icono). Los iconos son símbolos SVG de base.html.
WMO: dict[int, tuple[str, str]] = {
    0: ("Despejado", "sol"), 1: ("Casi despejado", "sol"), 2: ("Parcialmente nuboso", "sol-nube"),
    3: ("Cubierto", "nube"), 45: ("Niebla", "niebla"), 48: ("Niebla con escarcha", "niebla"),
    51: ("Llovizna débil", "lluvia"), 53: ("Llovizna", "lluvia"), 55: ("Llovizna intensa", "lluvia"),
    56: ("Llovizna helada", "lluvia"), 57: ("Llovizna helada", "lluvia"),
    61: ("Lluvia débil", "lluvia"), 63: ("Lluvia", "lluvia"), 65: ("Lluvia fuerte", "lluvia"),
    66: ("Lluvia helada", "lluvia"), 67: ("Lluvia helada", "lluvia"),
    71: ("Nieve débil", "nieve"), 73: ("Nieve", "nieve"), 75: ("Nieve fuerte", "nieve"), 77: ("Granizo fino", "nieve"),
    80: ("Chubascos", "lluvia"), 81: ("Chubascos", "lluvia"), 82: ("Chubascos fuertes", "lluvia"),
    85: ("Chubascos de nieve", "nieve"), 86: ("Chubascos de nieve", "nieve"),
    95: ("Tormenta", "tormenta"), 96: ("Tormenta con granizo", "tormenta"), 99: ("Tormenta con granizo", "tormenta"),
}
DIAS = ["lun", "mar", "mié", "jue", "vie", "sáb", "dom"]


def _wmo(codigo: Any) -> tuple[str, str]:
    try:
        return WMO.get(int(codigo), ("—", "nube"))
    except (TypeError, ValueError):
        return ("—", "nube")


# --- Fuentes --------------------------------------------------------------------

async def _tiempo(cliente: httpx.AsyncClient, cfg: dict[str, Any]) -> dict[str, Any]:
    j = json.loads(await _get(
        cliente, "https://api.open-meteo.com/v1/forecast",
        latitude=cfg["lat"], longitude=cfg["lon"], timezone="auto", forecast_days=7,
        current="temperature_2m,apparent_temperature,relative_humidity_2m,weather_code,wind_speed_10m,precipitation",
        daily="weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max",
    ))
    c, d = j["current"], j["daily"]
    texto, icono = _wmo(c.get("weather_code"))
    dias = []
    for i, fecha in enumerate(d["time"]):
        t, ic = _wmo(d["weather_code"][i])
        dia = datetime.fromisoformat(fecha)
        dias.append({
            "nombre": "hoy" if i == 0 else DIAS[dia.weekday()],
            "fecha": dia.strftime("%d/%m"),
            "texto": t, "icono": ic,
            "max": round(d["temperature_2m_max"][i]),
            "min": round(d["temperature_2m_min"][i]),
            "lluvia": d["precipitation_probability_max"][i],
        })
    return {
        "temp": round(c["temperature_2m"]),
        "sensacion": round(c["apparent_temperature"]),
        "humedad": c.get("relative_humidity_2m"),
        "viento": round(c.get("wind_speed_10m") or 0),
        "texto": texto, "icono": icono,
        "dias": dias,
    }


async def _sismos(cliente: httpx.AsyncClient, cfg: dict[str, Any]) -> list[dict[str, Any]]:
    desde = (datetime.now(timezone.utc) - timedelta(days=int(cfg["dias_sismos"]))).strftime("%Y-%m-%dT%H:%M:%S")
    crudo = await _get(
        cliente, "https://www.seismicportal.eu/fdsnws/event/1/query",
        format="json", lat=cfg["lat"], lon=cfg["lon"],
        maxradius=round(float(cfg["radio_km"]) / 111.19, 3),   # grados de arco
        starttime=desde, orderby="time", limit=100,
    )
    if not crudo.strip():                 # FDSN responde vacío (204) si no hay eventos
        return []
    j = json.loads(crudo)
    salida = []
    for f in j.get("features", []):
        p = f.get("properties", {})
        try:
            lat, lon, mag = float(p["lat"]), float(p["lon"]), float(p["mag"])
            ts = datetime.fromisoformat(p["time"].replace("Z", "+00:00")).timestamp()
        except (KeyError, TypeError, ValueError):
            continue
        salida.append({
            "ts": int(ts),
            "mag": round(mag, 1),
            "tipo_mag": p.get("magtype", ""),
            "lugar": (p.get("flynn_region") or "").title(),
            "prof": round(float(p.get("depth") or 0)),
            "km": round(distancia_km(cfg["lat"], cfg["lon"], lat, lon)),
            "url": f"https://www.seismicportal.eu/eventdetails.html?unid={quote_plus(str(p.get('unid', '')))}",
        })
    return salida


async def _noticias(cliente: httpx.AsyncClient, cfg: dict[str, Any]) -> list[dict[str, Any]]:
    fuentes = cfg["noticias"] or [
        f"https://news.google.com/rss/search?q={quote_plus(cfg['nombre'])}&hl=es&gl=ES&ceid=ES:es"
    ]
    vistos, salida = set(), []
    for url in fuentes:
        raiz = XML.fromstring(await _get(cliente, url))
        for item in raiz.iter("item"):
            titulo = (item.findtext("title") or "").strip()
            enlace = _enlace_seguro(item.findtext("link"))
            if not titulo or not enlace:
                continue
            fuente_el = item.find("source")
            fuente = (fuente_el.text or "").strip() if fuente_el is not None else urlsplit(enlace).hostname or ""
            # Google News añade " - Medio" al titular; ya lo mostramos aparte.
            if fuente and titulo.endswith(f" - {fuente}"):
                titulo = titulo[: -len(fuente) - 3]
            clave = titulo.casefold()
            if clave in vistos:
                continue
            vistos.add(clave)
            try:
                ts = int(parsedate_to_datetime(item.findtext("pubDate") or "").timestamp())
            except (TypeError, ValueError):
                ts = None
            salida.append({"titulo": titulo[:220], "url": enlace, "fuente": fuente[:60], "ts": ts})
    salida.sort(key=lambda n: n["ts"] or 0, reverse=True)
    return salida[: int(cfg["max_noticias"])]


FUENTES = {"tiempo": _tiempo, "sismos": _sismos, "noticias": _noticias}


async def refrescar(cliente: httpx.AsyncClient | None = None) -> None:
    """Consulta las tres fuentes en paralelo. Cada una falla por su cuenta."""
    cfg = config()
    propio = cliente is None
    cliente = cliente or httpx.AsyncClient(
        timeout=TIMEOUT, follow_redirects=True, headers={"User-Agent": USER_AGENT}
    )
    try:
        resultados = await asyncio.gather(
            *(f(cliente, cfg) for f in FUENTES.values()), return_exceptions=True
        )
    finally:
        if propio:
            await cliente.aclose()
    ahora = int(time.time())
    for nombre, r in zip(FUENTES, resultados):
        if isinstance(r, BaseException):
            # Se conserva el último dato bueno; el error se enseña junto a su hora.
            _estado[nombre]["error"] = type(r).__name__
            log.warning("Entorno/%s: %s", nombre, r)
        else:
            _estado[nombre].update(datos=r, ts=ahora, error=None)


async def actualizador() -> None:
    while True:
        try:
            await refrescar()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - el bucle no puede morir
            log.warning("Fallo al refrescar el entorno: %s", exc)
        await asyncio.sleep(CADA)
