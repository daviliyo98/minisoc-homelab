"""Salud de la Pi: CPU, temperatura, memoria, disco... desde Prometheus.

Son los mismos datos que pinta Grafana (node-exporter -> Prometheus), leídos por la
API HTTP de Prometheus. El portal va en red host, así que llega a 127.0.0.1:9090
aunque Prometheus solo escuche en el loopback.

Igual que con el entorno, se consulta en segundo plano cada minuto y la página solo
lee la caché: si Prometheus está caído, el portal lo dice y sigue funcionando.

Umbrales: los de una Raspberry Pi 4. La temperatura importa especialmente: a partir
de ~80 °C el firmware baja la frecuencia de la CPU (throttling) y todo va más lento.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

import httpx

log = logging.getLogger("portal.salud")

PROMETHEUS = os.environ.get("PROMETHEUS_URL", "http://127.0.0.1:9090").rstrip("/")
CADA = max(30, int(os.environ.get("PORTAL_SALUD_CADA", "60")))
VENTANA = 3600            # la gráfica cubre la última hora
PASO = 60                 # un punto por minuto: 61 puntos por métrica

# Interfaces que no son la red de casa (Docker, Tailscale, loopback).
_RED = 'device!~"lo|veth.*|docker.*|br-.*|tailscale.*"'

# clave, etiqueta, unidad, PromQL, (aviso, crítico), formato
METRICAS: list[dict[str, Any]] = [
    {"clave": "cpu", "nombre": "CPU", "unidad": "%", "decimales": 0,
     "q": '100 * (1 - avg(rate(node_cpu_seconds_total{mode="idle"}[2m])))',
     "umbral": (85, 95), "ayuda": "Uso medio de los 4 núcleos."},
    {"clave": "temp", "nombre": "Temperatura", "unidad": "°C", "decimales": 1,
     "q": "max(node_thermal_zone_temp) or max(node_hwmon_temp_celsius)",
     "umbral": (70, 80), "ayuda": "A partir de 80 °C la Pi reduce la frecuencia (throttling)."},
    {"clave": "ram", "nombre": "Memoria", "unidad": "%", "decimales": 0,
     "q": "100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)",
     "umbral": (85, 95), "ayuda": "Memoria en uso real (sin contar la caché de disco)."},
    {"clave": "swap", "nombre": "Swap", "unidad": "%", "decimales": 0,
     "q": "100 * (1 - node_memory_SwapFree_bytes / node_memory_SwapTotal_bytes)",
     "umbral": (60, 85), "ayuda": "Si sube, falta RAM y el sistema tira del disco."},
    {"clave": "disco", "nombre": "Disco /", "unidad": "%", "decimales": 0,
     "q": '100 * (1 - max(node_filesystem_avail_bytes{mountpoint="/",fstype!="rootfs"})'
          ' / max(node_filesystem_size_bytes{mountpoint="/",fstype!="rootfs"}))',
     "umbral": (85, 95), "ayuda": "Espacio ocupado en el disco del sistema."},
    {"clave": "iowait", "nombre": "Espera de disco", "unidad": "%", "decimales": 0,
     "q": '100 * avg(rate(node_cpu_seconds_total{mode="iowait"}[2m]))',
     "umbral": (20, 50), "ayuda": "Tiempo que la CPU pasa esperando al disco (el «wa» de top)."},
    {"clave": "carga", "nombre": "Carga (1 min)", "unidad": "", "decimales": 2,
     "q": "node_load1",
     "umbral": (4, 8), "ayuda": "Procesos esperando CPU. En 4 núcleos, más de 4 es cola."},
    {"clave": "red", "nombre": "Red (entrada)", "unidad": "Mb/s", "decimales": 1,
     "q": f"8 * sum(rate(node_network_receive_bytes_total{{{_RED}}}[2m])) / 1e6",
     "umbral": None, "ayuda": "Tráfico recibido por la Pi, sin contar Docker ni Tailscale."},
]

_EXTRA = {
    "uptime": "time() - node_boot_time_seconds",
    "ram_total": "node_memory_MemTotal_bytes",
    "disco_libre": 'max(node_filesystem_avail_bytes{mountpoint="/",fstype!="rootfs"})',
}

_estado: dict[str, Any] = {"metricas": [], "extra": {}, "ts": None, "error": None, "alertas": 0}


def estado() -> dict[str, Any]:
    return _estado


async def _consulta(cliente: httpx.AsyncClient, q: str) -> float | None:
    r = await cliente.get(f"{PROMETHEUS}/api/v1/query", params={"query": q})
    r.raise_for_status()
    res = r.json().get("data", {}).get("result") or []
    try:
        return float(res[0]["value"][1]) if res else None
    except (KeyError, IndexError, TypeError, ValueError):
        return None


async def _serie(cliente: httpx.AsyncClient, q: str, ahora: int) -> list[tuple[int, float]]:
    r = await cliente.get(f"{PROMETHEUS}/api/v1/query_range",
                          params={"query": q, "start": ahora - VENTANA, "end": ahora, "step": PASO})
    r.raise_for_status()
    res = r.json().get("data", {}).get("result") or []
    if not res:
        return []
    salida = []
    for ts, v in res[0].get("values", []):
        try:
            valor = float(v)
        except (TypeError, ValueError):
            continue
        if valor == valor:                       # descarta NaN
            salida.append((int(float(ts)), valor))
    return salida


def _nivel(valor: float | None, umbral: tuple[float, float] | None) -> str:
    if valor is None or not umbral:
        return "nd" if valor is None else "ok"
    aviso, critico = umbral
    return "critico" if valor >= critico else ("aviso" if valor >= aviso else "ok")


def chispa(serie: list[tuple[int, float]], ancho: int = 240, alto: int = 48,
           minimo: float | None = 0.0, maximo: float | None = None) -> dict[str, Any] | None:
    """Geometría de una sparkline en SVG (la página la pinta sin JS ni estilos en línea).

    El eje Y empieza en 0 para los porcentajes: una CPU que va del 3 % al 5 % no debe
    parecer un pico. Para la temperatura se ajusta al rango real (minimo=None).
    """
    if len(serie) < 2:
        return None
    t0, t1 = serie[0][0], serie[-1][0]
    valores = [v for _, v in serie]
    lo = min(valores) if minimo is None else min(minimo, min(valores))
    hi = max(valores) if maximo is None else max(maximo, max(valores))
    if minimo is None:                           # rango ajustado: un poco de aire
        margen = max((hi - lo) * 0.15, 0.5)
        lo, hi = lo - margen, hi + margen
    if hi - lo < 1e-9:
        hi = lo + 1
    pad = 3
    def xy(ts: int, v: float) -> tuple[float, float]:
        x = pad + (ts - t0) / max(t1 - t0, 1) * (ancho - 2 * pad)
        y = alto - pad - (v - lo) / (hi - lo) * (alto - 2 * pad)
        return round(x, 1), round(y, 1)
    puntos = [xy(ts, v) for ts, v in serie]
    linea = " ".join(f"{x},{y}" for x, y in puntos)
    area = f"{puntos[0][0]},{alto - pad} {linea} {puntos[-1][0]},{alto - pad}"
    # Zonas de hover: una por punto, con su valor en <title> (tooltip nativo, sin JS).
    paso_x = (ancho - 2 * pad) / max(len(serie) - 1, 1)
    zonas = [{"x": round(x - paso_x / 2, 1), "w": round(paso_x, 1), "ts": ts, "v": v}
             for (x, _), (ts, v) in zip(puntos, serie)]
    return {"ancho": ancho, "alto": alto, "linea": linea, "area": area,
            "ultimo": puntos[-1], "zonas": zonas}


async def refrescar(cliente: httpx.AsyncClient | None = None) -> None:
    ahora = int(time.time())
    propio = cliente is None
    cliente = cliente or httpx.AsyncClient(timeout=httpx.Timeout(6.0, connect=2.0), trust_env=False)
    try:
        actuales = await asyncio.gather(*(_consulta(cliente, m["q"]) for m in METRICAS), return_exceptions=True)
        series = await asyncio.gather(*(_serie(cliente, m["q"], ahora) for m in METRICAS), return_exceptions=True)
        extra = await asyncio.gather(*(_consulta(cliente, q) for q in _EXTRA.values()), return_exceptions=True)
    finally:
        if propio:
            await cliente.aclose()

    fallos = [r for r in (*actuales, *series, *extra) if isinstance(r, BaseException)]
    if fallos and len(fallos) == len(actuales) + len(series) + len(extra):
        # Prometheus entero no responde: se conserva el último dato bueno.
        _estado["error"] = f"{type(fallos[0]).__name__}: {fallos[0]}"[:160]
        log.warning("Prometheus: %s", _estado["error"])
        return

    metricas = []
    for m, actual, serie in zip(METRICAS, actuales, series):
        actual = None if isinstance(actual, BaseException) else actual
        serie = [] if isinstance(serie, BaseException) else serie
        valores = [v for _, v in serie]
        metricas.append({
            **{k: m[k] for k in ("clave", "nombre", "unidad", "decimales", "ayuda", "umbral")},
            "valor": actual,
            "nivel": _nivel(actual, m["umbral"]),
            "min": min(valores) if valores else None,
            "max": max(valores) if valores else None,
            "chispa": chispa(serie, minimo=None if m["clave"] in ("temp", "carga", "red") else 0.0,
                             maximo=100.0 if m["unidad"] == "%" else None),
        })
    _estado.update(
        metricas=metricas,
        extra={k: (None if isinstance(v, BaseException) else v) for k, v in zip(_EXTRA, extra)},
        alertas=sum(1 for m in metricas if m["nivel"] in ("aviso", "critico")),
        ts=ahora,
        error=None,
    )


async def actualizador() -> None:
    while True:
        try:
            await refrescar()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - el bucle no puede morir
            _estado["error"] = f"{type(exc).__name__}: {exc}"[:160]
            log.warning("Fallo al refrescar la salud: %s", exc)
        await asyncio.sleep(CADA)
