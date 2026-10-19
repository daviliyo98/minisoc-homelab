"""Historial de sondas en SQLite: disponibilidad de 24 h y registro de caídas.

Por qué un muestreador en segundo plano y no guardar lo que mide cada visita a la
página: si el dato depende de cuándo abres el portal, una caída de madrugada no
existe. El muestreador sondea cada PORTAL_POLL segundos (60 por defecto) haya o
no alguien mirando, así que la disponibilidad es una muestra regular y honesta.

Solo se guardan dos cosas:
- `sondas`: una fila por servicio y muestreo (para la barra de 24 h).
- `eventos`: una fila cuando un servicio CAMBIA de estado (para "Caído desde").

Si la base de datos no se puede abrir (volumen sin montar, disco lleno), el portal
sigue funcionando sin historial: un fallo del historial no puede tumbar el catálogo.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from . import catalog, health

log = logging.getLogger("portal.historial")

RUTA_DB = Path(os.environ.get("PORTAL_DB", "/data/portal.db"))
INTERVALO = max(15, int(os.environ.get("PORTAL_POLL", "60")))
RETENCION_DIAS = int(os.environ.get("PORTAL_RETENCION_DIAS", "7"))

_con: sqlite3.Connection | None = None
_ultimo_estado: dict[str, bool] = {}


def _abrir() -> sqlite3.Connection | None:
    global _con
    if _con is not None:
        return _con
    try:
        RUTA_DB.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(RUTA_DB, check_same_thread=False, isolation_level=None)
        # WAL: lecturas de la página sin bloquear la escritura del muestreador, y
        # menos escrituras aleatorias en la microSD.
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS sondas (
                ts INTEGER NOT NULL, servicio TEXT NOT NULL,
                ok INTEGER NOT NULL, detalle TEXT, ms INTEGER
            );
            CREATE INDEX IF NOT EXISTS sondas_servicio_ts ON sondas (servicio, ts);
            CREATE TABLE IF NOT EXISTS eventos (
                ts INTEGER NOT NULL, servicio TEXT NOT NULL,
                ok INTEGER NOT NULL, detalle TEXT
            );
            CREATE INDEX IF NOT EXISTS eventos_ts ON eventos (ts);
            """
        )
        _con = con
        # Recupera el último estado conocido para no registrar un "cambio" falso
        # cada vez que se reinicia el contenedor.
        for servicio, ok in con.execute(
            "SELECT servicio, ok FROM eventos e WHERE ts = "
            "(SELECT MAX(ts) FROM eventos WHERE servicio = e.servicio)"
        ):
            _ultimo_estado[servicio] = bool(ok)
        return con
    except (sqlite3.Error, OSError) as exc:
        log.warning("Historial desactivado: no se puede abrir %s (%s)", RUTA_DB, exc)
        return None


def disponible() -> bool:
    return _abrir() is not None


def registrar(estados: dict[str, dict[str, Any]], ahora: int | None = None) -> None:
    """Guarda una muestra por servicio con sonda y un evento si cambió de estado."""
    con = _abrir()
    if con is None:
        return
    ahora = ahora or int(time.time())
    filas, eventos = [], []
    for nombre, e in estados.items():
        if e.get("ok") is None:          # servicio sin sonda: no hay nada que medir
            continue
        ok = bool(e["ok"])
        filas.append((ahora, nombre, int(ok), e.get("detalle"), e.get("ms")))
        previo = _ultimo_estado.get(nombre)
        # La primera muestra de un servicio sano no es un evento ("vuelve a
        # responder" sin haber caído sería ruido). Si la primera ya falla, sí.
        if previo != ok and not (previo is None and ok):
            eventos.append((ahora, nombre, int(ok), e.get("detalle")))
        _ultimo_estado[nombre] = ok
    try:
        with con:
            con.executemany("INSERT INTO sondas VALUES (?, ?, ?, ?, ?)", filas)
            con.executemany("INSERT INTO eventos VALUES (?, ?, ?, ?)", eventos)
    except sqlite3.Error as exc:
        log.warning("No se pudo guardar la muestra: %s", exc)


def purgar(ahora: int | None = None) -> None:
    con = _abrir()
    if con is None:
        return
    limite = (ahora or int(time.time())) - RETENCION_DIAS * 86400
    try:
        with con:
            con.execute("DELETE FROM sondas WHERE ts < ?", (limite,))
            con.execute("DELETE FROM eventos WHERE ts < ?", (limite,))
    except sqlite3.Error as exc:
        log.warning("No se pudo purgar el historial: %s", exc)


def disponibilidad_24h(servicio: str, ahora: int | None = None) -> dict[str, Any]:
    """24 franjas de una hora (la última a la derecha) con el % de sondas correctas.

    Una franja sin muestras vale None: no es lo mismo "no sé" que "estuvo caído".
    """
    vacio = {"franjas": [None] * 24, "porcentaje": None, "muestras": 0, "ms_medio": None}
    con = _abrir()
    if con is None:
        return vacio
    ahora = ahora or int(time.time())
    inicio = ahora - 24 * 3600
    totales, buenas = [0] * 24, [0] * 24
    ms_total = ms_n = 0
    for ts, ok, ms in con.execute(
        "SELECT ts, ok, ms FROM sondas WHERE servicio = ? AND ts > ?", (servicio, inicio)
    ):
        i = min(23, (ts - inicio) // 3600)
        totales[i] += 1
        buenas[i] += ok
        if ms is not None:
            ms_total += ms
            ms_n += 1
    n = sum(totales)
    if not n:
        return vacio
    return {
        "franjas": [round(100 * b / t) if t else None for b, t in zip(buenas, totales)],
        "porcentaje": round(100 * sum(buenas) / n, 1),
        "muestras": n,
        "ms_medio": round(ms_total / ms_n) if ms_n else None,
    }


def eventos(servicio: str | None = None, limite: int = 50) -> list[dict[str, Any]]:
    con = _abrir()
    if con is None:
        return []
    sql = "SELECT ts, servicio, ok, detalle FROM eventos"
    args: tuple[Any, ...] = ()
    if servicio:
        sql += " WHERE servicio = ?"
        args = (servicio,)
    sql += " ORDER BY ts DESC LIMIT ?"
    return [
        {"ts": ts, "servicio": s, "ok": bool(ok), "detalle": d}
        for ts, s, ok, d in con.execute(sql, (*args, limite))
    ]


def desde(servicio: str) -> int | None:
    """Momento del último cambio de estado: "Caído desde 20:43"."""
    ultimo = eventos(servicio, limite=1)
    return ultimo[0]["ts"] if ultimo else None


# --- Dispositivos vistos: detección de aparatos nuevos en la red -------------------
#
# Un aparato "nuevo" es una MAC que el portal no había visto nunca. La primera vez que
# se ejecuta, la tabla está vacía y todo lo que hay se guarda como LÍNEA BASE sin
# avisar: si no, el primer arranque dispararía una alerta por cada aparato de casa y
# las alertas reales se perderían entre el ruido (fatiga de alertas).

def _tabla_vistos(con: sqlite3.Connection) -> None:
    con.execute(
        "CREATE TABLE IF NOT EXISTS vistos ("
        " mac TEXT PRIMARY KEY, primera INTEGER NOT NULL, ultima INTEGER NOT NULL,"
        " ip TEXT, fabricante TEXT, nombre_red TEXT, aviso INTEGER NOT NULL DEFAULT 0)"
    )


def registrar_vistos(dispositivos: list[dict[str, Any]], ahora: int | None = None) -> list[str]:
    """Guarda los aparatos vistos y devuelve las MAC nuevas que merecen alerta."""
    con = _abrir()
    if con is None:
        return []
    ahora = ahora or int(time.time())
    nuevas: list[str] = []
    try:
        with con:
            _tabla_vistos(con)
            linea_base = con.execute("SELECT COUNT(*) FROM vistos").fetchone()[0] == 0
            conocidas = {m for (m,) in con.execute("SELECT mac FROM vistos")}
            for d in dispositivos:
                mac = d["mac"]
                datos = (d.get("ip"), d.get("fabricante") or "", d.get("nombre_red") or "")
                if mac in conocidas:
                    con.execute(
                        "UPDATE vistos SET ultima = ?, ip = COALESCE(?, ip),"
                        " fabricante = COALESCE(NULLIF(?, ''), fabricante),"
                        " nombre_red = COALESCE(NULLIF(?, ''), nombre_red) WHERE mac = ?",
                        (ahora, *datos, mac),
                    )
                    continue
                # Avisa solo si no es la línea base y el aparato no está dado de alta.
                aviso = int(not linea_base and not d.get("conocido"))
                con.execute("INSERT INTO vistos VALUES (?, ?, ?, ?, ?, ?, ?)", (mac, ahora, ahora, *datos, aviso))
                if aviso:
                    nuevas.append(mac)
        if nuevas:
            log.warning("Dispositivo nuevo en la red: %s", ", ".join(nuevas))
    except sqlite3.Error as exc:
        log.warning("No se pudo registrar dispositivos vistos: %s", exc)
    return nuevas


def dispositivos_nuevos(dias: int = 7) -> list[dict[str, Any]]:
    """Alertas de aparatos nuevos de los últimos días, del más reciente al más antiguo."""
    con = _abrir()
    if con is None:
        return []
    try:
        _tabla_vistos(con)
        filas = con.execute(
            "SELECT mac, primera, ultima, ip, fabricante, nombre_red FROM vistos"
            " WHERE aviso = 1 AND primera > ? ORDER BY primera DESC",
            (int(time.time()) - dias * 86400,),
        ).fetchall()
    except sqlite3.Error:
        return []
    return [dict(zip(("mac", "primera", "ultima", "ip", "fabricante", "nombre_red"), f)) for f in filas]


async def muestreador() -> None:
    """Bucle de fondo. Nunca termina por un error: lo registra y sigue."""
    if not disponible():
        return
    vueltas = 0
    while True:
        try:
            servicios = catalog.servicios("tailnet")
            estados = await health.comprobar_todos(servicios)
            registrar(estados)
            vueltas += 1
            if vueltas % 60 == 1:
                purgar()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - el muestreo no puede morir
            log.warning("Fallo en el muestreo: %s", exc)
        await asyncio.sleep(INTERVALO)
