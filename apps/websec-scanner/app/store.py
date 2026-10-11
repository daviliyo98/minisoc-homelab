"""
store — Persistencia en SQLite de escaneos, activos monitorizados, auditoría y
verificación de dominios.

El contenedor es de solo lectura: la base de datos vive en un volumen montado
en /data (DB_PATH). Una conexión por operación + WAL: sencillo y seguro entre
los hilos de FastAPI, los trabajos en segundo plano y el planificador.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager

DB_PATH = os.environ.get("DB_PATH", "/data/websec.db")
_LOCK = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id         TEXT PRIMARY KEY,
    tipo       TEXT NOT NULL,          -- web | correo | dns | full | recon | nuclei | zap-pasivo | zap-activo | tls
    objetivo   TEXT NOT NULL,
    status     TEXT NOT NULL,          -- queued | running | done | error | cancelled
    started    REAL NOT NULL,
    finished   REAL,
    puntuacion INTEGER,
    cvss_max   REAL,
    result     TEXT,                   -- JSON completo del resultado
    error      TEXT,
    log        TEXT,                   -- JSON: lista de líneas
    usuario    TEXT,                   -- nombre de la API key que lo lanzó
    asset_id   TEXT                    -- si lo lanzó el monitor
);
CREATE INDEX IF NOT EXISTS ix_scans_obj ON scans(objetivo, tipo, started);
CREATE INDEX IF NOT EXISTS ix_scans_asset ON scans(asset_id, started);

CREATE TABLE IF NOT EXISTS assets (
    id          TEXT PRIMARY KEY,
    tipo        TEXT NOT NULL,         -- web | correo | dns | full
    objetivo    TEXT NOT NULL,
    intervalo_h REAL NOT NULL,
    activo      INTEGER NOT NULL DEFAULT 1,
    creado      REAL NOT NULL,
    ultimo      REAL,
    UNIQUE(tipo, objetivo)
);

CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    usuario  TEXT,
    ip       TEXT,
    accion   TEXT NOT NULL,
    objetivo TEXT,
    resultado TEXT
);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);

CREATE TABLE IF NOT EXISTS verifications (
    dominio     TEXT PRIMARY KEY,
    token       TEXT NOT NULL,
    creado      REAL NOT NULL,
    verificado  REAL
);
"""


@contextmanager
def _conn():
    c = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init() -> None:
    """Crea el esquema y marca como interrumpidos los trabajos de un arranque anterior."""
    d = os.path.dirname(DB_PATH)
    if d:
        os.makedirs(d, exist_ok=True)
    with _LOCK, _conn() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(_SCHEMA)
        c.execute("UPDATE scans SET status='error', error='Interrumpido por un reinicio del servicio.', "
                  "finished=? WHERE status IN ('queued','running')", (time.time(),))


def _row(r: sqlite3.Row | None, full: bool = True) -> dict | None:
    if r is None:
        return None
    d = dict(r)
    for k in ("result", "log"):
        if k in d:
            if full and d[k]:
                d[k] = json.loads(d[k])
            elif not full:
                d.pop(k, None)
    return d


# --------------------------------------------------------------------------- #
#  Escaneos
# --------------------------------------------------------------------------- #
def new_scan(tipo: str, objetivo: str, *, status: str = "running",
             usuario: str | None = None, asset_id: str | None = None,
             scan_id: str | None = None) -> str:
    sid = scan_id or uuid.uuid4().hex
    with _LOCK, _conn() as c:
        c.execute("INSERT INTO scans (id, tipo, objetivo, status, started, usuario, asset_id, log) "
                  "VALUES (?,?,?,?,?,?,?,?)",
                  (sid, tipo, objetivo, status, time.time(), usuario, asset_id, "[]"))
    return sid


def set_status(sid: str, status: str) -> None:
    with _LOCK, _conn() as c:
        c.execute("UPDATE scans SET status=? WHERE id=?", (status, sid))


def finish_scan(sid: str, result: dict) -> None:
    with _LOCK, _conn() as c:
        c.execute("UPDATE scans SET status='done', finished=?, puntuacion=?, cvss_max=?, result=? "
                  "WHERE id=? AND status!='cancelled'",
                  (time.time(), result.get("puntuacion"), result.get("cvss_max"),
                   json.dumps(result, ensure_ascii=False), sid))


def fail_scan(sid: str, error: str, status: str = "error") -> None:
    with _LOCK, _conn() as c:
        c.execute("UPDATE scans SET status=?, finished=?, error=? WHERE id=? AND status!='cancelled'",
                  (status, time.time(), error, sid))


def append_log(sid: str, linea: str, maximo: int = 80) -> None:
    with _LOCK, _conn() as c:
        r = c.execute("SELECT log FROM scans WHERE id=?", (sid,)).fetchone()
        if r is None:
            return
        log = json.loads(r["log"] or "[]")
        log.append(linea)
        c.execute("UPDATE scans SET log=? WHERE id=?", (json.dumps(log[-maximo:], ensure_ascii=False), sid))


def get_scan(sid: str) -> dict | None:
    with _conn() as c:
        return _row(c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone())


def list_scans(*, objetivo: str | None = None, tipo: str | None = None,
               asset_id: str | None = None, limit: int = 50, offset: int = 0) -> list[dict]:
    q, args = "SELECT * FROM scans WHERE 1=1", []
    if objetivo:
        q += " AND objetivo LIKE ?"
        args.append(f"%{objetivo}%")
    if tipo:
        q += " AND tipo=?"
        args.append(tipo)
    if asset_id:
        q += " AND asset_id=?"
        args.append(asset_id)
    q += " ORDER BY started DESC LIMIT ? OFFSET ?"
    args += [limit, offset]
    with _conn() as c:
        return [_row(r, full=False) for r in c.execute(q, args).fetchall()]


def previous_scan(sid: str) -> dict | None:
    """Escaneo terminado anterior del mismo objetivo y tipo (para comparar)."""
    with _conn() as c:
        cur = c.execute("SELECT tipo, objetivo, started FROM scans WHERE id=?", (sid,)).fetchone()
        if cur is None:
            return None
        r = c.execute("SELECT * FROM scans WHERE tipo=? AND objetivo=? AND status='done' AND started<? "
                      "ORDER BY started DESC LIMIT 1",
                      (cur["tipo"], cur["objetivo"], cur["started"])).fetchone()
        return _row(r)


def delete_scan(sid: str) -> bool:
    with _LOCK, _conn() as c:
        return c.execute("DELETE FROM scans WHERE id=?", (sid,)).rowcount > 0


def count_by_status() -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT tipo, status, COUNT(*) AS n FROM scans GROUP BY tipo, status").fetchall()]


# --------------------------------------------------------------------------- #
#  Activos monitorizados
# --------------------------------------------------------------------------- #
def add_asset(tipo: str, objetivo: str, intervalo_h: float) -> dict:
    aid = uuid.uuid4().hex[:12]
    with _LOCK, _conn() as c:
        c.execute("INSERT INTO assets (id, tipo, objetivo, intervalo_h, creado) VALUES (?,?,?,?,?) "
                  "ON CONFLICT(tipo, objetivo) DO UPDATE SET intervalo_h=excluded.intervalo_h, activo=1",
                  (aid, tipo, objetivo, intervalo_h, time.time()))
        return dict(c.execute("SELECT * FROM assets WHERE tipo=? AND objetivo=?", (tipo, objetivo)).fetchone())


def list_assets() -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM assets ORDER BY creado").fetchall()]


def get_asset(aid: str) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
        return dict(r) if r else None


def delete_asset(aid: str) -> bool:
    with _LOCK, _conn() as c:
        return c.execute("DELETE FROM assets WHERE id=?", (aid,)).rowcount > 0


def due_assets(now: float) -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM assets WHERE activo=1 AND (ultimo IS NULL OR ultimo + intervalo_h*3600 <= ?)",
            (now,)).fetchall()]


def touch_asset(aid: str, ts: float) -> None:
    with _LOCK, _conn() as c:
        c.execute("UPDATE assets SET ultimo=? WHERE id=?", (ts, aid))


def latest_asset_scan(aid: str) -> dict | None:
    with _conn() as c:
        return _row(c.execute("SELECT * FROM scans WHERE asset_id=? AND status='done' "
                              "ORDER BY started DESC LIMIT 1", (aid,)).fetchone())


# --------------------------------------------------------------------------- #
#  Auditoría
# --------------------------------------------------------------------------- #
def audit(usuario: str | None, ip: str | None, accion: str,
          objetivo: str | None = None, resultado: str | None = None) -> None:
    with _LOCK, _conn() as c:
        c.execute("INSERT INTO audit (ts, usuario, ip, accion, objetivo, resultado) VALUES (?,?,?,?,?,?)",
                  (time.time(), usuario, ip, accion, objetivo, resultado))


def list_audit(limit: int = 100, usuario: str | None = None) -> list[dict]:
    q, args = "SELECT * FROM audit", []
    if usuario:
        q += " WHERE usuario=?"
        args.append(usuario)
    q += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


# --------------------------------------------------------------------------- #
#  Verificación de dominios
# --------------------------------------------------------------------------- #
def get_or_create_token(dominio: str) -> dict:
    with _LOCK, _conn() as c:
        r = c.execute("SELECT * FROM verifications WHERE dominio=?", (dominio,)).fetchone()
        if r is None:
            c.execute("INSERT INTO verifications (dominio, token, creado) VALUES (?,?,?)",
                      (dominio, uuid.uuid4().hex, time.time()))
            r = c.execute("SELECT * FROM verifications WHERE dominio=?", (dominio,)).fetchone()
        return dict(r)


def mark_verified(dominio: str) -> None:
    with _LOCK, _conn() as c:
        c.execute("UPDATE verifications SET verificado=? WHERE dominio=?", (time.time(), dominio))


def list_verifications() -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM verifications ORDER BY dominio").fetchall()]


def verified_domains() -> list[str]:
    with _conn() as c:
        return [r["dominio"] for r in c.execute(
            "SELECT dominio FROM verifications WHERE verificado IS NOT NULL").fetchall()]
