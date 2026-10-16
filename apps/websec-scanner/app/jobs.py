"""
jobs — Trabajos largos en segundo plano (Nuclei, ZAP, testssl.sh).

  • Estado y resultado persistidos en SQLite (sobreviven a un reinicio de la UI
    y quedan en el historial).
  • Límite de concurrencia (JOBS_MAX_CONCURRENT, por defecto 1): el resto
    espera en cola ('queued'). Así nunca corren varios Nuclei/ZAP a la vez y la
    Pi no se queda sin memoria.
  • Cancelación: DELETE /scans/{id} activa un evento que mata el proceso
    (Nuclei/testssl) o corta el bucle de ZAP en el siguiente paso.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Callable

from . import severity, store, tarifas

MAX_CONCURRENT = max(1, int(os.environ.get("JOBS_MAX_CONCURRENT", "1") or 1))
_SEM = threading.BoundedSemaphore(MAX_CONCURRENT)
_CANCEL: dict[str, threading.Event] = {}
_LOCK = threading.Lock()


class CanceladoPorUsuario(BaseException):
    """Hereda de BaseException a propósito: atraviesa los `except Exception` de los
    módulos de escaneo (p. ej. zapscan ignora los errores del callback de log)."""


def en_curso() -> int:
    with _LOCK:
        return len(_CANCEL)


def log(sid: str, msg: str) -> None:
    """Añade una línea con hora al log del trabajo. Corta el trabajo si se ha cancelado."""
    store.append_log(sid, time.strftime("%H:%M:%S") + "  " + msg)
    ev = _CANCEL.get(sid)
    if ev is not None and ev.is_set():
        raise CanceladoPorUsuario()


def lanzar(tipo: str, objetivo: str, usuario: str,
           trabajo: Callable[[str, threading.Event], dict], *, motor: str, aviso: str) -> str:
    """Registra el trabajo, lo encola y devuelve su id.

    `trabajo(sid, cancel)` debe devolver {"ok": bool, "findings": [...], "error"?: str, ...}.
    """
    sid = store.new_scan(tipo, objetivo, status="queued", usuario=usuario)
    ev = threading.Event()
    with _LOCK:
        _CANCEL[sid] = ev

    def _run() -> None:
        try:
            with _SEM:
                if ev.is_set():
                    return
                store.set_status(sid, "running")
                try:
                    res = trabajo(sid, ev)
                except CanceladoPorUsuario:
                    res = {"ok": False, "cancelado": True, "error": "Escaneo cancelado."}
                except Exception as e:
                    res = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                if ev.is_set() or res.get("cancelado"):
                    store.fail_scan(sid, "Cancelado por el usuario.", status="cancelled")
                elif not res.get("ok"):
                    store.fail_scan(sid, res.get("error", "No se pudo ejecutar el escaneo."))
                else:
                    out = resultado(res, objetivo=objetivo, modo=tipo, motor=motor, aviso=aviso, sid=sid)
                    tarifas.aplicar(out, store.previous_scan(sid))
                    store.finish_scan(sid, out)
        finally:
            with _LOCK:
                _CANCEL.pop(sid, None)

    threading.Thread(target=_run, daemon=True, name=f"job-{sid[:8]}").start()
    return sid


def resultado(res: dict, *, objetivo: str, modo: str, motor: str, aviso: str, sid: str) -> dict:
    from .scanners import puntuar
    todos = res["findings"]
    severity.enrich(todos, {"nuclei": "activo", "zap": "zap", "testssl": "tls"}.get(motor, motor))
    todos.sort(key=lambda f: -(f.get("cvss_score") or 0.0))
    out = {
        "scan_id": sid, "objetivo": objetivo, "modo": modo, "motor": motor,
        "puntuacion": puntuar(todos),
        "cvss_max": severity.cvss_max(todos),
        "resumen": severity.resumen(todos),
        "pago_por_hallazgo": severity.pago_por_hallazgo(todos),
        "hallazgos": todos,
        "aviso": aviso,
    }
    if res.get("resumen_tls"):
        out["tls"] = res["resumen_tls"]
    if res.get("tecnologia"):
        out["tecnologia"] = res["tecnologia"]
    return out


def cancelar(sid: str) -> bool:
    """Marca el trabajo como cancelado. True si estaba en cola o en curso."""
    with _LOCK:
        ev = _CANCEL.get(sid)
    if ev is None:
        return False
    ev.set()
    s = store.get_scan(sid)
    if s and s["status"] == "queued":
        store.fail_scan(sid, "Cancelado por el usuario.", status="cancelled")
    return True
