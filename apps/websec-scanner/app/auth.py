"""
auth — Claves de API con roles, límite de peticiones y registro de auditoría.

Claves (variable API_KEYS, separadas por comas):  nombre:rol:clave
    API_KEYS="fran:admin:<hex>,cliente1:pasivo:<hex>,pentest:activo:<hex>"
Roles (cada uno incluye al anterior):
    pasivo  -> escaneos pasivos (web, correo, DNS, recon, full), historial, informes
    activo  -> + Nuclei, ZAP y TLS a fondo (testssl.sh)
    admin   -> + activos monitorizados, auditoría, alertas
Compatibilidad: si existe API_KEY (clave única antigua), equivale a una clave 'admin'.

Cada intento con clave inválida queda en la auditoría y en stdout con el prefijo
AUDIT (formato JSON por línea), listo para que lo recoja CrowdSec/Loki.
"""
from __future__ import annotations

import hmac
import json
import os
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request

from . import store

ROLES = {"pasivo": 1, "activo": 2, "admin": 3}
RATE_LIMIT = int(os.environ.get("RATE_LIMIT_PER_MIN", "60") or 60)


@dataclass(frozen=True)
class Ident:
    nombre: str
    rol: str


def _cargar_claves() -> list[tuple[str, str, str]]:
    claves: list[tuple[str, str, str]] = []
    for item in (os.environ.get("API_KEYS", "") or "").split(","):
        item = item.strip()
        if not item:
            continue
        partes = item.split(":", 2)
        if len(partes) != 3 or partes[1] not in ROLES or len(partes[2]) < 16:
            print(f"[auth] Entrada de API_KEYS ignorada (formato nombre:rol:clave, clave ≥16): {partes[0]!r}",
                  file=sys.stderr)
            continue
        claves.append((partes[0], partes[1], partes[2]))
    legacy = os.environ.get("API_KEY", "")
    if legacy:
        claves.append(("admin", "admin", legacy))
    return claves


_CLAVES = _cargar_claves()
_HITS: dict[str, deque] = defaultdict(deque)
_HITS_LOCK = threading.Lock()


def reload_keys() -> None:
    """Relee las claves del entorno (útil en tests)."""
    global _CLAVES
    _CLAVES = _cargar_claves()


def _identificar(clave: str | None) -> Ident | None:
    if not clave:
        return None
    hallado = None
    # Comparación en tiempo constante, recorriendo SIEMPRE todas las claves.
    for nombre, rol, k in _CLAVES:
        if hmac.compare_digest(clave.encode(), k.encode()):
            hallado = Ident(nombre, rol)
    return hallado


def _limite(nombre: str) -> bool:
    """Ventana deslizante de 60 s por clave. True si se permite la petición."""
    ahora = time.monotonic()
    with _HITS_LOCK:
        q = _HITS[nombre]
        while q and ahora - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return False
        q.append(ahora)
        return True


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def audit(request: Request | None, ident: Ident | None, accion: str,
          objetivo: str | None = None, resultado: str | None = None) -> None:
    ip = client_ip(request) if request is not None else "interno"
    usuario = ident.nombre if ident else None
    try:
        store.audit(usuario, ip, accion, objetivo, resultado)
    except Exception as e:  # la auditoría nunca debe tumbar una petición
        print(f"[auth] No se pudo guardar la auditoría: {e}", file=sys.stderr)
    print("AUDIT " + json.dumps({"ts": int(time.time()), "usuario": usuario, "ip": ip,
                                 "accion": accion, "objetivo": objetivo, "resultado": resultado},
                                ensure_ascii=False), flush=True)


def require(rol: str):
    """Dependencia de FastAPI: exige una clave con al menos el rol indicado."""
    nivel = ROLES[rol]

    def dep(request: Request, x_api_key: str | None = Header(default=None)) -> Ident:
        if not _CLAVES:
            raise HTTPException(500, "El servidor no tiene claves de API configuradas (API_KEY o API_KEYS).")
        ident = _identificar(x_api_key)
        if ident is None:
            audit(request, None, "auth-fallida", request.url.path, "401")
            raise HTTPException(401, "Clave de API inválida o ausente.")
        if ROLES[ident.rol] < nivel:
            audit(request, ident, "permiso-denegado", request.url.path, "403")
            raise HTTPException(403, f"Tu clave ({ident.rol}) no tiene permiso para esta operación (requiere {rol}).")
        if not _limite(ident.nombre):
            raise HTTPException(429, f"Demasiadas peticiones: máximo {RATE_LIMIT} por minuto.")
        return ident

    return dep
