"""
websec-scanner — Analizador PASIVO de postura de seguridad web.

Solo observa lo que el servidor expone públicamente. No sondea rutas
ni prueba parámetros. Requiere una clave de API para usarse.

Documentación interactiva en /docs una vez arrancado.
"""
from __future__ import annotations

import os
import threading
import time
import uuid
from urllib.parse import urlparse

from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator

from . import activescan, checks, mailcheck

# La interfaz web se carga una vez al arrancar (el contenedor es de solo lectura)
_INDEX = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

API_KEY = os.environ.get("API_KEY", "")
# El modo activo (Nuclei) está DESACTIVADO salvo que se active explícitamente.
ACTIVE_ENABLED = os.environ.get("ACTIVE_SCAN_ENABLED", "") == "1"

app = FastAPI(
    title="MINISOC websec-scanner",
    description="Analizador pasivo de postura de seguridad web (solo observa lo público).",
    version="1.0.0",
)


class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validar(cls, v: str) -> str:
        if not urlparse(v).scheme:
            v = "https://" + v
        p = urlparse(v)
        if p.scheme not in ("http", "https"):
            raise ValueError("Solo se admiten URLs http/https.")
        if not p.hostname:
            raise ValueError("URL sin host válido.")
        # El bloqueo de objetivos internos/reservados (anti-SSRF) se hace en el
        # endpoint con checks.es_publico(), que da un mensaje claro (400) en vez
        # del error de validación 422.
        return v


def _auth(x_api_key: str | None) -> None:
    if not API_KEY:
        raise HTTPException(500, "El servidor no tiene API_KEY configurada.")
    if x_api_key != API_KEY:
        raise HTTPException(401, "Clave de API inválida o ausente.")


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    """Interfaz web: formulario para lanzar escaneos y ver el resultado."""
    return _INDEX


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


class MailScanRequest(BaseModel):
    domain: str


@app.post("/scan-mail")
def scan_mail(req: MailScanRequest, x_api_key: str | None = Header(default=None)) -> dict:
    """Analiza la postura de seguridad del correo de un dominio (SPF/DKIM/DMARC).

    Responde a: ¿puede suplantarse este dominio para enviar correo en su nombre?
    Endpoint síncrono: dns.resolver es bloqueante y FastAPI lo ejecuta en un hilo.
    """
    _auth(x_api_key)
    return mailcheck.scan(req.domain)


@app.post("/scan")
async def scan(req: ScanRequest, x_api_key: str | None = Header(default=None)) -> dict:
    """Analiza la postura de seguridad pública de una URL.

    Checks: cabeceras HTTP de seguridad, configuración TLS y security.txt.
    """
    _auth(x_api_key)
    timeout = 10.0
    host = urlparse(req.url if urlparse(req.url).scheme else "https://" + req.url).hostname

    # Anti-SSRF: el host debe resolver SOLO a IPs públicas.
    if not checks.es_publico(host or ""):
        raise HTTPException(400, "Objetivo no permitido: resuelve a una dirección interna o reservada.")

    try:
        http_res = await checks.check_http(req.url, timeout)
    except checks.SsrfBloqueado as e:
        raise HTTPException(400, str(e))
    except httpx.ConnectError:
        raise HTTPException(502, "No se pudo conectar con el objetivo: el puerto puede estar cerrado o el host no acepta HTTPS.")
    except httpx.TimeoutException:
        raise HTTPException(504, "El objetivo no respondió a tiempo.")
    except httpx.RequestError as e:
        raise HTTPException(502, f"Error al contactar con el objetivo: {type(e).__name__}")
    tls_res = checks.check_tls(host, timeout) if http_res["https"] else {
        "ok": False, "nota": "Sin HTTPS, no se analiza TLS.", "findings": [{
            "severidad": "alta", "titulo": "El sitio no usa HTTPS",
            "detalle": "El tráfico viaja sin cifrar.",
            "remediacion": "Instalar un certificado y forzar HTTPS."}]}
    sectxt = await checks.check_security_txt(req.url, timeout)
    caa = checks.check_caa(host) if host else {"caa": None, "findings": []}
    redir = await checks.check_http_redirect(req.url, timeout)

    todos = (http_res["findings"] + tls_res.get("findings", [])
             + caa["findings"] + redir["findings"])
    orden = {"alta": 0, "media": 1, "baja": 2}
    todos.sort(key=lambda f: orden.get(f["severidad"], 9))

    # Puntuación simple: 100 menos penalización por hallazgo
    pen = {"alta": 20, "media": 8, "baja": 3}
    nota = max(0, 100 - sum(pen.get(f["severidad"], 0) for f in todos))

    # Resultado concreto de cada comprobación (no solo los hallazgos)
    cab = http_res.get("cabeceras_seguridad", {})
    nombres_cab = {
        "strict-transport-security": "HSTS", "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options", "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy",
    }
    rh = redir.get("redirige_https")
    comprobaciones = [
        {"nombre": "HTTPS", "estado": "ok" if http_res["https"] else "falta",
         "detalle": "activo" if http_res["https"] else "el sitio no cifra"},
        {"nombre": "Redirección HTTP→HTTPS",
         "estado": "ok" if rh else ("aviso" if rh is False else "info"),
         "detalle": "redirige" if rh else ("no redirige" if rh is False else "no comprobable")},
        {"nombre": "TLS", "estado": "ok" if tls_res.get("ok") else "falta",
         "detalle": (f"{tls_res.get('version', '')} · caduca en {tls_res.get('dias_para_caducar', '?')}d") if tls_res.get("ok") else "no disponible"},
    ]
    for h, label in nombres_cab.items():
        comprobaciones.append({"nombre": label, "estado": "ok" if cab.get(h) else "falta",
                               "detalle": "presente" if cab.get(h) else "ausente"})
    comprobaciones.append({"nombre": "CAA", "estado": "ok" if caa.get("caa") else "aviso",
                           "detalle": "presente" if caa.get("caa") else "sin CAA"})
    comprobaciones.append({"nombre": "security.txt", "estado": "ok" if sectxt.get("existe") else "info",
                           "detalle": sectxt.get("ruta", "no publicado") if sectxt.get("existe") else "no publicado"})

    return {
        "objetivo": http_res["url_final"],
        "puntuacion": nota,
        "comprobaciones": comprobaciones,
        "resumen": {
            "altas": sum(1 for f in todos if f["severidad"] == "alta"),
            "medias": sum(1 for f in todos if f["severidad"] == "media"),
            "bajas": sum(1 for f in todos if f["severidad"] == "baja"),
        },
        "tls": {k: v for k, v in tls_res.items() if k != "findings"},
        "security_txt": sectxt,
        "caa": caa.get("caa"),
        "redirige_https": redir.get("redirige_https"),
        "hallazgos": todos,
        "aviso": "Diagnóstico pasivo de la exposición pública de la web. Útil para detectar "
                 "configuraciones ausentes o débiles, pero NO sustituye una auditoría interna "
                 "del servidor ni una prueba de penetración (pentest). "
                 "Escanee solo sistemas propios o autorizados.",
    }


class ActiveScanRequest(ScanRequest):
    """Hereda la validación de URL de ScanRequest (incluido el bloqueo anti-SSRF)."""
    autorizo: bool = False


# --- Trabajos en segundo plano para el escaneo activo (es largo) ---
# El escaneo con Nuclei tarda minutos: no cabe en una petición/respuesta. Se
# lanza en un hilo, se devuelve un ticket, y el cliente consulta el estado.
_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()
_MAX_JOBS = 20


def _run_active_job(job_id: str, url: str) -> None:
    res = activescan.scan_activo(url, timeout_total=420.0)
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return
        if not res.get("ok"):
            job["status"] = "error"
            job["error"] = res.get("error", "No se pudo ejecutar el escaneo activo.")
            return
        todos = res["findings"]
        pen = {"alta": 20, "media": 8, "baja": 3}
        nota = max(0, 100 - sum(pen.get(f["severidad"], 0) for f in todos))
        job["status"] = "done"
        job["result"] = {
            "objetivo": url, "modo": "activo", "motor": "nuclei", "puntuacion": nota,
            "resumen": {
                "altas": sum(1 for f in todos if f["severidad"] == "alta"),
                "medias": sum(1 for f in todos if f["severidad"] == "media"),
                "bajas": sum(1 for f in todos if f["severidad"] == "baja"),
            },
            "hallazgos": todos,
            "aviso": "Escaneo ACTIVO con Nuclei (sin plantillas destructivas). Ejecútelo SOLO "
                     "con autorización explícita y por escrito del titular del sistema.",
        }


@app.post("/scan-active")
def scan_active(req: ActiveScanRequest, x_api_key: str | None = Header(default=None)) -> dict:
    """Lanza un escaneo ACTIVO (Nuclei) en segundo plano y devuelve un ticket.

    Triple candado: 1) ACTIVE_SCAN_ENABLED=1  2) autorizo=true  3) anti-SSRF.
    El resultado se consulta luego en GET /scan-status/{job_id}.
    """
    _auth(x_api_key)
    if not ACTIVE_ENABLED:
        raise HTTPException(403, "El modo activo está desactivado. Actívalo con ACTIVE_SCAN_ENABLED=1 en el servidor.")
    if not req.autorizo:
        raise HTTPException(400, "El escaneo activo requiere confirmar la autorización (autorizo=true).")

    host = urlparse(req.url).hostname or ""
    if not checks.es_publico(host):
        raise HTTPException(400, "Objetivo no permitido: resuelve a una dirección interna o reservada.")

    job_id = uuid.uuid4().hex
    with _JOBS_LOCK:
        # Poda: si hay demasiados trabajos, quitamos el más antiguo.
        if len(_JOBS) >= _MAX_JOBS:
            viejo = min(_JOBS, key=lambda k: _JOBS[k]["started"])
            _JOBS.pop(viejo, None)
        _JOBS[job_id] = {"status": "running", "started": time.time(),
                         "objetivo": req.url, "result": None, "error": None}
    threading.Thread(target=_run_active_job, args=(job_id, req.url), daemon=True).start()
    return {"job_id": job_id, "status": "running", "objetivo": req.url}


@app.get("/scan-status/{job_id}")
def scan_status(job_id: str, x_api_key: str | None = Header(default=None)) -> dict:
    """Consulta el estado/resultado de un escaneo activo en segundo plano."""
    _auth(x_api_key)
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            raise HTTPException(404, "Trabajo no encontrado o caducado.")
        out: dict = {"status": job["status"], "objetivo": job["objetivo"]}
        if job["status"] == "done":
            out["result"] = job["result"]
        elif job["status"] == "error":
            out["error"] = job["error"]
        return out
