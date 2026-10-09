"""
websec-scanner — Analizador PASIVO de postura de seguridad web.

Solo observa lo que el servidor expone públicamente. No sondea rutas
ni prueba parámetros. Requiere una clave de API para usarse.

Documentación interactiva en /docs una vez arrancado.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator

from . import checks, mailcheck

# La interfaz web se carga una vez al arrancar (el contenedor es de solo lectura)
_INDEX = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

API_KEY = os.environ.get("API_KEY", "")

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
        host = p.hostname or ""
        # No permitir escanear la red interna ni localhost desde la API
        if host in ("localhost", "127.0.0.1", "0.0.0.0") or host.startswith(
            ("10.", "192.168.", "172.16.", "172.17.", "169.254.")
        ):
            raise ValueError("No se permiten objetivos internos o de loopback.")
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

    try:
        http_res = await checks.check_http(req.url, timeout)
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

    return {
        "objetivo": http_res["url_final"],
        "puntuacion": nota,
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
        "aviso": "Análisis pasivo. Escanee solo sistemas propios o autorizados.",
    }
