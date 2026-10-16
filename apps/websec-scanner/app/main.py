"""
websec-scanner — Analizador de postura de seguridad web (MINISOC).

Pasivo por defecto: solo observa lo que el servidor expone públicamente. Los
módulos activos (Nuclei, ZAP, testssl.sh) van tras varios candados.
Requiere una clave de API (ver auth.py para roles).

Documentación interactiva en /docs una vez arrancado.
"""
from __future__ import annotations

import asyncio
import os
import socket
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import dns.resolver
import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field, field_validator

from . import activescan, checks, comboscan, jobs, monitor, reconweb, report, scanners, store, tarifas, tlsdeep, zapscan
from .auth import Ident, audit, require

# La interfaz web se carga una vez al arrancar (el contenedor es de solo lectura)
_INDEX = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")

# El modo activo (Nuclei) está DESACTIVADO salvo que se active explícitamente.
ACTIVE_ENABLED = os.environ.get("ACTIVE_SCAN_ENABLED", "") == "1"
# Integración con OWASP ZAP (contenedor aparte). Desactivada salvo que se pida.
ZAP_ENABLED = os.environ.get("ZAP_ENABLED", "") == "1"
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")
ZAP_BASE = os.environ.get("ZAP_BASE", "http://zap:8080")
# Si es 1, los escaneos activos solo se permiten contra dominios verificados por DNS.
REQUIRE_VERIFIED = os.environ.get("REQUIRE_VERIFIED_DOMAIN", "") == "1"
# Token opcional para /metrics (Authorization: Bearer ...). Vacío = abierto en la LAN.
METRICS_TOKEN = os.environ.get("METRICS_TOKEN", "")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    store.init()
    monitor.start()
    yield
    monitor.stop()


app = FastAPI(
    title="MINISOC websec-scanner",
    description="Analizador de postura de seguridad web: pasivo por defecto, activo bajo autorización.",
    version="2.0.0",
    lifespan=lifespan,
)


def _http(e: scanners.ScanError) -> HTTPException:
    return HTTPException(e.status, e.mensaje)


class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validar(cls, v: str) -> str:
        try:
            return scanners.normalizar_url(v.strip())
        except scanners.ScanError as e:
            raise ValueError(e.mensaje)


class DomainRequest(BaseModel):
    domain: str


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    """Interfaz web: formulario para lanzar escaneos y ver el resultado."""
    return _INDEX


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/whoami")
def whoami(ident: Ident = Depends(require("pasivo"))) -> dict:
    """Nombre y rol de la clave usada, y qué módulos están habilitados en el servidor."""
    return {"usuario": ident.nombre, "rol": ident.rol,
            "modulos": {"activo": ACTIVE_ENABLED, "zap": ZAP_ENABLED, "tls_profundo": tlsdeep.disponible(),
                        "verificacion_obligatoria": REQUIRE_VERIFIED},
            "monitor": monitor.estado()}


# --------------------------------------------------------------------------- #
#  Escaneos pasivos (síncronos, se guardan en el historial)
# --------------------------------------------------------------------------- #
async def _ejecutar(request: Request, ident: Ident, tipo: str, objetivo: str, corrutina) -> dict:
    sid = store.new_scan(tipo, objetivo, usuario=ident.nombre)
    try:
        res = await corrutina
    except scanners.ScanError as e:
        store.fail_scan(sid, e.mensaje)
        audit(request, ident, f"scan-{tipo}", objetivo, f"error {e.status}")
        raise _http(e)
    except Exception as e:
        store.fail_scan(sid, f"{type(e).__name__}: {e}")
        raise
    res["scan_id"] = sid
    tarifas.aplicar(res, store.previous_scan(sid))
    store.finish_scan(sid, res)
    audit(request, ident, f"scan-{tipo}", objetivo, "ok")
    return res


def _hilo(fn, *args):
    return asyncio.to_thread(fn, *args)


@app.post("/scan")
async def scan(req: ScanRequest, request: Request, ident: Ident = Depends(require("pasivo"))) -> dict:
    """Postura de seguridad pública de una URL: cabeceras, TLS, CAA, security.txt, contenido mixto, SRI, CORS."""
    return await _ejecutar(request, ident, "web", req.url, scanners.run_web(req.url))


@app.post("/scan-mail")
async def scan_mail(req: DomainRequest, request: Request, ident: Ident = Depends(require("pasivo"))) -> dict:
    """¿Puede suplantarse este dominio para enviar correo? (SPF/DKIM/DMARC/MTA-STS/TLS-RPT/BIMI)."""
    dom = scanners.dominio_de(req.domain)
    return await _ejecutar(request, ident, "correo", dom, _hilo(scanners.run_mail, dom))


@app.post("/scan-dns")
async def scan_dns(req: DomainRequest, request: Request, ident: Ident = Depends(require("pasivo"))) -> dict:
    """Reconocimiento DNS pasivo (A/AAAA/MX/NS/SOA/TXT/CAA) y postura de infraestructura."""
    dom = scanners.dominio_de(req.domain)
    return await _ejecutar(request, ident, "dns", dom, _hilo(scanners.run_dns, dom))


@app.post("/scan-recon")
async def scan_recon(req: DomainRequest, request: Request, ident: Ident = Depends(require("pasivo"))) -> dict:
    """Superficie expuesta: subdominios (Certificate Transparency), takeover y puertos/CVEs (Shodan InternetDB)."""
    dom = scanners.dominio_de(req.domain)
    return await _ejecutar(request, ident, "recon", dom, _hilo(scanners.run_recon, dom))


class FullScanRequest(ScanRequest):
    domain: str | None = None


@app.post("/scan-full")
async def scan_full(req: FullScanRequest, request: Request, ident: Ident = Depends(require("pasivo"))) -> dict:
    """Web + correo + DNS en paralelo, con puntuación global. `domain` es opcional (por defecto, el de la URL)."""
    dom = scanners.dominio_de(req.domain or req.url)
    return await _ejecutar(request, ident, "full", dom, scanners.run_full(req.url, req.domain))


# --------------------------------------------------------------------------- #
#  Escaneos activos en segundo plano (Nuclei, ZAP, testssl.sh)
# --------------------------------------------------------------------------- #
class ActiveScanRequest(ScanRequest):
    autorizo: bool = False


class ActiveFullRequest(ActiveScanRequest):
    # Si True, ZAP hace inyección (SQLi/XSS…); requiere ACTIVE_SCAN_ENABLED=1.
    inyeccion: bool = False


class ZapScanRequest(ActiveScanRequest):
    """`activo=True` añade el escaneo de inyección (intrusivo)."""
    activo: bool = False


def _dominio_verificado(host: str) -> bool:
    host = host.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in store.verified_domains())


def _candados(req: ActiveScanRequest, request: Request, ident: Ident, accion: str) -> str:
    """Comprobaciones comunes de los escaneos activos. Devuelve el host validado."""
    if not req.autorizo:
        raise HTTPException(400, "El escaneo requiere confirmar la autorización (autorizo=true).")
    host = urlparse(req.url).hostname or ""
    if not checks.es_publico(host):
        raise HTTPException(400, "Objetivo no permitido: resuelve a una dirección interna o reservada.")
    if REQUIRE_VERIFIED and not _dominio_verificado(host):
        audit(request, ident, accion, req.url, "dominio no verificado")
        raise HTTPException(403, f"{host} no pertenece a ningún dominio verificado. Verifícalo antes en POST /verify.")
    return host


@app.post("/scan-active")
def scan_active(req: ActiveScanRequest, request: Request, ident: Ident = Depends(require("activo"))) -> dict:
    """Escaneo ACTIVO con Nuclei en segundo plano. Devuelve un ticket (job_id).

    Candados: ACTIVE_SCAN_ENABLED=1 · rol 'activo' · autorizo=true · anti-SSRF ·
    dominio verificado (si REQUIRE_VERIFIED_DOMAIN=1). Estado en GET /scan-status/{job_id}.
    """
    if not ACTIVE_ENABLED:
        raise HTTPException(403, "El modo activo está desactivado. Actívalo con ACTIVE_SCAN_ENABLED=1 en el servidor.")
    _candados(req, request, ident, "scan-active")
    url = req.url

    def trabajo(sid: str, cancel: threading.Event) -> dict:
        jobs.log(sid, "Nuclei: lanzando plantillas (cve, misconfig, exposure…)")
        return activescan.scan_activo(url, timeout_total=420.0, cancel=cancel)

    sid = jobs.lanzar("nuclei", url, ident.nombre, trabajo, motor="nuclei",
                      aviso="Escaneo ACTIVO con Nuclei (sin plantillas destructivas). Ejecútelo SOLO "
                            "con autorización explícita y por escrito del titular del sistema.")
    audit(request, ident, "scan-active", url, f"job {sid}")
    return {"job_id": sid, "status": "queued", "objetivo": url}


def _zap_parar() -> None:
    try:
        with httpx.Client(timeout=5) as c:
            for comp in ("spider", "ascan"):
                c.get(f"{ZAP_BASE}/JSON/{comp}/action/stopAllScans/", params={"apikey": ZAP_API_KEY})
    except Exception:
        pass


@app.post("/scan-zap")
def scan_zap(req: ZapScanRequest, request: Request, ident: Ident = Depends(require("activo"))) -> dict:
    """Escaneo con OWASP ZAP en segundo plano (spider + pasivo; `activo=true` añade inyección).

    Candados: ZAP_ENABLED=1 · rol 'activo' · autorizo=true · anti-SSRF · dominio verificado
    (si se exige). `activo=true` requiere además ACTIVE_SCAN_ENABLED=1.
    """
    if not ZAP_ENABLED:
        raise HTTPException(403, "La integración con ZAP está desactivada. Actívala con ZAP_ENABLED=1 y arranca el contenedor 'zap'.")
    if req.activo and not ACTIVE_ENABLED:
        raise HTTPException(403, "El escaneo ACTIVO de ZAP (inyección) requiere ACTIVE_SCAN_ENABLED=1 en el servidor.")
    _candados(req, request, ident, "scan-zap")
    url, activo = req.url, req.activo
    modo = "zap-activo" if activo else "zap-pasivo"

    def trabajo(sid: str, cancel: threading.Event) -> dict:
        try:
            return zapscan.scan_zap(
                url, activo=activo, base=ZAP_BASE, api_key=ZAP_API_KEY,
                # Sitios reales tardan: 10 min pasivo / 20 min activo.
                timeout_total=(1200.0 if activo else 600.0), es_publico=checks.es_publico,
                log=lambda m: jobs.log(sid, m),
            )
        except jobs.CanceladoPorUsuario:
            _zap_parar()
            raise

    if activo:
        aviso = ("Escaneo ACTIVO con OWASP ZAP: inyecta cargas (SQLi, XSS, etc.) sobre los "
                 "parámetros descubiertos. Es INTRUSIVO. Ejecútelo SOLO con autorización "
                 "explícita y por escrito del titular del sistema.")
    else:
        aviso = ("Escaneo con OWASP ZAP (spider + análisis pasivo): rastrea el sitio y analiza "
                 "las respuestas sin inyectar cargas. Escanee solo sistemas propios o autorizados.")
    sid = jobs.lanzar(modo, url, ident.nombre, trabajo, motor="zap", aviso=aviso)
    audit(request, ident, "scan-zap", url, f"job {sid} {modo}")
    return {"job_id": sid, "status": "queued", "objetivo": url, "modo": modo}


@app.post("/scan-webrecon")
def scan_webrecon(req: ActiveScanRequest, request: Request, ident: Ident = Depends(require("activo"))) -> dict:
    """Reconocimiento web ACTIVO-LIGERO (solo lectura: GET/HEAD a rutas del sitio).

    Detecta ficheros sensibles (.git/.env/backups), security.txt y, si hay
    WordPress, versión/plugins, enumeración de usuarios, XML-RPC y wp-login.
    Candados: rol 'activo' · autorizo=true · anti-SSRF · dominio verificado (si se exige).
    No inyecta cargas. Estado en GET /scan-status/{job_id}.
    """
    _candados(req, request, ident, "scan-webrecon")
    url = req.url

    def trabajo(sid: str, cancel: threading.Event) -> dict:
        jobs.log(sid, "Reconocimiento web activo-ligero: ficheros, security.txt y WordPress")
        return reconweb.scan(url, log=lambda m: jobs.log(sid, m))

    sid = jobs.lanzar("webrecon", url, ident.nombre, trabajo, motor="webrecon",
                      aviso="Reconocimiento web activo-ligero (solo lectura: GET/HEAD a rutas del sitio). "
                            "Ejecútelo SOLO sobre sistemas propios o con autorización por escrito.")
    audit(request, ident, "scan-webrecon", url, f"job {sid}")
    return {"job_id": sid, "status": "queued", "objetivo": url}


@app.post("/scan-activo")
def scan_activo_combo(req: ActiveFullRequest, request: Request, ident: Ident = Depends(require("activo"))) -> dict:
    """Análisis ACTIVO unificado en una sola acción (en segundo plano).

    Contempla el último análisis pasivo del objetivo y añade recon web + TLS a
    fondo + Nuclei (si está habilitado) + ZAP (si está habilitado), fusionando y
    deduplicando los hallazgos en un único informe profesional.
    Candados: rol 'activo' · autorizo=true · anti-SSRF · dominio verificado (si se exige).
    `inyeccion=true` (ZAP activo) requiere además ACTIVE_SCAN_ENABLED=1.
    """
    _candados(req, request, ident, "scan-activo")
    if req.inyeccion and not ACTIVE_ENABLED:
        raise HTTPException(403, "La inyección (ZAP activo) requiere ACTIVE_SCAN_ENABLED=1 en el servidor.")
    url = req.url
    dom = scanners.dominio_de(url)

    def trabajo(sid: str, cancel: threading.Event) -> dict:
        jobs.log(sid, "Análisis ACTIVO unificado: pasivo previo + recon web + TLS + Nuclei + ZAP")
        return comboscan.scan_activo(
            url, objetivo=dom, con_inyeccion=req.inyeccion,
            active_enabled=ACTIVE_ENABLED, zap_enabled=ZAP_ENABLED,
            zap_base=ZAP_BASE, zap_api_key=ZAP_API_KEY, es_publico=checks.es_publico,
            log=lambda m: jobs.log(sid, m), cancel=cancel)

    motores = ["recon web", "TLS"] + (["Nuclei"] if ACTIVE_ENABLED else []) + (["ZAP"] if ZAP_ENABLED else [])
    sid = jobs.lanzar("activo", url, ident.nombre, trabajo, motor="combo",
                      aviso="Análisis ACTIVO: envía peticiones reales al objetivo (" + ", ".join(motores) +
                            "). Ejecútelo SOLO sobre sistemas propios o con autorización por escrito.")
    audit(request, ident, "scan-activo", url, f"job {sid}")
    return {"job_id": sid, "status": "queued", "objetivo": url}


@app.post("/scan-tls")
def scan_tls(req: ActiveScanRequest, request: Request, ident: Ident = Depends(require("activo"))) -> dict:
    """Análisis TLS a fondo con testssl.sh (protocolos, cifrados, cadena, Heartbleed, ROBOT…), en segundo plano."""
    if not tlsdeep.disponible():
        raise HTTPException(503, "testssl.sh no está instalado en el contenedor.")
    host = _candados(req, request, ident, "scan-tls")
    port = urlparse(req.url).port or 443
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except OSError:
        raise HTTPException(400, f"No se pudo resolver {host} a una IPv4.")
    objetivo = f"{host}:{port}"

    def trabajo(sid: str, cancel: threading.Event) -> dict:
        jobs.log(sid, f"testssl.sh contra {objetivo} ({ip}); suele tardar 3-8 min en la Pi…")
        return tlsdeep.scan_tls(host, ip, port, cancel=cancel)

    sid = jobs.lanzar("tls", objetivo, ident.nombre, trabajo, motor="testssl",
                      aviso="Análisis TLS con testssl.sh: realiza cientos de handshakes, algunos con paquetes "
                            "anómalos para detectar vulnerabilidades. Solo sistemas propios o autorizados.")
    audit(request, ident, "scan-tls", objetivo, f"job {sid}")
    return {"job_id": sid, "status": "queued", "objetivo": objetivo}


@app.get("/scan-status/{job_id}")
def scan_status(job_id: str, ident: Ident = Depends(require("pasivo"))) -> dict:
    """Estado/resultado de un trabajo en segundo plano (compatible con la UI anterior)."""
    s = store.get_scan(job_id)
    if s is None:
        raise HTTPException(404, "Trabajo no encontrado.")
    estado = {"queued": "running", "cancelled": "error"}.get(s["status"], s["status"])
    out: dict = {"status": estado, "estado_real": s["status"], "objetivo": s["objetivo"]}
    if s["status"] == "queued":
        out["log"] = ["En cola: esperando a que termine otro escaneo activo…"] + (s.get("log") or [])
    elif s.get("log"):
        out["log"] = s["log"]
    if s["status"] == "done":
        out["result"] = s["result"]
    elif s["status"] in ("error", "cancelled"):
        out["error"] = s["error"]
    return out


# --------------------------------------------------------------------------- #
#  Historial, comparación e informes
# --------------------------------------------------------------------------- #
@app.get("/scans")
def scans(objetivo: str | None = None, tipo: str | None = None, asset_id: str | None = None,
          limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
          ident: Ident = Depends(require("pasivo"))) -> list[dict]:
    """Historial de escaneos (sin el resultado completo). Filtros: objetivo (contiene), tipo, asset_id."""
    return store.list_scans(objetivo=objetivo, tipo=tipo, asset_id=asset_id, limit=limit, offset=offset)


def _scan_o_404(sid: str) -> dict:
    s = store.get_scan(sid)
    if s is None:
        raise HTTPException(404, "Escaneo no encontrado.")
    return s


@app.get("/scans/{sid}")
def scan_detalle(sid: str, ident: Ident = Depends(require("pasivo"))) -> dict:
    return _scan_o_404(sid)


@app.delete("/scans/{sid}")
def scan_borrar(sid: str, request: Request, ident: Ident = Depends(require("activo"))) -> dict:
    """Cancela el escaneo si está en cola/en curso; si ya terminó, lo borra del historial."""
    s = _scan_o_404(sid)
    if s["status"] in ("queued", "running"):
        ok = jobs.cancelar(sid)
        audit(request, ident, "cancelar", s["objetivo"], sid)
        return {"cancelado": ok}
    store.delete_scan(sid)
    audit(request, ident, "borrar", s["objetivo"], sid)
    return {"borrado": True}


@app.get("/scans/{sid}/diff")
def scan_diff(sid: str, contra: str | None = None, ident: Ident = Depends(require("pasivo"))) -> dict:
    """Compara con otro escaneo (`contra`) o, por defecto, con el anterior del mismo objetivo y tipo."""
    actual = _scan_o_404(sid)
    anterior = _scan_o_404(contra) if contra else store.previous_scan(sid)
    if anterior is None:
        raise HTTPException(404, "No hay un escaneo anterior con el que comparar.")
    return {"actual": sid, "anterior": anterior["id"], "fecha_anterior": anterior["started"],
            **report.diff(anterior.get("result"), actual.get("result"))}


@app.get("/scans/{sid}/report")
def scan_report(sid: str, format: Literal["html", "md", "json", "sarif"] = "html", precios: bool = False,
                ident: Ident = Depends(require("pasivo"))):
    """Informe descargable. HTML (imprimible a PDF), Markdown, JSON o SARIF 2.1.0.

    `precios=1` añade la estimación de pago por hallazgo (html/md); por defecto no se incluye.
    """
    s = _scan_o_404(sid)
    if s["status"] != "done":
        raise HTTPException(409, f"El escaneo no ha terminado (estado: {s['status']}).")
    previo = store.previous_scan(sid)
    cambios = report.diff(previo["result"], s["result"]) if previo else None
    nombre = f"informe-{scanners.dominio_de(s['objetivo']) or 'objetivo'}-{sid[:8]}"
    if format == "html":
        return HTMLResponse(report.render_html(s, cambios, precios))
    if format == "md":
        cuerpo, mime, ext = report.render_md(s, cambios, precios), "text/markdown; charset=utf-8", "md"
    elif format == "sarif":
        cuerpo, mime, ext = report.render_sarif(s), "application/sarif+json", "sarif"
    else:
        cuerpo, mime, ext = report.render_json(s), "application/json", "json"
    return Response(cuerpo, media_type=mime,
                    headers={"Content-Disposition": f'attachment; filename="{nombre}.{ext}"'})


# --------------------------------------------------------------------------- #
#  Activos monitorizados y alertas
# --------------------------------------------------------------------------- #
class AssetRequest(BaseModel):
    objetivo: str
    tipo: Literal["web", "correo", "dns", "recon", "full"] = "full"
    intervalo_h: float = Field(24.0, ge=1.0, le=24 * 30)


@app.get("/assets")
def assets(ident: Ident = Depends(require("pasivo"))) -> list[dict]:
    """Activos monitorizados, con el resumen de su último escaneo."""
    out = []
    for a in store.list_assets():
        s = store.latest_asset_scan(a["id"])
        r = (s or {}).get("result") or {}
        out.append({**a, "ultimo_scan": (s or {}).get("id"), "puntuacion": r.get("puntuacion"),
                    "cvss_max": r.get("cvss_max")})
    return out


@app.post("/assets")
def asset_crear(req: AssetRequest, request: Request, ident: Ident = Depends(require("admin"))) -> dict:
    """Da de alta (o actualiza) un activo y lo escanea en la próxima vuelta del planificador (≤1 min)."""
    if req.tipo in ("web", "full"):
        try:
            objetivo = scanners.normalizar_url(req.objetivo.strip())
        except scanners.ScanError as e:
            raise _http(e)
        if not checks.es_publico(urlparse(objetivo).hostname or ""):
            raise HTTPException(400, "Objetivo no permitido: resuelve a una dirección interna o reservada.")
    else:
        objetivo = scanners.dominio_de(req.objetivo)
        if "." not in objetivo:
            raise HTTPException(400, "Dominio no válido.")
    a = store.add_asset(req.tipo, objetivo, req.intervalo_h)
    audit(request, ident, "asset-alta", objetivo, a["id"])
    return a


@app.delete("/assets/{aid}")
def asset_borrar(aid: str, request: Request, ident: Ident = Depends(require("admin"))) -> dict:
    a = store.get_asset(aid)
    if not a or not store.delete_asset(aid):
        raise HTTPException(404, "Activo no encontrado.")
    audit(request, ident, "asset-baja", a["objetivo"], aid)
    return {"borrado": True}


@app.post("/assets/{aid}/run")
def asset_run(aid: str, request: Request, ident: Ident = Depends(require("admin"))) -> dict:
    """Fuerza un escaneo inmediato del activo (en segundo plano)."""
    a = store.get_asset(aid)
    if not a:
        raise HTTPException(404, "Activo no encontrado.")
    threading.Thread(target=monitor.escanear_asset, args=(a,), daemon=True).start()
    audit(request, ident, "asset-run", a["objetivo"], aid)
    return {"lanzado": True, "asset": a["objetivo"]}


@app.post("/alerts/test")
def alerts_test(ident: Ident = Depends(require("admin"))) -> dict:
    """Envía una alerta de prueba por los canales configurados (webhook/Telegram)."""
    if not monitor.canales():
        raise HTTPException(400, "No hay canales configurados (ALERT_WEBHOOK_URL o TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID).")
    return monitor.enviar_alerta("Prueba de alertas", [f"Enviada por {ident.nombre} desde websec-scanner."])


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(authorization: str | None = Header(default=None)) -> str:
    """Métricas Prometheus de los activos monitorizados."""
    if METRICS_TOKEN and authorization != f"Bearer {METRICS_TOKEN}":
        raise HTTPException(401, "Token de métricas inválido.")
    return monitor.metrics(jobs.en_curso())


# --------------------------------------------------------------------------- #
#  Auditoría
# --------------------------------------------------------------------------- #
@app.get("/audit")
def audit_log(limit: int = Query(100, ge=1, le=1000), usuario: str | None = None,
              ident: Ident = Depends(require("admin"))) -> list[dict]:
    """Registro de quién escaneó qué y cuándo (incluye intentos con clave inválida)."""
    return store.list_audit(limit, usuario)


# --------------------------------------------------------------------------- #
#  Verificación de propiedad de dominios (para escaneos activos)
# --------------------------------------------------------------------------- #
VERIFY_PREFIX = "minisoc-verify="


@app.post("/verify")
def verify_iniciar(req: DomainRequest, request: Request, ident: Ident = Depends(require("activo"))) -> dict:
    """Genera (o devuelve) el token que el titular debe publicar en DNS para demostrar el control del dominio."""
    dom = scanners.dominio_de(req.domain)
    if "." not in dom:
        raise HTTPException(400, "Dominio no válido.")
    v = store.get_or_create_token(dom)
    audit(request, ident, "verify-token", dom)
    return {"dominio": dom, "verificado": bool(v["verificado"]),
            "registro": {"tipo": "TXT", "nombre": f"_minisoc-verify.{dom}", "valor": VERIFY_PREFIX + v["token"]},
            "instrucciones": f"Publica el TXT y llama a POST /verify/{dom}/check. Cubre también sus subdominios."}


@app.post("/verify/{dominio}/check")
def verify_comprobar(dominio: str, request: Request, ident: Ident = Depends(require("activo"))) -> dict:
    dom = scanners.dominio_de(dominio)
    v = store.get_or_create_token(dom)
    esperado = VERIFY_PREFIX + v["token"]
    try:
        txts = [b"".join(r.strings).decode(errors="replace")
                for r in dns.resolver.resolve(f"_minisoc-verify.{dom}", "TXT", lifetime=6.0)]
    except Exception:
        txts = []
    ok = esperado in txts
    if ok:
        store.mark_verified(dom)
    audit(request, ident, "verify-check", dom, "ok" if ok else "no encontrado")
    return {"dominio": dom, "verificado": ok or bool(v["verificado"]),
            "detalle": "Token encontrado en DNS." if ok else f"No se encontró {esperado} en _minisoc-verify.{dom} (¿propagación DNS?)."}


@app.get("/verify")
def verify_listar(ident: Ident = Depends(require("activo"))) -> list[dict]:
    return [{"dominio": v["dominio"], "verificado": v["verificado"], "creado": v["creado"]}
            for v in store.list_verifications()]
