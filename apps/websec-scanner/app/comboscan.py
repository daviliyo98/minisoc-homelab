"""
comboscan — Acción ACTIVA unificada.

Una sola acción que, sobre un objetivo autorizado:
  0. Incorpora lo ya encontrado en el último análisis PASIVO del objetivo.
  1. Recon web activo-ligero (ficheros sensibles, security.txt, WordPress).
  2. TLS a fondo (testssl.sh), si está disponible.
  3. Nuclei (CVE/misconfig/exposure), si ACTIVE_SCAN_ENABLED=1.
  4. OWASP ZAP (spider+pasivo, o inyección si se pide), si ZAP_ENABLED=1.

Fusiona todos los hallazgos y los deduplica por identidad (el mismo problema
detectado por varias fuentes se queda una sola vez, con el mayor CVSS). Así el
informe activo es UN documento profesional completo, sin repeticiones.
"""
from __future__ import annotations

import socket
from urllib.parse import urlparse

from . import activescan, reconweb, severity, store, tlsdeep, zapscan


def _origen(findings: list[dict], origen: str) -> list[dict]:
    for f in findings:
        f.setdefault("origen", origen)
    return findings


def _passive_previo(objetivo: str) -> tuple[list[dict], dict | None]:
    """Hallazgos del último análisis pasivo completo (tipo 'full') del objetivo."""
    try:
        for s in store.list_scans(objetivo=objetivo, tipo="full", limit=8):
            if s.get("status") != "done" or s.get("objetivo") != objetivo:
                continue
            full = store.get_scan(s["id"])
            hs = ((full or {}).get("result") or {}).get("hallazgos") or []
            if hs:
                return [dict(f) for f in hs], s
    except Exception:
        pass
    return [], None


def scan_activo(url: str, *, objetivo: str, con_inyeccion: bool,
                active_enabled: bool, zap_enabled: bool, zap_base: str, zap_api_key: str,
                es_publico, log, cancel) -> dict:
    findings: list[dict] = []
    tecnologia: dict = {}
    resumen_tls = None

    def _log(m):
        if log:
            log(m)

    # 0) Contemplar lo ya encontrado en la pasiva
    previos, meta = _passive_previo(objetivo)
    if previos:
        _log(f"Incorporando {len(previos)} hallazgo(s) del último análisis pasivo ({meta['id'][:8]}).")
        findings += _origen(previos, "pasivo")
    else:
        _log("Sin análisis pasivo previo de este objetivo: ejecuta el pasivo antes para un informe más completo.")

    # 1) Recon web activo-ligero
    _log("Recon web: ficheros sensibles, security.txt y WordPress…")
    r = reconweb.scan(url, log=log)
    if r.get("ok"):
        findings += _origen(r.get("findings", []), "recon-web")
        tecnologia = r.get("tecnologia") or {}
    else:
        _log("Recon web no completó: " + str(r.get("error", "")))

    # 2) TLS a fondo (testssl.sh)
    if tlsdeep.disponible():
        host = urlparse(url).hostname or ""
        port = urlparse(url).port or 443
        try:
            ip = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
            _log(f"TLS a fondo (testssl.sh) contra {host}:{port}; suele tardar unos minutos…")
            t = tlsdeep.scan_tls(host, ip, port, cancel=cancel)
            if t.get("ok"):
                findings += _origen(t.get("findings", []), "tls")
                resumen_tls = t.get("resumen_tls")
            else:
                _log("TLS a fondo: " + str(t.get("error", "")))
        except OSError:
            _log("TLS a fondo omitido: no se pudo resolver el objetivo a IPv4.")
    else:
        _log("testssl.sh no disponible en el contenedor; TLS a fondo omitido.")

    # 3) Nuclei
    if active_enabled:
        _log("Nuclei: plantillas CVE / misconfig / exposure…")
        n = activescan.scan_activo(url, timeout_total=420.0, cancel=cancel)
        if n.get("ok"):
            findings += _origen(n.get("findings", []), "nuclei")
        else:
            _log("Nuclei: " + str(n.get("error", "")))
    else:
        _log("Nuclei desactivado (ACTIVE_SCAN_ENABLED=0); omitido.")

    # 4) OWASP ZAP
    if zap_enabled:
        modo = "activo (inyección SQLi/XSS…)" if con_inyeccion else "spider + análisis pasivo"
        _log(f"OWASP ZAP {modo}…")
        z = zapscan.scan_zap(
            url, activo=con_inyeccion, base=zap_base, api_key=zap_api_key,
            timeout_total=(1200.0 if con_inyeccion else 600.0),
            es_publico=es_publico, log=log)
        if z.get("ok"):
            findings += _origen(z.get("findings", []), "zap")
        else:
            _log("ZAP: " + str(z.get("error", "")))
    else:
        _log("ZAP desactivado (ZAP_ENABLED=0); omitido.")

    # Deduplicado: un mismo problema detectado por varias fuentes se queda una vez
    # (el de mayor CVSS). Enriquecemos antes para tener id/servicio/puntuación.
    severity.enrich(findings)
    unicos: dict[str, dict] = {}
    for f in findings:
        k = severity.identidad(f)
        cur = unicos.get(k)
        if cur is None:
            unicos[k] = f
        elif (f.get("cvss_score") or 0.0) > (cur.get("cvss_score") or 0.0):
            f.setdefault("origen", cur.get("origen"))
            unicos[k] = f

    return {"ok": True, "objetivo": objetivo, "findings": list(unicos.values()),
            "tecnologia": tecnologia, "resumen_tls": resumen_tls}
