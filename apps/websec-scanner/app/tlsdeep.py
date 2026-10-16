"""
tlsdeep — Análisis TLS a fondo con testssl.sh.

Complementa check_tls (que solo mira versión negociada y caducidad) con:
protocolos ofrecidos, suites de cifrado, cadena y revocación del certificado
y vulnerabilidades conocidas de TLS (Heartbleed, ROBOT, POODLE, BEAST, LUCKY13,
SWEET32, FREAK, LOGJAM, DROWN, Ticketbleed, CCS…).

Hace muchos handshakes (algunos con paquetes deliberadamente anómalos para
detectar vulnerabilidades), así que se trata como escaneo activo: rol 'activo'
y autorización explícita. Tarda varios minutos: va en segundo plano.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading

from .activescan import Cancelado, run_cancelable

TESTSSL = os.environ.get("TESTSSL_PATH", "/opt/testssl/testssl.sh")

# testssl.sh -> severidad del scanner (el tramo lo recalcula severity.enrich)
_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def disponible() -> bool:
    return os.path.isfile(TESTSSL) and shutil.which("bash") is not None


def scan_tls(host: str, ip: str, port: int = 443, *, timeout_total: float = 900.0,
             cancel: threading.Event | None = None) -> dict:
    """Ejecuta testssl.sh contra host:port, conectando a la IP ya validada (anti-rebinding)."""
    if not disponible():
        return {"ok": False, "error": "testssl.sh no está instalado en el contenedor.", "findings": []}

    fd, salida = tempfile.mkstemp(prefix="testssl-", suffix=".json", dir="/tmp")
    os.close(fd)
    os.unlink(salida)  # testssl.sh se niega a sobrescribir un fichero existente
    cmd = [
        "bash", TESTSSL,
        "--quiet", "--color", "0", "--warnings", "off", "--nodns", "min",
        "--ip", ip,                       # conecta SOLO a la IP comprobada como pública
        "-p", "-S", "-U",                 # protocolos, certificado/servidor, vulnerabilidades
        "-s",                             # categorías de cifrado estándar
        "--connect-timeout", "10", "--openssl-timeout", "10",
        "--jsonfile", salida,
        f"{host}:{port}",
    ]
    env = {"HOME": "/tmp", "PATH": "/usr/local/bin:/usr/bin:/bin", "TERM": "dumb"}
    try:
        rc, _out, err = run_cancelable(cmd, timeout=timeout_total, env=env, cancel=cancel)
    except Cancelado:
        return {"ok": False, "cancelado": True, "error": "Escaneo cancelado.", "findings": []}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "testssl.sh superó el tiempo límite.", "findings": []}

    try:
        with open(salida, encoding="utf-8") as fh:
            datos = json.load(fh)
    except Exception:
        tail = " | ".join((err or "").strip().splitlines()[-3:]) or f"código de salida {rc}"
        return {"ok": False, "error": f"testssl.sh no generó resultados: {tail}", "findings": []}
    finally:
        try:
            os.unlink(salida)
        except OSError:
            pass

    # Un escaneo interrumpido NO debe pasar por "sin hallazgos" (ocultaría un fallo como si
    # el objetivo estuviera limpio): si testssl.sh registra un FATAL, es un error.
    fatales = [e.get("finding", "") for e in datos if str(e.get("severity", "")).upper() == "FATAL"]
    if fatales:
        return {"ok": False, "error": "testssl.sh no completó el análisis: " + " | ".join(fatales[:2]), "findings": []}
    return {"ok": True, "motor": "testssl", "findings": agrupar_tls(parse(datos)), "resumen_tls": resumen(datos)}


def _id(e: dict) -> str:
    """Id sin el sufijo de certificado ('cert_keySize <hostCert#1>' -> 'cert_keySize')."""
    return str(e.get("id", "")).split(" <", 1)[0]


def parse(datos: list[dict]) -> list[dict]:
    """Convierte la salida JSON (plana) de testssl.sh en hallazgos del scanner."""
    findings: list[dict] = []
    vistos: set[str] = set()
    for e in datos:
        sev = _SEV.get(str(e.get("severity", "")).upper())
        tid = _id(e)
        if not sev or tid in vistos:
            continue
        vistos.add(tid)
        cve = (e.get("cve") or "").split()
        f = {
            "severidad": sev,
            "titulo": f"TLS: {tid}",
            "detalle": e.get("finding") or "",
            "remediacion": _remediacion(tid),
            "plantilla": tid,
        }
        if cve:
            f["cve"] = cve
        if e.get("cwe"):
            f["cwe"] = e["cwe"]
        findings.append(f)
    return findings


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Causas raíz: muchos identificadores de testssl son síntomas del MISMO problema de
# configuración. Los agrupamos para no inflar el informe (ni la factura) con 7-8
# "hallazgos" que en realidad son 2.
_PROTO_OBSOLETO = {"sslv2", "sslv3", "tls1", "tls1_1", "beast", "beast_cbc_tls1", "poodle_ssl", "poodle"}
_CIFRADO_DEBIL = {"sweet32", "lucky13", "rc4", "3des", "freak", "logjam", "drown"}
_GRUPOS_META = {
    "proto": ("tls-proto-obsoleto", "Protocolos TLS obsoletos habilitados (TLS 1.0/1.1 o anteriores)",
              "Desactivar SSLv2/SSLv3/TLS 1.0/1.1 en el servidor y permitir solo TLS 1.2 y 1.3."),
    "cifrado": ("tls-cifrado-debil", "Suites de cifrado débiles habilitadas",
                "Eliminar las suites débiles (NULL, EXPORT, RC4, 3DES, CBC sin AEAD, 64-bit) y aplicar "
                "la configuración 'intermediate' de Mozilla."),
}


def _grupo_de(tid: str) -> str | None:
    t = tid.lower()
    if t in _PROTO_OBSOLETO:
        return "proto"
    if t in _CIFRADO_DEBIL or t.startswith("cipherlist"):
        return "cifrado"
    return None


def agrupar_tls(findings: list[dict]) -> list[dict]:
    """Colapsa los hallazgos de testssl en sus causas raíz (protocolos obsoletos,
    cifrado débil). Vulnerabilidades concretas (Heartbleed, ROBOT, BREACH…) y el
    certificado se mantienen individuales."""
    grupos: dict[str, dict] = {}
    salida: list[dict] = []
    for f in findings:
        g = _grupo_de(f.get("plantilla", ""))
        if g is None:
            salida.append(f)
            continue
        d = grupos.setdefault(g, {"miembros": [], "sev": "low", "cve": [], "det": []})
        d["miembros"].append(f.get("plantilla", ""))
        if _SEV_RANK.get(f.get("severidad", ""), 0) > _SEV_RANK.get(d["sev"], 0):
            d["sev"] = f["severidad"]
        for c in f.get("cve", []):
            if c not in d["cve"]:
                d["cve"].append(c)
        if f.get("detalle"):
            d["det"].append(f"{f.get('plantilla', '')}: {f['detalle']}")
    for g, d in grupos.items():
        gid, titulo, rem = _GRUPOS_META[g]
        nf = {
            "severidad": d["sev"], "id": gid, "titulo": titulo, "plantilla": gid,
            "detalle": f"testssl.sh detectó {len(d['miembros'])} elemento(s) relacionados con esta misma "
                       f"causa raíz: {', '.join(d['miembros'])}.",
            "remediacion": rem,
            "evidencia": "; ".join(d["det"])[:400],
        }
        if d["cve"]:
            nf["cve"] = d["cve"]
        salida.append(nf)
    return salida


def resumen(datos: list[dict]) -> dict:
    """Datos clave para mostrar arriba del informe (protocolos, emisor, etc.)."""
    interes = {"SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3", "cert_commonName",
               "cert_caIssuers", "cert_notAfter", "cert_chain_of_trust", "OCSP_stapling",
               "HSTS", "cert_keySize", "overall_grade"}
    out: dict = {}
    for e in datos:
        tid = _id(e)
        if tid in interes and tid not in out:
            out[tid] = e.get("finding")
    return out


def _remediacion(tid: str) -> str:
    t = tid.lower()
    if t in ("sslv2", "sslv3", "tls1", "tls1_1"):
        return "Desactivar el protocolo obsoleto; permitir solo TLS 1.2 y 1.3."
    if t.startswith("cipherlist") or "cipher" in t:
        return "Eliminar suites débiles (NULL, EXPORT, RC4, 3DES, CBC sin AEAD); usar la configuración 'intermediate' de Mozilla."
    if t.startswith("cert_"):
        return "Revisar el certificado (cadena completa, algoritmo de firma, tamaño de clave, caducidad)."
    if t in ("heartbleed", "ccs", "ticketbleed", "robot", "drown", "freak", "logjam", "poodle_ssl",
             "beast", "lucky13", "sweet32", "breach", "crime_tls", "secure_renego", "secure_client_renego"):
        return f"Actualizar la librería TLS / servidor y aplicar la mitigación recomendada para {tid}."
    return "Ver la documentación de testssl.sh para este identificador y endurecer la configuración TLS."
