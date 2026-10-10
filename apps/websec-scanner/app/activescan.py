"""
activescan — Escaneo ACTIVO de vulnerabilidades web con Nuclei.

A DIFERENCIA del resto del scanner (que es pasivo), este módulo SÍ envía
peticiones al objetivo para detectar vulnerabilidades y malas configuraciones
conocidas, usando las plantillas de Nuclei (projectdiscovery).

Por eso está protegido por TRES candados (ver main.py):
  1. ACTIVE_SCAN_ENABLED=1 en el servidor (desactivado por defecto).
  2. La petición debe confirmar la autorización (autorizo=true).
  3. El validador de URL bloquea objetivos internos/loopback (anti-SSRF).

Se excluyen plantillas destructivas (dos, intrusive, fuzz): esto detecta,
no explota ni tumba servicios. Aun así, EJECÚTALO SOLO con autorización
explícita y por escrito del titular del sistema.
"""
from __future__ import annotations

import json
import shutil
import subprocess

# Nuclei -> severidad interna del scanner.
# 'info' NO es un fallo (es tecnología/huella detectada): va a su propio cubo
# "informativo", que se muestra aparte y NO penaliza la puntuación.
SEV_MAP = {
    "critical": "alta", "high": "alta",
    "medium": "media",
    "low": "baja",
    "info": "informativo", "unknown": "informativo",
}

TEMPLATES_DIR = "/opt/nuclei-templates"


def nuclei_disponible() -> bool:
    return shutil.which("nuclei") is not None


def scan_activo(url: str, timeout_total: float = 200.0) -> dict:
    """Ejecuta Nuclei contra una URL autorizada y devuelve los hallazgos."""
    if not nuclei_disponible():
        return {"ok": False, "error": "Nuclei no está instalado en el contenedor.", "findings": []}

    cmd = [
        "nuclei", "-u", url,
        "-jsonl", "-silent",
        # Enfoque en VULNERABILIDADES reales (no las 6.600 plantillas): mucho más
        # rápido (segundos en vez de minutos) y son los hallazgos que van en un informe.
        "-tags", "cve,misconfig,exposure,exposed-panels,default-login,tech,ssl,sqli,xss,lfi,rce,ssrf,takeover",
        # TODAS las severidades: los 'info'/'low' (cabeceras, cookies, tecnología
        # detectada) son justo lo que el usuario quiere ver. Se clasifican después.
        "-severity", "info,low,medium,high,critical",
        # Nada destructivo.
        "-exclude-tags", "dos,intrusive,fuzz",
        # Más paralelismo para terminar rápido, pero suave con el objetivo.
        "-concurrency", "50", "-bulk-size", "50", "-rate-limit", "50",
        "-timeout", "8", "-retries", "1",
        "-disable-update-check", "-no-interactsh", "-stats=false", "-nc",
    ]
    # El contenedor es de solo lectura: Nuclei escribe su config/caché en /tmp (tmpfs).
    env = {"HOME": "/tmp", "PATH": "/usr/local/bin:/usr/bin:/bin"}

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_total, env=env
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "El escaneo activo superó el tiempo límite.", "findings": []}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "error": f"No se pudo ejecutar Nuclei: {e}", "findings": []}

    findings: list[dict] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        info = j.get("info", {}) or {}
        sev = (info.get("severity") or "unknown").lower()
        matched = j.get("matched-at") or j.get("host") or url
        desc = (info.get("description") or "").strip()
        detalle = f"Detectado en: {matched}"
        if desc:
            detalle += f". {desc}"
        refs = info.get("reference") or []
        remediacion = (info.get("remediation")
                       or (" · ".join(refs[:2]) if refs else "")
                       or f"Revisar la plantilla '{j.get('template-id', '')}' de Nuclei.")
        findings.append({
            "severidad": SEV_MAP.get(sev, "baja"),
            "titulo": info.get("name") or j.get("template-id", "Hallazgo"),
            "detalle": detalle,
            "remediacion": remediacion,
        })

    # Si Nuclei terminó en error y no produjo hallazgos, NO lo hagamos pasar por
    # "0 hallazgos" (eso ocultaría un escaneo roto como si fuera un objetivo limpio).
    if not findings and proc.returncode != 0:
        err_lines = (proc.stderr or "").strip().splitlines()
        tail = " | ".join(l.strip() for l in err_lines[-3:]) if err_lines else f"código de salida {proc.returncode}"
        return {"ok": False, "error": f"Nuclei no completó el escaneo: {tail}", "findings": []}

    orden = {"alta": 0, "media": 1, "baja": 2, "informativo": 3}
    findings.sort(key=lambda f: orden.get(f["severidad"], 9))
    return {"ok": True, "motor": "nuclei", "total": len(findings), "findings": findings}
