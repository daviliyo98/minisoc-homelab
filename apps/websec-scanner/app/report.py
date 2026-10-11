"""
report — Comparación entre escaneos e informes descargables.

Formatos: html (autocontenido; desde el navegador se imprime a PDF), md, json y
SARIF 2.1.0 (para GitHub Code Scanning, DefectDojo y similares).
"""
from __future__ import annotations

import html
import json
import time

_SEV_ORDEN = {"critica": 0, "alta": 1, "media": 2, "baja": 3, "info": 4}
_SEV_COLOR = {"critica": "#b3001b", "alta": "#e5484d", "media": "#f08c00", "baja": "#c9a400", "info": "#6b7280"}


# --------------------------------------------------------------------------- #
#  Comparación
# --------------------------------------------------------------------------- #
def clave(f: dict) -> str:
    """Identidad estable de un hallazgo entre escaneos."""
    return f"{f.get('servicio', '')}|{f.get('titulo', '')}"


def hallazgos_de(result: dict | None) -> list[dict]:
    if not result:
        return []
    if "secciones" in result:  # /scan-full agrupa varios escaneos
        return [f for sec in result["secciones"].values() if sec for f in sec.get("hallazgos", [])]
    return result.get("hallazgos", [])


def diff(anterior: dict | None, actual: dict | None) -> dict:
    a = {clave(f): f for f in hallazgos_de(anterior)}
    b = {clave(f): f for f in hallazgos_de(actual)}
    nuevos = [b[k] for k in b if k not in a]
    corregidos = [a[k] for k in a if k not in b]
    def cv(r): return (r or {}).get("cvss_max")
    def pt(r): return (r or {}).get("puntuacion")
    return {
        "nuevos": sorted(nuevos, key=lambda f: -(f.get("cvss_score") or 0)),
        "corregidos": sorted(corregidos, key=lambda f: -(f.get("cvss_score") or 0)),
        "persisten": len([k for k in b if k in a]),
        "puntuacion": {"antes": pt(anterior), "ahora": pt(actual)},
        "cvss_max": {"antes": cv(anterior), "ahora": cv(actual)},
    }


# --------------------------------------------------------------------------- #
#  Informes
# --------------------------------------------------------------------------- #
def _fecha(ts: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "—"


def _ordenados(scan: dict) -> list[dict]:
    return sorted(hallazgos_de(scan.get("result")),
                  key=lambda f: (_SEV_ORDEN.get(f.get("severidad_cvss", "info"), 9), -(f.get("cvss_score") or 0)))


def render_json(scan: dict) -> str:
    return json.dumps(scan, ensure_ascii=False, indent=2)


def render_md(scan: dict, cambios: dict | None = None) -> str:
    r = scan.get("result") or {}
    out = [f"# Informe de seguridad — {scan['objetivo']}", "",
           f"- **Tipo de análisis:** {scan['tipo']}",
           f"- **Fecha:** {_fecha(scan.get('finished') or scan.get('started'))}",
           f"- **Puntuación:** {r.get('puntuacion', '—')}/100 · **CVSS máximo:** {r.get('cvss_max', '—')}",
           f"- **ID del escaneo:** `{scan['id']}`", ""]
    p = r.get("pago_por_hallazgo")
    if p:
        out += [f"**Hallazgos:** {p['criticas']} críticos · {p['altas']} altos · {p['medias']} medios · "
                f"{p['bajas']} bajos · {p['info']} informativos", ""]
    if cambios:
        out += ["## Cambios desde el escaneo anterior", "",
                f"- Nuevos: **{len(cambios['nuevos'])}** · Corregidos: **{len(cambios['corregidos'])}** · "
                f"Persisten: {cambios['persisten']}", ""]
        out += [f"  - 🆕 {f.get('titulo')}" for f in cambios["nuevos"]]
        out += [f"  - ✅ {f.get('titulo')}" for f in cambios["corregidos"]]
        out.append("")
    out += ["## Hallazgos", ""]
    hs = _ordenados(scan)
    if not hs:
        out.append("Sin hallazgos.")
    for i, f in enumerate(hs, 1):
        out += [f"### {i}. {f.get('titulo')}",
                f"**Severidad:** {f.get('severidad_cvss_label', f.get('severidad'))} "
                f"(CVSS {f.get('cvss_score', '—')})" + (f" · `{f['cvss']}`" if f.get("cvss") not in (None, "—") else ""),
                ""]
        meta = [x for x in (f.get("cwe"), f.get("owasp"), ", ".join(f.get("cve") or [])) if x and x != "—"]
        if meta:
            out += [" · ".join(meta), ""]
        out += [f.get("detalle", ""), "", f"**Remediación:** {f.get('remediacion', '')}", ""]
    if r.get("aviso"):
        out += ["---", f"_{r['aviso']}_"]
    return "\n".join(out)


def render_html(scan: dict, cambios: dict | None = None) -> str:
    e = lambda s: html.escape(str(s if s is not None else ""))
    r = scan.get("result") or {}
    hs = _ordenados(scan)
    cuenta = {k: 0 for k in _SEV_ORDEN}
    for f in hs:
        cuenta[f.get("severidad_cvss", "info")] = cuenta.get(f.get("severidad_cvss", "info"), 0) + 1
    tarjetas = "".join(
        f'<div class="kpi"><span style="background:{_SEV_COLOR[k]}"></span><b>{cuenta[k]}</b> {k.capitalize()}</div>'
        for k in _SEV_ORDEN)
    filas = []
    for i, f in enumerate(hs, 1):
        sev = f.get("severidad_cvss", "info")
        meta = " · ".join(e(x) for x in (f.get("cvss") if f.get("cvss") != "—" else None, f.get("cwe"),
                                          f.get("owasp"), ", ".join(f.get("cve") or [])) if x and x != "—")
        filas.append(
            f'<article><header><span class="sev" style="background:{_SEV_COLOR.get(sev)}">'
            f'{e(f.get("severidad_cvss_label", sev))} {e(f.get("cvss_score", ""))}</span>'
            f'<h3>{i}. {e(f.get("titulo"))}</h3></header>'
            f'<p>{e(f.get("detalle"))}</p>'
            + (f'<p class="meta">{meta}</p>' if meta else "")
            + f'<p class="fix"><b>Remediación:</b> {e(f.get("remediacion"))}</p></article>')
    bloque_cambios = ""
    if cambios:
        li = "".join(f"<li>🆕 {e(f.get('titulo'))}</li>" for f in cambios["nuevos"])
        li += "".join(f"<li>✅ {e(f.get('titulo'))}</li>" for f in cambios["corregidos"])
        bloque_cambios = (f'<section><h2>Cambios desde el escaneo anterior</h2><p>Nuevos: <b>{len(cambios["nuevos"])}</b>'
                          f' · Corregidos: <b>{len(cambios["corregidos"])}</b> · Persisten: {cambios["persisten"]}</p>'
                          f'<ul>{li}</ul></section>')
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de seguridad — {e(scan['objetivo'])}</title>
<style>
:root{{--text:#111827;--muted:#6b7280;--border:#e5e7eb;--bg:#fff}}
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--text);background:var(--bg);
     max-width:880px;margin:0 auto;padding:32px 16px;line-height:1.5}}
h1{{margin:0 0 4px;font-size:1.6rem}} h2{{font-size:1.15rem;margin:28px 0 10px;border-bottom:1px solid var(--border);padding-bottom:6px}}
h3{{font-size:1rem;margin:0}} .muted,.meta{{color:var(--muted);font-size:.85rem}}
.meta{{font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-word}}
.score{{display:flex;gap:24px;align-items:center;margin:18px 0}} .score .n{{font-size:2.6rem;font-weight:800}}
.kpis{{display:flex;flex-wrap:wrap;gap:10px;margin:10px 0}} .kpi{{border:1px solid var(--border);border-radius:8px;padding:6px 10px;font-size:.88rem}}
.kpi span{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}}
article{{border:1px solid var(--border);border-radius:10px;padding:14px 16px;margin:12px 0;break-inside:avoid}}
article header{{display:flex;gap:10px;align-items:center;margin-bottom:6px}}
.sev{{color:#fff;border-radius:999px;padding:2px 10px;font-size:.75rem;font-weight:700;white-space:nowrap}}
.fix b{{color:#047857}} footer{{margin-top:32px;font-size:.8rem;color:var(--muted)}}
@media print{{body{{padding:0}} a{{color:inherit}}}}
</style></head><body>
<h1>Informe de seguridad</h1>
<div class="muted">{e(scan['objetivo'])} · análisis <b>{e(scan['tipo'])}</b> · {_fecha(scan.get('finished') or scan.get('started'))} · ID {e(scan['id'])}</div>
<div class="score"><div class="n">{e(r.get('puntuacion', '—'))}<span class="muted">/100</span></div>
<div>CVSS máximo: <b>{e(r.get('cvss_max', '—'))}</b><br><span class="muted">{len(hs)} hallazgo(s)</span></div></div>
<div class="kpis">{tarjetas}</div>
{bloque_cambios}
<section><h2>Hallazgos</h2>{''.join(filas) or '<p>Sin hallazgos.</p>'}</section>
<footer>{e(r.get('aviso', ''))}<br>Generado por MINISOC websec-scanner. Puntuaciones CVSS v3.1 de referencia: ajustar al contexto del activo.</footer>
</body></html>"""


def render_sarif(scan: dict) -> str:
    nivel = {"critica": "error", "alta": "error", "media": "warning", "baja": "note", "info": "none"}
    reglas: dict[str, dict] = {}
    resultados = []
    for f in _ordenados(scan):
        rid = f.get("id") or f.get("plantilla") or f.get("titulo", "hallazgo")
        if rid not in reglas:
            props = {"security-severity": str(f.get("cvss_score") or 0.0),
                     "tags": [t for t in ("security", f.get("cwe"), f.get("owasp")) if t and t != "—"]}
            reglas[rid] = {"id": rid, "name": f.get("titulo"),
                           "shortDescription": {"text": f.get("titulo", "")},
                           "help": {"text": f.get("remediacion", "")},
                           "properties": props}
        resultados.append({
            "ruleId": rid,
            "level": nivel.get(f.get("severidad_cvss", "info"), "note"),
            "message": {"text": f"{f.get('titulo')}: {f.get('detalle', '')}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": scan["objetivo"]}}}],
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "MINISOC websec-scanner",
                                "rules": list(reglas.values())}},
            "automationDetails": {"id": f"{scan['tipo']}/{scan['id']}"},
            "results": resultados,
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)
