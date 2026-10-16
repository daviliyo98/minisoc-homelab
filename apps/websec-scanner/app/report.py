"""
report — Comparación entre escaneos e informes descargables.

Formatos: html (autocontenido; desde el navegador se imprime a PDF), md, json y
SARIF 2.1.0 (para GitHub Code Scanning, DefectDojo y similares).
"""
from __future__ import annotations

import html
import json
import time

from . import severity

_SEV_ORDEN = {"critica": 0, "alta": 1, "media": 2, "baja": 3, "info": 4}
_SEV_COLOR = {"critica": "#b3001b", "alta": "#e5484d", "media": "#f08c00", "baja": "#c9a400", "info": "#6b7280"}


# --------------------------------------------------------------------------- #
#  Comparación
# --------------------------------------------------------------------------- #
def clave(f: dict) -> str:
    """Identidad estable de un hallazgo entre escaneos (y entre módulos)."""
    return severity.identidad(f)


def hallazgos_de(result: dict | None) -> list[dict]:
    if not result:
        return []
    if "secciones" in result:  # /scan-full agrupa varios escaneos
        todos = [f for sec in result["secciones"].values() if sec for f in sec.get("hallazgos", [])]
    else:
        todos = result.get("hallazgos", [])
    unicos: dict[str, dict] = {}
    for f in todos:  # escaneos antiguos pueden traer el mismo problema de dos módulos
        unicos.setdefault(clave(f), f)
    return list(unicos.values())


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
_NOTA_CVSS = "Puntuaciones CVSS v3.1 de referencia: ajustar al contexto del activo."


def _copyright() -> str:
    return f"© {time.strftime('%Y')} Almenasec. Todos los derechos reservados."


def _fecha(ts: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "—"


_PRIO_ORDEN = {"P0": 0, "P1": 1, "P2": 2}


def _ordenados(scan: dict) -> list[dict]:
    return sorted(hallazgos_de(scan.get("result")),
                  key=lambda f: (_PRIO_ORDEN.get(f.get("prioridad"), 3),
                                 _SEV_ORDEN.get(f.get("severidad_cvss", "info"), 9),
                                 -(f.get("cvss_score") or 0)))


def render_json(scan: dict) -> str:
    return json.dumps(scan, ensure_ascii=False, indent=2)


_TRAMO = {"critica": "Crítica", "alta": "Alta", "media": "Media", "baja": "Baja"}


def _eur(n: float) -> str:
    return f"{n:,.0f} €".replace(",", ".")


def _filas_presupuesto(q: dict) -> list[tuple[str, str]]:
    filas = []
    if q["cuota_minima"]:
        filas.append(("Cuota mínima", _eur(q["cuota_minima"])))
    filas += [(f"{_TRAMO[l['tramo']]} × {l['unidades']} ({_eur(l['precio'])} c/u)", _eur(l["importe"]))
              for l in q["lineas"]]
    if q["tope_aplicado"]:
        filas.append((f"Tope máximo aplicado (sin tope: {_eur(q['cuota_minima'] + q['subtotal_hallazgos'])})",
                      _eur(q["tope"])))
    filas.append(("Total estimado (sin IVA)", _eur(q["total"])))
    return filas


def render_md(scan: dict, cambios: dict | None = None, precios: bool = False) -> str:
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
    q = r.get("presupuesto")
    if precios and q:
        out += ["## Estimación económica (pago por hallazgo)", "", "| Concepto | Importe |", "|---|---:|"]
        out += [f"| {c} | {i} |" for c, i in _filas_presupuesto(q)]
        out += ["", f"_{q['nota']}_", ""]
    if cambios:
        out += ["## Cambios desde el escaneo anterior", "",
                f"- Nuevos: **{len(cambios['nuevos'])}** · Corregidos: **{len(cambios['corregidos'])}** · "
                f"Persisten: {cambios['persisten']}", ""]
        out += [f"  - 🆕 {f.get('titulo')}" for f in cambios["nuevos"]]
        out += [f"  - ✅ {f.get('titulo')}" for f in cambios["corregidos"]]
        out.append("")
    _todo = _ordenados(scan)
    hs = [f for f in _todo if not f.get("inventario")]
    inventario = [f for f in _todo if f.get("inventario")]
    _pc = {"P0": 0, "P1": 0, "P2": 0}
    for _f in hs:
        if _f.get("prioridad") in _pc:
            _pc[_f["prioridad"]] += 1
    out += ["## Hallazgos", ""]
    if hs:
        out += [f"**Plan priorizado:** P0 {_pc['P0']} · P1 {_pc['P1']} · P2 {_pc['P2']} "
                "(P0 explotable ya · P1 endurecer pronto · P2 defensa en profundidad)", ""]
    if not hs:
        out.append("Sin hallazgos.")
    for i, f in enumerate(hs, 1):
        out += [f"### {i}. " + (f"[{f['prioridad']}] " if f.get('prioridad') else "") + f"{f.get('titulo')}",
                f"**Severidad:** {f.get('severidad_cvss_label', f.get('severidad'))} "
                f"(CVSS {f.get('cvss_score', '—')})" + (f" · `{f['cvss']}`" if f.get("cvss") not in (None, "—") else ""),
                ""]
        meta = [x for x in (("Fuente: " + f["origen"]) if f.get("origen") else None,
                             f.get("cwe"), f.get("owasp"), ", ".join(f.get("cve") or [])) if x and x != "—"]
        if meta:
            out += [" · ".join(meta), ""]
        out += [f.get("detalle", ""), ""]
        if f.get("evidencia"):
            out += [f"**Evidencia:** `{f['evidencia']}`", ""]
        out += [f"**Remediación:** {f.get('remediacion', '')}", ""]
        if f.get("nota_operativa"):
            out += [f"**Nota operativa:** {f['nota_operativa']}", ""]
    if inventario:
        out += ["", "## Inventario y detecciones", "",
                "_Tecnologías, WAF, certificado y versiones detectadas. No son hallazgos ni se facturan; se listan como contexto._", ""]
        out += [f"- **{f.get('titulo')}** — {(f.get('detalle') or '')[:160]}" for f in inventario]
        out += [""]
    pie = " ".join(x for x in (_copyright(), r.get("aviso")) if x)
    out += ["---", f"_{pie}_", "", f"_{_NOTA_CVSS}_"]
    return "\n".join(out)


def render_html(scan: dict, cambios: dict | None = None, precios: bool = False) -> str:
    e = lambda s: html.escape(str(s if s is not None else ""))
    r = scan.get("result") or {}
    _todo = _ordenados(scan)
    hs = [f for f in _todo if not f.get("inventario")]
    inventario = [f for f in _todo if f.get("inventario")]
    cuenta = {k: 0 for k in _SEV_ORDEN}
    for f in hs:
        cuenta[f.get("severidad_cvss", "info")] = cuenta.get(f.get("severidad_cvss", "info"), 0) + 1
    tarjetas = "".join(
        f'<div class="kpi"><span style="background:{_SEV_COLOR[k]}"></span><b>{cuenta[k]}</b> {k.capitalize()}</div>'
        for k in _SEV_ORDEN)
    plan_c = {"P0": 0, "P1": 0, "P2": 0}
    for f in hs:
        if f.get("prioridad") in plan_c:
            plan_c[f["prioridad"]] += 1
    plan = ('<div class="plan"><b>Plan priorizado</b> — '
            f'<span class="prio prio-P0">P0</span> {plan_c["P0"]} · '
            f'<span class="prio prio-P1">P1</span> {plan_c["P1"]} · '
            f'<span class="prio prio-P2">P2</span> {plan_c["P2"]}<span class="muted"> &nbsp;(P0 explotable ya · P1 endurecer pronto · P2 defensa en profundidad)</span></div>') if hs else ""
    filas = []
    for i, f in enumerate(hs, 1):
        sev = f.get("severidad_cvss", "info")
        meta = " · ".join(e(x) for x in (("Fuente: " + f["origen"]) if f.get("origen") else None,
                                          f.get("cvss") if f.get("cvss") != "—" else None, f.get("cwe"),
                                          f.get("owasp"), ", ".join(f.get("cve") or [])) if x and x != "—")
        filas.append(
            f'<article><header><span class="sev" style="background:{_SEV_COLOR.get(sev)}">'
            f'{e(f.get("severidad_cvss_label", sev))} {e(f.get("cvss_score", ""))}</span>'
            + (f'<span class="prio prio-{e(f.get("prioridad"))}">{e(f.get("prioridad"))}</span>' if f.get("prioridad") else "")
            + f'<h3>{i}. {e(f.get("titulo"))}</h3></header>'
            f'<p>{e(f.get("detalle"))}</p>'
            + (f'<p class="evid"><b>Evidencia:</b> <code>{e(f.get("evidencia"))}</code></p>' if f.get("evidencia") else "")
            + (f'<p class="meta">{meta}</p>' if meta else "")
            + (f'<p class="nota"><b>Nota operativa:</b> {e(f.get("nota_operativa"))}</p>' if f.get("nota_operativa") else "")
            + f'<p class="fix"><b>Remediación:</b> {e(f.get("remediacion"))}</p></article>')
    bloque_cambios = ""
    if cambios:
        li = "".join(f"<li>🆕 {e(f.get('titulo'))}</li>" for f in cambios["nuevos"])
        li += "".join(f"<li>✅ {e(f.get('titulo'))}</li>" for f in cambios["corregidos"])
        bloque_cambios = (f'<section><h2>Cambios desde el escaneo anterior</h2><p>Nuevos: <b>{len(cambios["nuevos"])}</b>'
                          f' · Corregidos: <b>{len(cambios["corregidos"])}</b> · Persisten: {cambios["persisten"]}</p>'
                          f'<ul>{li}</ul></section>')
    bloque_precio = ""
    q = r.get("presupuesto")
    if precios and q:
        tr = "".join(f"<tr><td>{e(c)}</td><td class=\"num\">{e(i)}</td></tr>" for c, i in _filas_presupuesto(q))
        bloque_precio = (f'<section><h2>Estimación económica (pago por hallazgo)</h2>'
                         f'<table class="presu">{tr}</table><p class="muted">{e(q["nota"])}</p></section>')
    inv_html = ""
    if inventario:
        items = "".join(f'<li><b>{e(f.get("titulo"))}</b> — {e((f.get("detalle") or "")[:160])}</li>' for f in inventario)
        inv_html = (f'<section><h2>Inventario y detecciones ({len(inventario)})</h2>'
                    f'<p class="muted">Tecnologías, WAF, certificado y versiones detectadas. No son hallazgos ni se facturan; se listan como contexto.</p>'
                    f'<ul class="inv">{items}</ul></section>')
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
.prio{{border-radius:999px;padding:2px 9px;font-size:.72rem;font-weight:800;white-space:nowrap;border:1px solid}}
.prio-P0{{color:#b91c1c;border-color:#fca5a5;background:#fef2f2}}
.prio-P1{{color:#b45309;border-color:#fcd34d;background:#fffbeb}}
.prio-P2{{color:#1d4ed8;border-color:#bfdbfe;background:#eff6ff}}
.plan{{margin:6px 0 2px;font-size:.9rem;display:flex;gap:6px;align-items:center;flex-wrap:wrap}}
.evid code{{font-size:.8rem;word-break:break-all}}
.nota{{font-size:.85rem;background:#fff7ed;border-left:3px solid #fb923c;padding:6px 10px;border-radius:4px;color:#7c2d12}}
.nota b{{color:#7c2d12}}
.fix b{{color:#047857}}
.inv{{columns:2;gap:18px;font-size:.85rem;color:var(--muted)}} .inv li{{break-inside:avoid;margin:2px 0}}
@media(max-width:560px){{.inv{{columns:1}}}}
.presu{{border-collapse:collapse;width:100%;max-width:520px}} .presu td{{border-bottom:1px solid var(--border);padding:6px 4px}}
.presu .num{{text-align:right;white-space:nowrap}} .presu tr:last-child td{{font-weight:700;border-bottom:0}} footer{{margin-top:32px;font-size:.8rem;color:var(--muted)}}
@media print{{body{{padding:0}} a{{color:inherit}}}}
</style></head><body>
<h1>Informe de seguridad</h1>
<div class="muted">{e(scan['objetivo'])} · análisis <b>{e(scan['tipo'])}</b> · {_fecha(scan.get('finished') or scan.get('started'))} · ID {e(scan['id'])}</div>
<div class="score"><div class="n">{e(r.get('puntuacion', '—'))}<span class="muted">/100</span></div>
<div>CVSS máximo: <b>{e(r.get('cvss_max', '—'))}</b><br><span class="muted">{len(hs)} hallazgo(s)</span></div></div>
<div class="kpis">{tarjetas}</div>
{plan}
{bloque_precio}
{bloque_cambios}
<section><h2>Hallazgos</h2>{''.join(filas) or '<p>Sin hallazgos.</p>'}</section>
{inv_html}
<footer>{e(_copyright())} {e(r.get('aviso', ''))}<br>{e(_NOTA_CVSS)}</footer>
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
