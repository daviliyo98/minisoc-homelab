"""
mailcheck — Análisis PASIVO de la postura de seguridad del CORREO de un dominio.

Responde a una pregunta de negocio: "¿Pueden suplantar este dominio para enviar
correo en su nombre?" (p. ej. facturas falsas a sus clientes).

Observa SOLO registros DNS públicos: SPF, DKIM, DMARC y MX. No envía correo ni
interactúa con el servidor de correo. Es, como el resto del scanner, pasivo.

Referencias: RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC).
"""
from __future__ import annotations

from urllib.parse import urlparse

import dns.resolver

# Selectores DKIM habituales. DKIM no es "descubrible": si el dominio usa un
# selector propio no estándar, no lo veremos (y no concluimos que falte).
COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "dkim",
    "mail", "s1", "s2", "smtp", "mandrill", "mailjet", "sendgrid",
    "zoho", "zohomail", "protonmail", "pm", "fm1", "fm2", "fm3", "amazonses",
]

_RESOLVER = dns.resolver.Resolver()
_RESOLVER.lifetime = 5.0
_RESOLVER.timeout = 5.0


def _txt(name: str) -> list[str]:
    """Devuelve los registros TXT de un nombre (cada uno ya reensamblado)."""
    try:
        ans = _RESOLVER.resolve(name, "TXT")
    except Exception:
        return []
    out = []
    for r in ans:
        parts = []
        for s in r.strings:
            parts.append(s.decode(errors="ignore") if isinstance(s, (bytes, bytearray)) else str(s))
        out.append("".join(parts))
    return out


def _mx(domain: str) -> list[str]:
    try:
        ans = _RESOLVER.resolve(domain, "MX")
        return sorted(str(r.exchange).rstrip(".") for r in ans)
    except Exception:
        return []


def _clean_domain(value: str) -> str:
    """Admite 'ejemplo.com', 'https://ejemplo.com/x' o 'correo@ejemplo.com'."""
    value = value.strip()
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    if "://" in value:
        value = urlparse(value).hostname or value
    return value.strip(". ").lower()


# --------------------------------------------------------------------------- #
#  SPF
# --------------------------------------------------------------------------- #
def check_spf(domain: str) -> dict:
    findings: list[dict] = []
    records = [t for t in _txt(domain) if t.lower().startswith("v=spf1")]

    if not records:
        findings.append({
            "severidad": "alta",
            "titulo": "No existe registro SPF",
            "detalle": "Sin SPF, nada declara qué servidores pueden enviar correo con este dominio.",
            "remediacion": "Publicar un TXT con v=spf1 que liste los emisores legítimos y termine en '-all'.",
        })
        return {"presente": False, "cualificador": None, "registro": None, "findings": findings}

    if len(records) > 1:
        findings.append({
            "severidad": "alta",
            "titulo": "Varios registros SPF",
            "detalle": "Tener más de un SPF es inválido (RFC 7208): los servidores lo descartan y es como no tenerlo.",
            "remediacion": "Dejar un único registro SPF, combinando los emisores con 'include:'.",
        })

    rec = records[0].lower()
    if "-all" in rec:
        qual = "-all"
    elif "~all" in rec:
        qual = "~all"
    elif "?all" in rec:
        qual = "?all"
    elif "+all" in rec:
        qual = "+all"
    else:
        qual = None

    if qual == "+all":
        findings.append({
            "severidad": "alta",
            "titulo": "SPF permite a cualquiera ('+all')",
            "detalle": "'+all' autoriza a CUALQUIER servidor a enviar como este dominio. Peor que no tener SPF.",
            "remediacion": "Cambiar '+all' por '-all' (rechazo) o '~all' (softfail).",
        })
    elif qual in ("?all", None):
        findings.append({
            "severidad": "media",
            "titulo": "SPF no es restrictivo",
            "detalle": f"El SPF termina en '{qual or 'sin all'}', que no pide rechazar a los emisores no autorizados.",
            "remediacion": "Terminar el SPF en '-all' (recomendado) o '~all'.",
        })

    return {"presente": True, "cualificador": qual, "registro": records[0], "findings": findings}


# --------------------------------------------------------------------------- #
#  DMARC
# --------------------------------------------------------------------------- #
def check_dmarc(domain: str) -> dict:
    findings: list[dict] = []
    records = [t for t in _txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]

    if not records:
        findings.append({
            "severidad": "alta",
            "titulo": "No existe registro DMARC",
            "detalle": "Sin DMARC no se le dice al receptor qué hacer con el correo que falla SPF/DKIM: la suplantación pasa.",
            "remediacion": "Publicar _dmarc.<dominio> con v=DMARC1; empezar en p=none con rua para observar, y subir a p=quarantine/reject.",
        })
        return {"presente": False, "politica": None, "rua": False, "registro": None, "findings": findings}

    rec = records[0]
    tags = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "none").lower()
    has_rua = "rua" in tags

    if policy == "none":
        findings.append({
            "severidad": "media",
            "titulo": "DMARC solo en modo observación (p=none)",
            "detalle": "Con p=none el correo suplantado NO se bloquea; solo se monitoriza. En la práctica, sigue siendo suplantable.",
            "remediacion": "Tras revisar los informes rua, subir la política a p=quarantine y después a p=reject.",
        })
    elif policy == "quarantine":
        findings.append({
            "severidad": "baja",
            "titulo": "DMARC en cuarentena (p=quarantine)",
            "detalle": "El correo suplantado va a spam. Bien, aunque 'reject' es el objetivo final.",
            "remediacion": "Cuando haya confianza en los informes, subir a p=reject.",
        })
    # p=reject => sin hallazgo (óptimo)

    if not has_rua:
        findings.append({
            "severidad": "baja",
            "titulo": "DMARC sin informes (rua)",
            "detalle": "Sin 'rua' no recibes informes de quién intenta suplantarte: pierdes visibilidad.",
            "remediacion": "Añadir rua=mailto:dmarc@<dominio> para recibir informes agregados.",
        })

    return {"presente": True, "politica": policy, "rua": has_rua, "registro": rec, "findings": findings}


# --------------------------------------------------------------------------- #
#  DKIM (best-effort: probamos selectores habituales)
# --------------------------------------------------------------------------- #
def check_dkim(domain: str) -> dict:
    encontrados = []
    for sel in COMMON_DKIM_SELECTORS:
        recs = _txt(f"{sel}._domainkey.{domain}")
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in recs):
            encontrados.append(sel)

    findings: list[dict] = []
    if not encontrados:
        findings.append({
            "severidad": "baja",
            "titulo": "No se detectó DKIM en selectores habituales",
            "detalle": "Puede existir con un selector propio no estándar (no es concluyente). DKIM firma el correo para probar su autenticidad.",
            "remediacion": "Verificar/activar DKIM en el proveedor de correo y publicar la clave pública en <selector>._domainkey.",
        })
    return {"detectado": bool(encontrados), "selectores": encontrados, "findings": findings}


# --------------------------------------------------------------------------- #
#  Agregado + veredicto de suplantación
# --------------------------------------------------------------------------- #
def scan(domain: str) -> dict:
    domain = _clean_domain(domain)
    spf = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim = check_dkim(domain)
    mx = _mx(domain)

    todos = spf["findings"] + dmarc["findings"] + dkim["findings"]
    orden = {"alta": 0, "media": 1, "baja": 2}
    todos.sort(key=lambda f: orden.get(f["severidad"], 9))

    pen = {"alta": 25, "media": 10, "baja": 4}
    nota = max(0, 100 - sum(pen.get(f["severidad"], 0) for f in todos))

    # Veredicto de suplantación: la protección REAL exige SPF restrictivo
    # Y DMARC que bloquee (quarantine/reject). DKIM suma pero no basta solo.
    spf_ok = spf["presente"] and spf["cualificador"] in ("-all", "~all")
    dmarc_bloquea = dmarc["presente"] and dmarc["politica"] in ("quarantine", "reject")

    if spf_ok and dmarc_bloquea:
        suplantable = False
        veredicto = "Protegido: SPF restrictivo y DMARC activo. La suplantación directa está mitigada."
    elif spf["presente"] or dmarc["presente"]:
        suplantable = True
        veredicto = "Parcialmente protegido: hay defensas pero no bloquean la suplantación en la práctica (revisa los hallazgos)."
    else:
        suplantable = True
        veredicto = "SUPLANTABLE: sin SPF ni DMARC, cualquiera puede enviar correo haciéndose pasar por este dominio."

    return {
        "objetivo": domain,
        "puntuacion": nota,
        "suplantable": suplantable,
        "veredicto": veredicto,
        "resumen": {
            "altas": sum(1 for f in todos if f["severidad"] == "alta"),
            "medias": sum(1 for f in todos if f["severidad"] == "media"),
            "bajas": sum(1 for f in todos if f["severidad"] == "baja"),
        },
        "spf": {k: v for k, v in spf.items() if k != "findings"},
        "dmarc": {k: v for k, v in dmarc.items() if k != "findings"},
        "dkim": {k: v for k, v in dkim.items() if k != "findings"},
        "mx": mx,
        "recibe_correo": bool(mx),
        "hallazgos": todos,
        "aviso": "Análisis pasivo de DNS público. Comprueba solo dominios propios o autorizados.",
    }
