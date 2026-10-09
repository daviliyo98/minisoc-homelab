"""
mailcheck — Análisis PASIVO de la postura de seguridad del CORREO de un dominio.

Responde a una pregunta de negocio: "¿Pueden suplantar este dominio para enviar
correo en su nombre?" (p. ej. facturas falsas a sus clientes).

Observa SOLO registros DNS públicos: SPF, DKIM, DMARC y MX. No envía correo ni
interactúa con el servidor de correo. Es, como el resto del scanner, pasivo.

Referencias: RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC).
"""
from __future__ import annotations

import re
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
def _all_qualifier(rec_low: str) -> str | None:
    """Devuelve el cualificador del mecanismo 'all' de un registro SPF, si lo hay."""
    for q in ("-all", "~all", "?all", "+all"):
        if q in rec_low:
            return q
    return None


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
    qual = _all_qualifier(rec)
    delegado = None
    # Si el registro no trae 'all' propio pero delega con 'redirect=', seguimos un
    # salto y leemos la política efectiva del destino (p. ej. gmail -> _spf.google.com).
    if qual is None:
        m = re.search(r"redirect=([^\s]+)", rec)
        if m:
            delegado = m.group(1).rstrip(".")
            tgt = [t for t in _txt(delegado) if t.lower().startswith("v=spf1")]
            if tgt:
                qual = _all_qualifier(tgt[0].lower())

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

    # Nº de búsquedas DNS: el RFC 7208 limita a 10. Pasarse provoca 'permerror'
    # y muchos receptores lo tratan como si no hubiera SPF.
    lookups = 0
    for tok in rec.split():
        t = tok.lstrip("+-~?").lower()
        if (t.startswith(("include:", "exists:", "redirect=", "a:", "a/", "mx:", "mx/"))
                or t in ("a", "mx", "ptr")):
            lookups += 1
    if lookups > 10:
        findings.append({
            "severidad": "media",
            "titulo": f"SPF con demasiadas búsquedas DNS ({lookups} > 10)",
            "detalle": "Superar 10 búsquedas invalida el SPF (permerror, RFC 7208) y deja de proteger.",
            "remediacion": "Reducir los 'include:' o aplanar el registro (SPF flattening).",
        })

    return {"presente": True, "cualificador": qual, "delegado_en": delegado,
            "busquedas_dns": lookups, "registro": records[0], "findings": findings}


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

    # pct<100: la política solo se aplica a una parte del correo (el resto pasa).
    pct = tags.get("pct", "")
    if policy in ("quarantine", "reject") and pct.isdigit() and int(pct) < 100:
        findings.append({
            "severidad": "media",
            "titulo": f"DMARC se aplica solo al {pct}% del correo (pct={pct})",
            "detalle": "Con pct<100 la política solo afecta a una parte: el resto del correo suplantado pasa.",
            "remediacion": "Subir pct a 100 cuando los informes estén limpios.",
        })

    # sp=none: los subdominios quedan sin política aunque el dominio sí la tenga.
    if policy in ("quarantine", "reject") and tags.get("sp", "").lower() == "none":
        findings.append({
            "severidad": "media",
            "titulo": "Subdominios sin protección (sp=none)",
            "detalle": "La política de subdominios es 'none': se puede suplantar correo desde cualquier subdominio.",
            "remediacion": "Quitar sp=none o igualarla a la política principal (p. ej. sp=reject).",
        })

    return {"presente": True, "politica": policy, "rua": has_rua,
            "subdominios": tags.get("sp"), "pct": tags.get("pct", "100"),
            "registro": rec, "findings": findings}


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
#  Cifrado y verificación del transporte de correo (pasivo, solo DNS)
# --------------------------------------------------------------------------- #
def check_mta_sts(domain: str, tiene_mx: bool) -> dict:
    """MTA-STS (RFC 8461): exige que el correo ENTRANTE llegue cifrado por TLS."""
    recs = [t for t in _txt(f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]
    findings: list[dict] = []
    if tiene_mx and not recs:
        findings.append({
            "severidad": "baja",
            "titulo": "Sin MTA-STS",
            "detalle": "No se exige cifrado TLS al correo entrante: un atacante en la red podría degradar la conexión.",
            "remediacion": "Publicar el registro _mta-sts y la política en https://mta-sts.<dominio>/.well-known/mta-sts.txt.",
        })
    return {"presente": bool(recs), "findings": findings}


def check_tls_rpt(domain: str, tiene_mx: bool) -> dict:
    """TLS-RPT (RFC 8460): informes de fallos de cifrado en la entrega de correo."""
    recs = [t for t in _txt(f"_smtp._tls.{domain}") if t.lower().startswith("v=tlsrptv1")]
    findings: list[dict] = []
    if tiene_mx and not recs:
        findings.append({
            "severidad": "baja",
            "titulo": "Sin TLS-RPT",
            "detalle": "No recibes informes cuando falla el cifrado TLS al entregar tu correo: pierdes visibilidad.",
            "remediacion": "Publicar _smtp._tls.<dominio> con v=TLSRPTv1 y un destino rua de informes.",
        })
    return {"presente": bool(recs), "findings": findings}


def check_dnssec(domain: str) -> dict:
    """DNSSEC: firma criptográfica del DNS. Sin él, las respuestas se pueden falsificar."""
    try:
        firmado = len(_RESOLVER.resolve(domain, "DNSKEY")) > 0
    except Exception:
        firmado = False
    findings: list[dict] = []
    if not firmado:
        findings.append({
            "severidad": "baja",
            "titulo": "Dominio sin DNSSEC",
            "detalle": "Sin DNSSEC las respuestas DNS no están firmadas y pueden falsificarse (cache poisoning).",
            "remediacion": "Activar DNSSEC en el registrador o proveedor de DNS.",
        })
    return {"dnssec": firmado, "findings": findings}


def check_bimi(domain: str, dmarc_enforced: bool) -> dict:
    """BIMI: muestra el logo de marca en la bandeja. Solo tiene sentido con DMARC activo."""
    recs = [t for t in _txt(f"default._bimi.{domain}") if t.lower().startswith("v=bimi1")]
    findings: list[dict] = []
    if dmarc_enforced and not recs:
        findings.append({
            "severidad": "baja",
            "titulo": "Oportunidad: sin BIMI",
            "detalle": "Ya tienes DMARC activo; BIMI mostraría tu logo junto a tus correos (más confianza y marca).",
            "remediacion": "Publicar default._bimi.<dominio> con la URL de tu logo SVG (y, opcionalmente, un VMC).",
        })
    return {"presente": bool(recs), "findings": findings}


# --------------------------------------------------------------------------- #
#  Agregado + veredicto de suplantación
# --------------------------------------------------------------------------- #
def scan(domain: str) -> dict:
    domain = _clean_domain(domain)
    spf = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim = check_dkim(domain)
    mx = _mx(domain)
    tiene_mx = bool(mx)
    dmarc_enforced = dmarc.get("presente") and dmarc.get("politica") in ("quarantine", "reject")
    mta_sts = check_mta_sts(domain, tiene_mx)
    tls_rpt = check_tls_rpt(domain, tiene_mx)
    dnssec = check_dnssec(domain)
    bimi = check_bimi(domain, dmarc_enforced)

    todos = (spf["findings"] + dmarc["findings"] + dkim["findings"]
             + mta_sts["findings"] + tls_rpt["findings"] + dnssec["findings"] + bimi["findings"])
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

    # Resultado concreto de CADA comprobación (lo que pasa y lo que falta),
    # no solo los hallazgos. estado: ok | aviso | falta | info
    comprobaciones = [
        {"nombre": "SPF", "detalle": (spf.get("cualificador") or "sin all") if spf["presente"] else "no publicado",
         "estado": "ok" if (spf["presente"] and spf.get("cualificador") in ("-all", "~all"))
                   else ("aviso" if spf["presente"] else "falta")},
        {"nombre": "DKIM", "detalle": ("selector: " + ", ".join(dkim["selectores"])) if dkim["detectado"] else "no detectado (no concluyente)",
         "estado": "ok" if dkim["detectado"] else "info"},
        {"nombre": "DMARC", "detalle": ("p=" + dmarc["politica"]) if dmarc["presente"] else "no publicado",
         "estado": ("ok" if dmarc.get("politica") == "reject" else "aviso") if dmarc["presente"] else "falta"},
        {"nombre": "Informes DMARC (rua)", "detalle": "configurado" if dmarc.get("rua") else "sin rua",
         "estado": ("ok" if dmarc.get("rua") else "falta") if dmarc["presente"] else "info"},
        {"nombre": "Recepción de correo (MX)", "detalle": "recibe correo" if tiene_mx else "sin MX",
         "estado": "ok" if tiene_mx else "info"},
        {"nombre": "MTA-STS", "detalle": "activo" if mta_sts["presente"] else "no configurado",
         "estado": "ok" if mta_sts["presente"] else ("falta" if tiene_mx else "info")},
        {"nombre": "TLS-RPT", "detalle": "activo" if tls_rpt["presente"] else "no configurado",
         "estado": "ok" if tls_rpt["presente"] else ("falta" if tiene_mx else "info")},
        {"nombre": "DNSSEC", "detalle": "firmado" if dnssec["dnssec"] else "sin firmar",
         "estado": "ok" if dnssec["dnssec"] else "aviso"},
        {"nombre": "BIMI", "detalle": "configurado" if bimi["presente"] else ("oportunidad" if dmarc_enforced else "requiere DMARC activo"),
         "estado": "ok" if bimi["presente"] else "info"},
    ]

    return {
        "objetivo": domain,
        "puntuacion": nota,
        "comprobaciones": comprobaciones,
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
        "mta_sts": {k: v for k, v in mta_sts.items() if k != "findings"},
        "tls_rpt": {k: v for k, v in tls_rpt.items() if k != "findings"},
        "dnssec": dnssec["dnssec"],
        "bimi": {k: v for k, v in bimi.items() if k != "findings"},
        "mx": mx,
        "recibe_correo": bool(mx),
        "hallazgos": todos,
        "aviso": "Análisis pasivo de DNS público. Comprueba solo dominios propios o autorizados.",
    }
