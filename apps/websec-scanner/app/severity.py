"""
Capa de severidad CVSS v3.1 para el websec-scanner.

Unifica cómo se puntúan los hallazgos de todos los módulos (web, correo, DNS,
Nuclei, ZAP) con el estándar de la industria **CVSS v3.1**, y los clasifica en
los mismos tramos que usa la web de Almenasec:

    Crítica  CVSS 9.0 – 10.0
    Alta     CVSS 7.0 – 8.9
    Media    CVSS 4.0 – 6.9
    Baja     CVSS 0.1 – 3.9
    Info     CVSS 0.0        (buenas prácticas / defensa en profundidad; no se factura)

Diseño NO invasivo: este módulo no modifica los módulos que generan hallazgos.
`enrich()` recibe la lista de hallazgos tal cual y la enriquece: infiere el tipo
a partir del título, le asigna vector CVSS, puntuación, tramo, CWE y OWASP, y
recalcula el campo `severidad` (que consume la interfaz) de forma coherente.

Importante: las puntuaciones del catálogo son una **línea base** del tramo. En
un proyecto real, el vector CVSS se ajusta al contexto del activo (métricas de
entorno), igual que se indica en la web ("las tarifas exactas se acuerdan antes
de empezar"). Sirve para priorizar de forma consistente, no como veredicto final.
"""
from __future__ import annotations

import re

# --- Tramos de severidad (idénticos a los de la web) ---
TIERS = [
    (9.0, "critica", "Crítica"),
    (7.0, "alta", "Alta"),
    (4.0, "media", "Media"),
    (0.1, "baja", "Baja"),
    (0.0, "info", "Info"),
]


def tier_for(score: float) -> tuple[str, str]:
    """Devuelve (clave, etiqueta) del tramo CVSS para una puntuación 0.0–10.0."""
    for umbral, clave, etiqueta in TIERS:
        if score >= umbral:
            return clave, etiqueta
    return "info", "Info"


# La interfaz actual solo conoce estos valores de `severidad`. Mapeamos el tramo
# CVSS real a uno de ellos para no romper la UI (el tramo real va aparte, en
# `severidad_cvss`). Cuando la UI se actualice, podrá usar directamente el tramo.
_DISPLAY = {"critica": "alta", "alta": "alta", "media": "media",
            "baja": "baja", "info": "informativo"}

# Sinónimos de severidad que usan las herramientas externas (Nuclei, ZAP) o el
# código antiguo, para poder derivar el tramo cuando no hay entrada en catálogo.
_LABEL_TIER = {
    "critical": "critica", "critica": "critica", "crítica": "critica",
    "high": "alta", "alta": "alta",
    "medium": "media", "media": "media",
    "low": "baja", "baja": "baja",
    "info": "info", "informational": "info", "informativo": "info", "none": "info",
}

# Puntuación base representativa de cada tramo, para derivar un número cuando solo
# tenemos la etiqueta (p. ej. hallazgos de Nuclei/ZAP sin CVSS propio).
_TIER_SCORE = {"critica": 9.5, "alta": 8.0, "media": 5.5, "baja": 2.5, "info": 0.0}


def _c(score: float, vector: str, cwe: str, owasp: str, servicio: str = "web") -> dict:
    clave, etiqueta = tier_for(score)
    return {"cvss_score": score, "cvss": vector, "cwe": cwe, "owasp": owasp,
            "servicio": servicio, "severidad_cvss": clave, "severidad_cvss_label": etiqueta}


# --- Catálogo CVSS por tipo de hallazgo (módulo web) ---
# Las severidades corrigen el criterio anterior: la AUSENCIA de cabeceras de
# seguridad es defensa en profundidad (Baja/Info), no una vulnerabilidad Alta.
CATALOG: dict[str, dict] = {
    # Cabeceras de seguridad ausentes
    "missing-csp":          _c(3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "CWE-1021", "A05:2021 — Security Misconfiguration"),
    "missing-hsts":         _c(3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-319",  "A05:2021 — Security Misconfiguration"),
    "missing-xfo":          _c(4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "CWE-1021", "A05:2021 — Security Misconfiguration"),
    "missing-xcto":         _c(3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "CWE-430",  "A05:2021 — Security Misconfiguration"),
    "missing-referrer":     _c(0.0, "—", "CWE-200", "A05:2021 — Security Misconfiguration"),
    "missing-permissions":  _c(0.0, "—", "CWE-693", "A05:2021 — Security Misconfiguration"),
    "missing-header":       _c(0.0, "—", "CWE-693", "A05:2021 — Security Misconfiguration"),
    # Cabeceras con valor débil/incorrecto
    "xcto-invalid":         _c(3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "CWE-430",  "A05:2021 — Security Misconfiguration"),
    "hsts-weak-maxage":     _c(2.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-319",  "A05:2021 — Security Misconfiguration"),
    "hsts-no-subdomains":   _c(2.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-319",  "A05:2021 — Security Misconfiguration"),
    "csp-weak":             _c(4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", "CWE-79",   "A03:2021 — Injection (XSS)"),
    # Fugas de información
    "leaky-header":         _c(0.0, "—", "CWE-200", "A05:2021 — Security Misconfiguration"),
    # TLS / HTTPS
    "no-https":             _c(6.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N", "CWE-319",  "A02:2021 — Cryptographic Failures"),
    "no-https-redirect":    _c(3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-319",  "A02:2021 — Cryptographic Failures"),
    "tls-error":            _c(5.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", "CWE-295",  "A02:2021 — Cryptographic Failures"),
    "cert-expired":         _c(5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-295",  "A02:2021 — Cryptographic Failures"),
    "cert-expiring":        _c(0.0, "—", "CWE-324", "Operativo / buenas prácticas"),
    "tls-obsolete-proto":   _c(5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-327",  "A02:2021 — Cryptographic Failures"),
    # DNS / certificados
    "no-caa":               _c(0.0, "—", "CWE-295", "Buenas prácticas (RFC 8659)"),
}


def _infer_id(f: dict) -> str | None:
    """Deduce el identificador de catálogo a partir del hallazgo.

    Preferimos un campo `id` explícito si el hallazgo ya lo trae; si no, se
    infiere por el título (los títulos del scanner son estables).
    """
    if f.get("id"):
        return f["id"]
    t = (f.get("titulo") or "").lower()
    if t.startswith("falta la cabecera "):
        h = t.replace("falta la cabecera ", "").strip()
        return {
            "content-security-policy": "missing-csp",
            "strict-transport-security": "missing-hsts",
            "x-frame-options": "missing-xfo",
            "x-content-type-options": "missing-xcto",
            "referrer-policy": "missing-referrer",
            "permissions-policy": "missing-permissions",
        }.get(h, "missing-header")
    if "x-content-type-options con valor" in t: return "xcto-invalid"
    if "revela tecnología" in t:                return "leaky-header"
    if t.startswith("cookie "):                 return "cookie-flags"
    if "hsts con max-age" in t:                 return "hsts-weak-maxage"
    if "hsts sin includesubdomains" in t:       return "hsts-no-subdomains"
    if "csp débil" in t:                        return "csp-weak"
    if "sin registro caa" in t:                 return "no-caa"
    if "http no redirige" in t:                 return "no-https-redirect"
    if "no se pudo establecer tls" in t:        return "tls-error"
    if "certificado caducado" in t:             return "cert-expired"
    if "a punto de caducar" in t:               return "cert-expiring"
    if t.startswith("protocolo obsoleto"):      return "tls-obsolete-proto"
    if "no usa https" in t:                     return "no-https"
    # --- Correo (mailcheck.py) ---
    if "no existe registro spf" in t:           return "mail-no-spf"
    if "varios registros spf" in t:             return "mail-spf-multiple"
    if "spf permite a cualquiera" in t:         return "mail-spf-plusall"
    if "spf no es restrictivo" in t:            return "mail-spf-weak"
    if "demasiadas búsquedas dns" in t:         return "mail-spf-lookups"
    if "no existe registro dmarc" in t:         return "mail-no-dmarc"
    if "dmarc solo en modo observación" in t:   return "mail-dmarc-none"
    if "dmarc en cuarentena" in t:              return "mail-dmarc-quarantine"
    if "dmarc sin informes" in t:               return "mail-dmarc-no-rua"
    if "se aplica solo al" in t:                return "mail-dmarc-pct"
    if "subdominios sin protección" in t:       return "mail-dmarc-sp-none"
    if "no se detectó dkim" in t:               return "mail-no-dkim"
    if "sin mta-sts" in t:                      return "mail-no-mta-sts"
    if "sin tls-rpt" in t:                      return "mail-no-tls-rpt"
    if "dominio sin dnssec" in t:               return "mail-no-dnssec"
    if "sin bimi" in t:                         return "mail-no-bimi"
    # --- DNS (dnsrecon.py) ---
    if "un solo servidor de nombres" in t:      return "dns-single-ns"
    if "sin redundancia real" in t:             return "dns-ns-same-ip"
    if "en la misma red" in t:                  return "dns-ns-same-net"
    if "correo y web en el mismo servidor" in t: return "dns-colocated"
    if "sin registro spf" in t:                 return "dns-no-spf"
    if "spf permisivo" in t:                    return "dns-spf-plusall"
    if "dnssec no habilitado" in t:             return "dns-no-dnssec"
    if "sin registro caa" in t:                 return "no-caa"
    return None


# cookie-flags no está arriba porque su CWE depende del flag; se resuelve aquí.
CATALOG["cookie-flags"] = _c(5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                             "CWE-614", "A05:2021 — Security Misconfiguration")

# --- Catálogo CORREO (suplantación: SPF/DKIM/DMARC/MTA-STS/DNSSEC/BIMI) ---
_SPOOF = "A07:2021 — Identification and Authentication Failures"
CATALOG.update({
    "mail-no-spf":            _c(6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", "CWE-290", _SPOOF, "correo"),
    "mail-spf-multiple":      _c(5.9, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", "CWE-290", _SPOOF, "correo"),
    "mail-spf-plusall":       _c(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N", "CWE-290", _SPOOF, "correo"),
    "mail-spf-weak":          _c(5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", "CWE-290", _SPOOF, "correo"),
    "mail-spf-lookups":       _c(5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", "CWE-290", _SPOOF, "correo"),
    "mail-no-dmarc":          _c(6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", "CWE-290", _SPOOF, "correo"),
    "mail-dmarc-none":        _c(5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", "CWE-290", _SPOOF, "correo"),
    "mail-dmarc-quarantine":  _c(2.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", "CWE-290", _SPOOF, "correo"),
    "mail-dmarc-no-rua":      _c(0.0, "—", "CWE-778", "A09:2021 — Security Logging and Monitoring Failures", "correo"),
    "mail-dmarc-pct":         _c(4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", "CWE-290", _SPOOF, "correo"),
    "mail-dmarc-sp-none":     _c(5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", "CWE-290", _SPOOF, "correo"),
    "mail-no-dkim":           _c(2.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", "CWE-290", _SPOOF, "correo"),
    "mail-no-mta-sts":        _c(3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-319", "A02:2021 — Cryptographic Failures", "correo"),
    "mail-no-tls-rpt":        _c(0.0, "—", "CWE-778", "A09:2021 — Security Logging and Monitoring Failures", "correo"),
    "mail-no-dnssec":         _c(3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", "CWE-345", "A02:2021 — Cryptographic Failures", "correo"),
    "mail-no-bimi":           _c(0.0, "—", "—", "Marca / buenas prácticas", "correo"),
})

# --- Catálogo DNS (infraestructura: redundancia, colocación, SPF a alto nivel) ---
CATALOG.update({
    "dns-single-ns":          _c(4.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", "CWE-1104", "Disponibilidad / buenas prácticas", "dns"),
    "dns-ns-same-ip":         _c(4.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", "CWE-1104", "Disponibilidad / buenas prácticas", "dns"),
    "dns-ns-same-net":        _c(2.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", "CWE-1104", "Disponibilidad / buenas prácticas", "dns"),
    "dns-colocated":          _c(2.0, "—", "CWE-1188", "Separación de servicios / buenas prácticas", "dns"),
    "dns-no-spf":             _c(6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", "CWE-290", _SPOOF, "dns"),
    "dns-spf-plusall":        _c(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N", "CWE-290", _SPOOF, "dns"),
    "dns-no-dnssec":          _c(3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", "CWE-345", "A02:2021 — Cryptographic Failures", "dns"),
})

# --- Catálogo WEB-APP (reconocimiento activo-ligero: ficheros y WordPress) ---
_MISCONF = "A05:2021 — Security Misconfiguration"
CATALOG.update({
    "web-git-exposed":    _c(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-527", _MISCONF),
    "web-env-exposed":    _c(9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-200", _MISCONF),
    "web-config-backup":  _c(9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", "CWE-530", _MISCONF),
    "web-backup-exposed": _c(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-530", _MISCONF),
    "web-info-files":     _c(3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-200", _MISCONF),
    "web-no-securitytxt": _c(0.0, "—", "CWE-1059", "RFC 9116 / buenas prácticas"),
    "wp-detected":        _c(0.0, "—", "CWE-200", "Fingerprinting / informativo"),
    "wp-user-enum":       _c(5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-204", _SPOOF),
    "wp-xmlrpc":          _c(5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", "CWE-799", _MISCONF),
    "wp-login-exposed":   _c(0.0, "—", "CWE-307", _MISCONF),
    "tls-proto-obsoleto": _c(5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-327", "A02:2021 — Cryptographic Failures", "tls"),
    "tls-cifrado-debil":  _c(5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-327", "A02:2021 — Cryptographic Failures", "tls"),
})


# --- Catálogo de checks web añadidos (HTML, CORS) ---
CATALOG.update({
    "cors-wildcard-credentials": _c(5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "CWE-942", "A05:2021 — Security Misconfiguration"),
    "mixed-content-active":   _c(4.8, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", "CWE-319", "A02:2021 — Cryptographic Failures"),
    "mixed-content-passive":  _c(2.6, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "CWE-319", "A02:2021 — Cryptographic Failures"),
    "no-sri":                 _c(2.6, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", "CWE-353", "A08:2021 — Software and Data Integrity Failures"),
})

# --- Catálogo RECON (exposición: subdominios, puertos, takeover) ---
CATALOG.update({
    "recon-takeover":         _c(8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N", "CWE-284", "A05:2021 — Security Misconfiguration", "recon"),
    "recon-dangling-cname":   _c(5.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", "CWE-284", "A05:2021 — Security Misconfiguration", "recon"),
    "recon-sensitive-ports":  _c(5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "CWE-668", "A05:2021 — Security Misconfiguration", "recon"),
    "recon-open-ports":       _c(0.0, "—", "CWE-668", "Superficie de exposición / inventario", "recon"),
    "recon-known-cves":       _c(6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "CWE-1104", "A06:2021 — Vulnerable and Outdated Components", "recon"),
})

# --- Notas de operatividad / rotura ---------------------------------------- #
# Avisos de "ojo, esto puede romper algo" o de contexto, para que la remediación
# sea aplicable en el mundo real y no un consejo naíf.
NOTAS_OPERATIVAS = {
    "cookie-flags": "Si a la cookie solo le falta HttpOnly y algún plugin la lee por JavaScript "
                    "(p. ej. Polylang en WordPress), activar HttpOnly puede romper su funcionamiento: "
                    "comprueba primero qué cookie es. Secure y SameSite deben ir siempre.",
    "missing-csp": "Despliega la CSP primero en Content-Security-Policy-Report-Only para recoger "
                   "violaciones sin romper la web; cuando el informe esté limpio, pásala a modo enforce.",
    "csp-weak": "Ajusta la CSP en Report-Only antes de endurecerla, para no bloquear por error recursos "
                "legítimos (fuentes, analítica, mapas).",
    "missing-hsts": "Activa HSTS solo cuando TODO el dominio (y, con includeSubDomains/preload, los "
                    "subdominios) sirva por HTTPS verificado; si no, dejarías recursos inaccesibles. "
                    "Envía a la lista preload solo tras unas semanas estable.",
    "no-caa": "Incluye en el CAA la CA que emite tus certificados (p. ej. letsencrypt.org); si falta, "
              "las renovaciones automáticas fallarán.",
    "leaky-header": "En muchos hostings compartidos o detrás de un CDN esta cabecera no es configurable; "
                    "si es tu caso, documéntalo como riesgo asumido en lugar de intentar quitarla.",
    "mail-no-dmarc": "Sube la política por fases (none → quarantine → reject) revisando los informes rua "
                     "en cada una. Saltar directo a p=reject puede bloquear correo legítimo (newsletters, "
                     "formularios, terceros).",
    "mail-dmarc-none": "No pases de golpe a p=reject: sube a p=quarantine, revisa los informes rua 2-4 "
                       "semanas y, cuando no haya falsos positivos, a p=reject.",
}

# --- Prioridad por riesgo explotable (plan de remediación) ------------------ #
# P0 = explotable / impacto directo ya · P1 = endurecer pronto · P2 = defensa en
# profundidad a medio/largo plazo. Por defecto se deriva del CVSS, con ajustes
# que reflejan la explotabilidad real (no solo la puntuación).
_PRIORIDAD_OVERRIDE = {
    "wp-user-enum": "P0",
    "mail-spf-plusall": "P0", "dns-spf-plusall": "P0",
    "wp-xmlrpc": "P1",
    "mail-no-dmarc": "P1", "mail-dmarc-none": "P1",
    "mail-no-spf": "P1", "dns-no-spf": "P1", "mail-spf-weak": "P1",
    "csp-weak": "P1",
    "mail-no-mta-sts": "P2", "mail-no-tls-rpt": "P2",
    "mail-no-dnssec": "P2", "dns-no-dnssec": "P2", "no-caa": "P2",
    "missing-referrer": "P2", "missing-permissions": "P2",
    "mail-no-bimi": "P2", "mail-dmarc-no-rua": "P2",
    "web-info-files": "P2", "web-no-securitytxt": "P2",
    "wp-login-exposed": "P2", "wp-detected": "P2",
    "leaky-header": "P2", "cert-expiring": "P2",
}


# Detecciones puras (tecnología/WAF/certificado/versiones) que NO son hallazgos:
# van a una sección "Inventario", fuera de los hallazgos y sin facturar.
_INVENTARIO_IDS = {"wp-detected"}
_INV_KEYWORDS = ("detection", "detect", "wappalyzer", "technology", "issuer",
                 "dns names", "wildcard", "tls version")


def es_inventario(f: dict, servicio: str = "") -> bool:
    if f.get("id") in _INVENTARIO_IDS:
        return True
    if f.get("severidad_cvss") != "info":
        return False
    titulo = (f.get("titulo") or "").lower()
    es_nuclei = f.get("origen") == "nuclei" or servicio in ("activo", "nuclei")
    return es_nuclei or any(k in titulo for k in _INV_KEYWORDS)


def prioridad_de(fid, cvss_score: float) -> str:
    if fid and fid in _PRIORIDAD_OVERRIDE:
        return _PRIORIDAD_OVERRIDE[fid]
    if cvss_score >= 7.0:
        return "P0"
    if cvss_score >= 4.0:
        return "P1"
    return "P2"


def enrich(findings: list[dict], servicio: str = "web") -> list[dict]:
    """Enriquece cada hallazgo con CVSS v3.1, tramo, CWE, OWASP y servicio.

    - Si el hallazgo está en el catálogo, usa su puntuación/vector y RECALCULA
      `severidad` de forma coherente (corrige severidades infladas).
    - Si no (p. ej. Nuclei/ZAP), deriva el tramo de la etiqueta existente y, si
      el hallazgo ya trae CVSS propio en `cvss_score`, lo respeta.
    Devuelve la misma lista (modificada in situ) para encadenar.
    """
    for f in findings:
        fid = _infer_id(f)
        meta = CATALOG.get(fid) if fid else None
        if meta:
            f.setdefault("id", fid)
            f["cvss"] = meta["cvss"]
            f["cvss_score"] = meta["cvss_score"]
            f["cwe"] = meta["cwe"]
            f["owasp"] = meta["owasp"]
            f["servicio"] = meta.get("servicio", servicio)
            f["severidad_cvss"] = meta["severidad_cvss"]
            f["severidad_cvss_label"] = meta["severidad_cvss_label"]
            f["severidad"] = _DISPLAY[meta["severidad_cvss"]]
        else:
            # Sin catálogo: deriva de la etiqueta que ya trae el hallazgo.
            clave = _LABEL_TIER.get(str(f.get("severidad", "")).lower(), "info")
            f["servicio"] = f.get("servicio", servicio)
            f["severidad_cvss"] = clave
            f["severidad_cvss_label"] = dict((k, v) for _, k, v in TIERS).get(clave, "Info")
            if f.get("cvss_score") is None:
                f["cvss_score"] = round(_TIER_SCORE.get(clave, 0.0), 1)
            f.setdefault("cvss", "—")
            f["severidad"] = _DISPLAY[clave]
        f["prioridad"] = prioridad_de(fid, f.get("cvss_score") or 0.0)
        if fid and fid in NOTAS_OPERATIVAS:
            f.setdefault("nota_operativa", NOTAS_OPERATIVAS[fid])
        if es_inventario(f, servicio):
            f["inventario"] = True
    return findings


# El mismo problema detectado por dos módulos del escaneo completo (el módulo DNS
# repite a alto nivel SPF, DNSSEC y CAA). Comparten identidad para no listarse ni
# cobrarse dos veces. SECCION_PREFERIDA dice en qué sección se queda.
_MISMO_PROBLEMA = {
    "mail-no-spf": "spf-ausente", "dns-no-spf": "spf-ausente",
    "mail-spf-plusall": "spf-plusall", "dns-spf-plusall": "spf-plusall",
    "mail-no-dnssec": "dnssec", "dns-no-dnssec": "dnssec",
    "no-caa": "caa",
}
SECCION_PREFERIDA = {"spf-ausente": "correo", "spf-plusall": "correo", "dnssec": "dns", "caa": "dns"}


def identidad(f: dict) -> str:
    """Identidad estable de un hallazgo (entre módulos y entre escaneos)."""
    comun = _MISMO_PROBLEMA.get(f.get("id") or "")
    return comun or f"{f.get('servicio', '')}|{f.get('titulo', '')}"


def resumen(findings: list[dict]) -> dict:
    """Recuento por el valor de `severidad` que muestra la interfaz."""
    def n(s): return sum(1 for f in findings if f.get("severidad") == s)
    return {"altas": n("alta"), "medias": n("media"),
            "bajas": n("baja"), "informativos": n("informativo")}


def pago_por_hallazgo(findings: list[dict]) -> dict:
    """Recuento por tramo CVSS real, listo para la tabla de precios.

    Los hallazgos Info (defensa en profundidad / buenas prácticas) NO se
    facturan — coherente con la web ("los informativos no se cobran").
    """
    def n(t): return sum(1 for f in findings if f.get("severidad_cvss") == t)
    criticas, altas, medias, bajas, info = n("critica"), n("alta"), n("media"), n("baja"), n("info")
    return {
        "criticas": criticas, "altas": altas, "medias": medias,
        "bajas": bajas, "info": info,
        "facturables": criticas + altas + medias + bajas,
        "nota": "Tarifados por severidad (CVSS v3.1). Los hallazgos Info no se facturan.",
    }


def cvss_max(findings: list[dict]) -> float:
    """Mayor puntuación CVSS presente (0.0 si no hay hallazgos puntuables)."""
    return max((f.get("cvss_score") or 0.0) for f in findings) if findings else 0.0
