"""
scanners — Lógica de los escaneos pasivos, independiente de HTTP.

La usan los endpoints de la API y el planificador de monitorización, de modo
que un escaneo programado da exactamente el mismo resultado que uno manual.
Los errores se comunican con ScanError(código_http, mensaje).
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx

from . import checks, dnsrecon, mailcheck, recon, severity

AVISO_PASIVO = ("Diagnóstico pasivo de la exposición pública de la web. Útil para detectar "
                "configuraciones ausentes o débiles, pero NO sustituye una auditoría interna "
                "del servidor ni una prueba de penetración (pentest). "
                "Escanee solo sistemas propios o autorizados.")


class ScanError(Exception):
    def __init__(self, status: int, mensaje: str):
        super().__init__(mensaje)
        self.status = status
        self.mensaje = mensaje


def puntuar(todos: list[dict]) -> int:
    """Puntuación 0–100 heredada (la UI la muestra), a partir de severidades ya corregidas por CVSS."""
    pen = {"alta": 20, "media": 8, "baja": 3}
    return max(0, 100 - sum(pen.get(f["severidad"], 0) for f in todos))


def completar(res: dict, servicio: str) -> dict:
    """Enriquece con CVSS, ordena y añade los resúmenes comunes."""
    severity.enrich(res["hallazgos"], servicio)
    res["hallazgos"].sort(key=lambda f: -(f.get("cvss_score") or 0.0))
    res["resumen"] = severity.resumen(res["hallazgos"])
    res["cvss_max"] = severity.cvss_max(res["hallazgos"])
    res["pago_por_hallazgo"] = severity.pago_por_hallazgo(res["hallazgos"])
    return res


def normalizar_url(url: str) -> str:
    if not urlparse(url).scheme:
        url = "https://" + url
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise ScanError(400, "Solo se admiten URLs http/https.")
    if not p.hostname:
        raise ScanError(400, "URL sin host válido.")
    return url


def dominio_de(url_o_dominio: str) -> str:
    v = url_o_dominio.strip()
    host = urlparse(v).hostname if "://" in v else v.split("/")[0]
    return (host or "").lower().strip(".").removeprefix("www.")


async def run_web(url: str, timeout: float = 10.0) -> dict:
    url = normalizar_url(url)
    p = urlparse(url)
    host = p.hostname or ""
    port = p.port or 443

    # Anti-SSRF: el host debe resolver SOLO a IPs públicas.
    if not checks.es_publico(host):
        raise ScanError(400, "Objetivo no permitido: resuelve a una dirección interna o reservada.")

    try:
        http_res = await checks.check_http(url, timeout)
    except checks.SsrfBloqueado as e:
        raise ScanError(400, str(e))
    except httpx.ConnectError:
        raise ScanError(502, "No se pudo conectar con el objetivo: el puerto puede estar cerrado o el host no acepta HTTPS.")
    except httpx.TimeoutException:
        raise ScanError(504, "El objetivo no respondió a tiempo.")
    except httpx.RequestError as e:
        raise ScanError(502, f"Error al contactar con el objetivo: {type(e).__name__}")

    final = urlparse(http_res["url_final"])
    if http_res["https"]:
        tls_host = final.hostname or host
        tls_port = final.port or (port if tls_host == host else 443)
        tls_res = await asyncio.to_thread(checks.check_tls, tls_host, timeout, tls_port)
    else:
        tls_res = {"ok": False, "nota": "Sin HTTPS, no se analiza TLS.", "findings": [{
            "severidad": "alta", "titulo": "El sitio no usa HTTPS",
            "detalle": "El tráfico viaja sin cifrar.",
            "remediacion": "Instalar un certificado y forzar HTTPS."}]}
    sectxt = await checks.check_security_txt(url, timeout)
    caa = await asyncio.to_thread(checks.check_caa, host)
    redir = await checks.check_http_redirect(url, timeout)

    todos = (http_res["findings"] + tls_res.get("findings", [])
             + caa["findings"] + redir["findings"])
    # Enriquecer con CVSS v3.1 (recalcula `severidad` de forma coherente).
    todos = severity.enrich(todos, "web")
    todos.sort(key=lambda f: -(f.get("cvss_score") or 0.0))

    cab = http_res.get("cabeceras_seguridad", {})
    nombres_cab = {
        "strict-transport-security": "HSTS", "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options", "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy",
    }
    rh = redir.get("redirige_https")
    comprobaciones = [
        {"nombre": "HTTPS", "estado": "ok" if http_res["https"] else "falta",
         "detalle": "activo" if http_res["https"] else "el sitio no cifra"},
        {"nombre": "Redirección HTTP→HTTPS",
         "estado": "ok" if rh else ("aviso" if rh is False else "info"),
         "detalle": "redirige" if rh else ("no redirige" if rh is False else "no comprobable")},
        {"nombre": "TLS", "estado": "ok" if tls_res.get("ok") else "falta",
         "detalle": (f"{tls_res.get('version', '')} · caduca en {tls_res.get('dias_para_caducar', '?')}d") if tls_res.get("ok") else "no disponible"},
    ]
    for h, label in nombres_cab.items():
        comprobaciones.append({"nombre": label, "estado": "ok" if cab.get(h) else "falta",
                               "detalle": "presente" if cab.get(h) else "ausente"})
    comprobaciones.append({"nombre": "CAA", "estado": "ok" if caa.get("caa") else "aviso",
                           "detalle": "presente" if caa.get("caa") else "sin CAA"})
    comprobaciones.append({"nombre": "security.txt", "estado": "ok" if sectxt.get("existe") else "info",
                           "detalle": sectxt.get("ruta", "no publicado") if sectxt.get("existe") else "no publicado"})
    ids = {f.get("id") for f in todos}
    comprobaciones.append({"nombre": "Contenido mixto",
                           "estado": "falta" if "mixed-content-active" in ids else ("aviso" if "mixed-content-passive" in ids else "ok"),
                           "detalle": "detectado" if ids & {"mixed-content-active", "mixed-content-passive"} else "no detectado"})
    comprobaciones.append({"nombre": "SRI en recursos externos", "estado": "aviso" if "no-sri" in ids else "ok",
                           "detalle": "faltan integrity" if "no-sri" in ids else "correcto o sin terceros"})

    return {
        "objetivo": http_res["url_final"],
        "puntuacion": puntuar(todos),
        "cvss_max": severity.cvss_max(todos),
        "comprobaciones": comprobaciones,
        "resumen": severity.resumen(todos),
        "pago_por_hallazgo": severity.pago_por_hallazgo(todos),
        "tls": {k: v for k, v in tls_res.items() if k != "findings"},
        "security_txt": sectxt,
        "caa": caa.get("caa"),
        "redirige_https": redir.get("redirige_https"),
        "hallazgos": todos,
        "aviso": AVISO_PASIVO,
    }


def run_mail(dominio: str) -> dict:
    return completar(mailcheck.scan(dominio), "correo")


def run_dns(dominio: str) -> dict:
    res = dnsrecon.scan(dominio)
    if res.get("error"):
        raise ScanError(400, res["error"])
    res = completar(res, "dns")
    res.setdefault("objetivo", res.get("dominio"))
    return res


def run_recon(dominio: str) -> dict:
    res = recon.scan(dominio)
    if res.get("error"):
        raise ScanError(400, res["error"])
    res = completar(res, "recon")
    res["puntuacion"] = puntuar(res["hallazgos"])
    return res


async def run_full(url: str, dominio: str | None = None) -> dict:
    """Web + correo + DNS en paralelo, con puntuación y CVSS globales."""
    url = normalizar_url(url)
    dom = dominio_de(dominio or url)
    web, mail, dnsr, rec = await asyncio.gather(
        run_web(url), asyncio.to_thread(run_mail, dom), asyncio.to_thread(run_dns, dom),
        asyncio.to_thread(run_recon, dom),
        return_exceptions=True)
    secciones, errores = {}, {}
    for nombre, r in (("web", web), ("correo", mail), ("dns", dnsr), ("recon", rec)):
        if isinstance(r, Exception):
            secciones[nombre] = None
            errores[nombre] = r.mensaje if isinstance(r, ScanError) else f"{type(r).__name__}: {r}"
        else:
            secciones[nombre] = r
    # Un problema que detectan dos módulos (SPF, DNSSEC, CAA) se queda solo en una sección:
    # la preferida si esa sección lo trae; si no (p. ej. falló), en la primera que lo tenga.
    donde: dict[str, str] = {}
    for nombre, s in secciones.items():
        for f in (s or {}).get("hallazgos", []):
            k = severity.identidad(f)
            if k not in donde or severity.SECCION_PREFERIDA.get(k) == nombre:
                donde[k] = nombre
    for nombre, s in secciones.items():
        if not s:
            continue
        propios, vistos = [], set()
        for f in s["hallazgos"]:
            k = severity.identidad(f)
            if donde[k] == nombre and k not in vistos:
                vistos.add(k)
                propios.append(f)
        s["hallazgos"] = propios
        s["resumen"] = severity.resumen(s["hallazgos"])
        s["cvss_max"] = severity.cvss_max(s["hallazgos"])
        s["pago_por_hallazgo"] = severity.pago_por_hallazgo(s["hallazgos"])
    validas = [s for s in secciones.values() if s]
    if not validas:
        raise ScanError(502, "Ningún análisis pudo completarse: " + "; ".join(f"{k}: {v}" for k, v in errores.items()))
    todos = [f for s in validas for f in s["hallazgos"]]
    return {
        "objetivo": dom,
        "url": url,
        "puntuacion": round(sum(s["puntuacion"] for s in validas) / len(validas)),
        "cvss_max": severity.cvss_max(todos),
        "resumen": severity.resumen(todos),
        "pago_por_hallazgo": severity.pago_por_hallazgo(todos),
        "secciones": secciones,
        "errores": errores,
        "aviso": AVISO_PASIVO,
    }


async def run_tipo(tipo: str, objetivo: str) -> dict:
    """Despacha por tipo (lo usa el planificador)."""
    if tipo == "web":
        return await run_web(objetivo)
    if tipo == "correo":
        return await asyncio.to_thread(run_mail, dominio_de(objetivo))
    if tipo == "dns":
        return await asyncio.to_thread(run_dns, dominio_de(objetivo))
    if tipo == "recon":
        return await asyncio.to_thread(run_recon, dominio_de(objetivo))
    if tipo == "full":
        return await run_full(objetivo)
    raise ScanError(400, f"Tipo de escaneo desconocido: {tipo}")
