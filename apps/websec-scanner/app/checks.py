"""
Checks pasivos de postura de seguridad web.

Todo lo que hay aquí observa únicamente lo que el servidor expone
públicamente a cualquier visitante (cabeceras, certificado TLS,
security.txt). NO sondea rutas, NO prueba parámetros, NO ataca.
Es, en esencia, lo mismo que ve un navegador al abrir la página.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import httpx


class SsrfBloqueado(ValueError):
    """El objetivo resuelve a una IP interna/reservada: posible SSRF, se rechaza."""


def es_publico(host: str) -> bool:
    """True solo si TODAS las IPs a las que resuelve el host son públicas.

    Protección anti-SSRF: en vez de mirar el texto del host (que se puede eludir
    con DNS a una IP interna, codificaciones raras o IPv6), resolvemos el host y
    comprobamos cada IP. Bloquea 10.x/192.168.x, 127.x, 169.254.169.254 (metadata
    cloud), ::1, direcciones reservadas, multicast, etc.
    """
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    if not infos:
        return False
    for *_, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return False
    return True

# Forzar IPv4: la red interna de Docker (docker0) es solo IPv4. Si el host tiene
# conectividad IPv6 (p. ej. por el Router Advertisement del router ISP, ver HL-001),
# httpx intentaría primero la dirección IPv6 y fallaría con "Network is unreachable".
# local_address="0.0.0.0" ata el socket a IPv4 y evita ese intento.
def _ipv4_transport() -> httpx.AsyncHTTPTransport:
    return httpx.AsyncHTTPTransport(local_address="0.0.0.0")


# Cabeceras de seguridad recomendadas (referencia: OWASP Secure Headers Project)
SECURITY_HEADERS = {
    "strict-transport-security": "Fuerza HTTPS en el navegador (HSTS)",
    "content-security-policy": "Mitiga XSS e inyección de contenido (CSP)",
    "x-frame-options": "Evita clickjacking (embebido en iframes)",
    "x-content-type-options": "Evita MIME sniffing (debe ser 'nosniff')",
    "referrer-policy": "Controla la fuga de la URL de origen",
    "permissions-policy": "Restringe APIs del navegador (cámara, micro...)",
}

# Cabeceras que revelan tecnología/versión (fuga de información)
LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

# CDNs / proxies inversos que fijan su propio 'server' y no dejan cambiarlo (p. ej.
# Cloudflare en el plan gratuito). Sin número de versión no revelan nada que no
# se vea ya en el DNS, así que no se informan.
CDN_SERVERS = {"cloudflare", "cloudfront", "amazons3", "akamaighost", "akamainetstorage",
               "netlify", "vercel", "github.com", "gws", "esf", "gse", "sffe", "fastly",
               "bunnycdn", "keycdn", "azure front door", "microsoft-azure-application-gateway",
               "google frontend", "varnish", "ddos-guard", "sucuri/cloudproxy", "imperva"}


def _cabecera_inocua(nombre: str, valor: str) -> bool:
    """True si 'server' es solo el nombre de un CDN, sin versión."""
    v = valor.strip().lower()
    return nombre == "server" and not any(c.isdigit() for c in v) and (
        v in CDN_SERVERS or v.split("-")[0] in CDN_SERVERS)


def _normalize(url: str) -> str:
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


async def check_http(url: str, timeout: float) -> dict:
    """Analiza las cabeceras HTTP de respuesta.

    Sigue las redirecciones manualmente y valida que CADA salto apunta a una IP
    pública (anti-SSRF): una web pública podría redirigir a http://169.254.169.254/
    o a una IP interna, y no queremos que el scanner la siga.
    """
    url = _normalize(url)
    findings: list[dict] = []
    cur = url
    r = None
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, verify=True, transport=_ipv4_transport()
    ) as client:
        for _ in range(6):
            host = urlparse(cur).hostname or ""
            if not es_publico(host):
                raise SsrfBloqueado(f"Objetivo no permitido (interno o reservado): {host}")
            r = await client.get(cur, headers={"User-Agent": "MINISOC-websec-scanner/1.0"})
            loc = r.headers.get("location")
            if r.is_redirect and loc:
                cur = str(httpx.URL(cur).join(loc))
                continue
            break
    if r is None:
        raise SsrfBloqueado("No se pudo completar la petición.")

    headers = {k.lower(): v for k, v in r.headers.items()}

    # Cabeceras de seguridad ausentes
    for h, desc in SECURITY_HEADERS.items():
        if h not in headers:
            sev = "alta" if h in ("content-security-policy", "strict-transport-security") else "media"
            findings.append({
                "severidad": sev,
                "titulo": f"Falta la cabecera {h}",
                "detalle": desc,
                "remediacion": f"Añadir la cabecera de respuesta '{h}'.",
            })

    # X-Content-Type-Options con valor incorrecto
    if headers.get("x-content-type-options", "").lower() not in ("", "nosniff"):
        findings.append({
            "severidad": "baja",
            "titulo": "x-content-type-options con valor inesperado",
            "detalle": f"Valor actual: {headers['x-content-type-options']}",
            "remediacion": "Debe ser exactamente 'nosniff'.",
        })

    # Fugas de versión
    for h in LEAKY_HEADERS:
        if h in headers and headers[h].strip() and not _cabecera_inocua(h, headers[h]):
            findings.append({
                "severidad": "baja",
                "titulo": f"La cabecera {h} revela tecnología",
                "detalle": f"{h}: {headers[h]}",
                "remediacion": f"Ocultar o minimizar el valor de '{h}'.",
            })

    # Cookies sin flags de seguridad. Se analizan los ATRIBUTOS (tras el primer
    # ';'), no la cadena entera: una cookie llamada 'insecure_id' o cuyo valor
    # contenga "secure" no debe contar como si tuviera el flag.
    for cookie in r.headers.get_list("set-cookie"):
        attrs = {p.strip().split("=", 1)[0].lower() for p in cookie.split(";")[1:] if p.strip()}
        faltan = [f for f in ("secure", "httponly", "samesite") if f not in attrs]
        if faltan:
            nombre = cookie.split("=", 1)[0].strip()
            findings.append({
                "severidad": "media",
                "titulo": f"Cookie '{nombre}' sin flags {', '.join(faltan)}",
                "detalle": "Una cookie sin Secure/HttpOnly/SameSite es más fácil de robar o de usar en ataques CSRF.",
                "remediacion": "Añadir los atributos Secure, HttpOnly y SameSite.",
            })

    # CORS: comodín junto con credenciales (los navegadores lo rechazan, pero
    # delata una configuración que suele reflejar el Origin en otras rutas).
    acao = headers.get("access-control-allow-origin", "").strip()
    if acao == "*" and headers.get("access-control-allow-credentials", "").lower() == "true":
        findings.append({
            "id": "cors-wildcard-credentials",
            "severidad": "media",
            "titulo": "CORS permisivo con credenciales",
            "detalle": "Access-Control-Allow-Origin: * junto con Access-Control-Allow-Credentials: true.",
            "remediacion": "Limitar Access-Control-Allow-Origin a una lista blanca de orígenes de confianza.",
        })

    # Análisis del HTML devuelto (lo mismo que recibe un navegador)
    if "html" in headers.get("content-type", "").lower():
        findings += analizar_html(r.text[:1_000_000], str(r.url))

    # Calidad de HSTS (si está presente)
    hsts = headers.get("strict-transport-security", "").lower()
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        maxage = int(m.group(1)) if m else 0
        if maxage < 15552000:  # 6 meses
            findings.append({
                "severidad": "baja",
                "titulo": "HSTS con max-age bajo",
                "detalle": f"max-age={maxage}s. Un valor corto debilita la protección de HSTS.",
                "remediacion": "Usar al menos max-age=31536000 (1 año).",
            })
        if "includesubdomains" not in hsts:
            findings.append({
                "severidad": "baja",
                "titulo": "HSTS sin includeSubDomains",
                "detalle": "La protección HSTS no cubre los subdominios.",
                "remediacion": "Añadir 'includeSubDomains' si todos los subdominios usan HTTPS.",
            })

    # Calidad de CSP (si está presente): existir no basta, puede ser permisiva
    csp = headers.get("content-security-policy", "").lower()
    if csp:
        debiles = []
        if "'unsafe-inline'" in csp:
            debiles.append("'unsafe-inline'")
        if "'unsafe-eval'" in csp:
            debiles.append("'unsafe-eval'")
        if re.search(r"(default-src|script-src)[^;]*\*", csp):
            debiles.append("comodín '*'")
        if debiles:
            findings.append({
                "severidad": "media",
                "titulo": "CSP débil",
                "detalle": "La CSP existe pero permite: " + ", ".join(debiles) + " (reduce la protección frente a XSS).",
                "remediacion": "Evitar 'unsafe-inline'/'unsafe-eval' y comodines; usar nonces o hashes.",
            })

    return {
        "url_final": str(r.url),
        "status": r.status_code,
        "https": str(r.url).startswith("https://"),
        "cabeceras_seguridad": {h: (h in headers) for h in SECURITY_HEADERS},
        "findings": findings,
    }


_TAG_RE = re.compile(r"<(script|iframe|img|link|form|audio|video|source|embed|object)\b[^>]*>", re.I)
_ATTR_RE = re.compile(r"""\b(src|href|action|data|integrity|rel)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.I)


def _attrs(tag: str) -> dict[str, str]:
    return {m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or "") for m in _ATTR_RE.finditer(tag)}


# Terceros cuyos recursos son dinámicos o se autoactualizan por diseño y que NO
# admiten Subresource Integrity (SRI): Google Fonts adapta el CSS al navegador,
# y Google Tag Manager / gtag / Analytics son cargadores que cambian solos. Un
# integrity fijo rompería la carga y el proveedor no publica hashes, así que
# marcarlos sería un falso positivo. Ampliable con SRI_EXENTOS en el entorno.
SIN_SRI_NO_APLICABLE = {
    "fonts.googleapis.com",
    "www.googletagmanager.com", "googletagmanager.com",
    "www.google-analytics.com", "google-analytics.com", "ssl.google-analytics.com",
    "www.googleadservices.com",
}
_SRI_EXENTOS_EXTRA = {
    s.strip().lower() for s in os.getenv("SRI_EXENTOS", "").split(",") if s.strip()
}


def _sri_no_aplicable(host: str) -> bool:
    host = (host or "").lower()
    exentos = SIN_SRI_NO_APLICABLE | _SRI_EXENTOS_EXTRA
    return any(host == e or host.endswith("." + e) for e in exentos)


def analizar_html(html: str, url_pagina: str) -> list[dict]:
    """Contenido mixto y scripts externos sin SRI, a partir del HTML de la página."""
    findings: list[dict] = []
    host_pagina = (urlparse(url_pagina).hostname or "").lower()
    es_https = url_pagina.startswith("https://")
    mixto_activo, mixto_pasivo, sin_sri = set(), set(), set()
    for m in _TAG_RE.finditer(html):
        tag, nombre = m.group(0), m.group(1).lower()
        a = _attrs(tag)
        if nombre == "link" and "stylesheet" not in a.get("rel", "").lower():
            continue
        destino = a.get("src") or a.get("href") or a.get("action") or a.get("data") or ""
        if es_https and destino.lower().startswith("http://"):
            (mixto_pasivo if nombre in ("img", "audio", "video", "source") else mixto_activo).add(destino[:120])
        if nombre in ("script", "link") and destino:
            h = (urlparse(destino if "//" in destino else "").hostname or "").lower()
            if destino.startswith("//"):
                h = (urlparse("https:" + destino).hostname or "").lower()
            if h and h != host_pagina and not a.get("integrity") and not _sri_no_aplicable(h):
                sin_sri.add(h)
    if mixto_activo:
        findings.append({
            "id": "mixed-content-active", "severidad": "media",
            "titulo": "Contenido mixto activo (scripts/estilos/iframes por HTTP)",
            "detalle": "Recursos cargados sin cifrar en una página HTTPS: " + ", ".join(sorted(mixto_activo)[:5]),
            "remediacion": "Cargar todos los recursos por https:// (o añadir la directiva CSP upgrade-insecure-requests).",
        })
    if mixto_pasivo:
        findings.append({
            "id": "mixed-content-passive", "severidad": "baja",
            "titulo": "Contenido mixto pasivo (imágenes/multimedia por HTTP)",
            "detalle": "Recursos multimedia sin cifrar: " + ", ".join(sorted(mixto_pasivo)[:5]),
            "remediacion": "Servir también imágenes y multimedia por https://.",
        })
    if sin_sri:
        findings.append({
            "id": "no-sri", "severidad": "baja",
            "titulo": "Scripts/estilos de terceros sin SRI",
            "detalle": "Se cargan recursos externos sin atributo integrity desde: " + ", ".join(sorted(sin_sri)[:8])
                       + ". Si ese tercero se compromete, el código malicioso se ejecuta en tu web.",
            "remediacion": "Añadir integrity=\"sha384-…\" y crossorigin=\"anonymous\" a los recursos externos con versión fija.",
        })
    return findings


def check_caa(hostname: str) -> dict:
    """CAA (RFC 8659): limita qué autoridades pueden emitir certificados para el dominio.

    Solo lectura de DNS. Igual que hace una CA (RFC 8659 §3), se sube por el árbol
    DNS desde el host hasta el dominio de primer nivel: así funciona también con
    sufijos de varias etiquetas (.co.uk, .com.es) sin necesitar la Public Suffix List.
    """
    findings: list[dict] = []
    labels = hostname.strip(".").split(".")
    candidatos = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    encontrado = False
    for name in candidatos:
        try:
            if len(dns.resolver.resolve(name, "CAA", lifetime=5.0)) > 0:
                encontrado = True
                break
        except Exception:
            continue
    if not encontrado:
        findings.append({
            "severidad": "baja",
            "titulo": "Sin registro CAA",
            "detalle": "Cualquier autoridad de certificación puede emitir certificados para este dominio.",
            "remediacion": "Publicar un registro CAA que autorice solo a tu CA (p. ej. letsencrypt.org).",
        })
    return {"caa": encontrado, "findings": findings}


async def check_http_redirect(url: str, timeout: float) -> dict:
    """Comprueba que http:// redirige a https:// (una sola petición GET a http)."""
    host = urlparse(_normalize(url)).netloc
    findings: list[dict] = []
    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, transport=_ipv4_transport()
        ) as client:
            r = await client.get("http://" + host, headers={"User-Agent": "MINISOC-websec-scanner/1.0"})
        loc = r.headers.get("location", "")
        redirige = 300 <= r.status_code < 400 and loc.lower().startswith("https://")
    except Exception:
        return {"redirige_https": None, "findings": []}  # si http no responde, no concluimos
    if not redirige:
        findings.append({
            "severidad": "media",
            "titulo": "HTTP no redirige a HTTPS",
            "detalle": "Quien escriba la dirección sin https:// navega sin cifrado.",
            "remediacion": "Configurar una redirección 301 permanente de http:// a https://.",
        })
    return {"redirige_https": redirige, "findings": findings}


def check_tls(hostname: str, timeout: float, port: int = 443) -> dict:
    """Comprueba el certificado TLS: validez, caducidad y versión del protocolo."""
    findings: list[dict] = []
    ctx = ssl.create_default_context()
    try:
        # Forzar IPv4 (ver nota en _ipv4_transport): resolvemos solo direcciones A.
        addr = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)[0][4]
        # Anti-SSRF / DNS rebinding: la IP a la que conectamos también debe ser pública.
        if not ipaddress.ip_address(addr[0]).is_global:
            raise SsrfBloqueado(f"{hostname} resuelve a una IP no pública ({addr[0]}).")
        with socket.create_connection(addr, timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
    except Exception as e:
        return {"ok": False, "error": str(e), "findings": [{
            "severidad": "alta",
            "titulo": "No se pudo establecer TLS",
            "detalle": str(e),
            "remediacion": f"Revisar que el puerto {port} y el certificado estén bien configurados.",
        }]}

    # Caducidad del certificado
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    dias = (not_after - datetime.now(timezone.utc)).days
    if dias < 0:
        findings.append({"severidad": "alta", "titulo": "Certificado caducado",
                         "detalle": f"Caducó hace {abs(dias)} días.",
                         "remediacion": "Renovar el certificado de inmediato."})
    elif dias < 15:
        findings.append({"severidad": "media", "titulo": "Certificado a punto de caducar",
                         "detalle": f"Caduca en {dias} días.",
                         "remediacion": "Renovar el certificado y automatizar la renovación."})

    # Versión de protocolo obsoleta
    if version in ("TLSv1", "TLSv1.1"):
        findings.append({"severidad": "alta", "titulo": f"Protocolo obsoleto: {version}",
                         "detalle": "TLS 1.0/1.1 están en desuso e inseguros.",
                         "remediacion": "Permitir solo TLS 1.2 y 1.3."})

    return {"ok": True, "version": version, "dias_para_caducar": dias,
            "emisor": dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "?"),
            "findings": findings}


async def check_security_txt(url: str, timeout: float) -> dict:
    """Busca /.well-known/security.txt (RFC 9116).

    Si existe, la web declara CÓMO y A QUIÉN reportar fallos: es una
    invitación a la divulgación responsable. Si no existe, no hay invitación.
    """
    url = _normalize(url)
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    # Sin seguir redirecciones: evitamos que un redirect lleve la petición a un
    # destino interno (anti-SSRF). Solo nos interesa el security.txt del propio host.
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, transport=_ipv4_transport()) as client:
        for path in ("/.well-known/security.txt", "/security.txt"):
            try:
                r = await client.get(base + path)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            text = r.text
            ctype = r.headers.get("content-type", "").lower()
            # Validación RFC 9116: debe ser texto plano con un campo 'Contact:' al
            # inicio de una línea, y NO una página HTML (evita falsos positivos por
            # soft-404: servidores que devuelven su página de login para cualquier ruta).
            looks_html = "<html" in text.lower() or "<!doctype" in text.lower()
            has_contact = re.search(r"(?im)^\s*contact\s*:", text) is not None
            is_plain = "text/html" not in ctype
            if has_contact and is_plain and not looks_html:
                return {"existe": True, "ruta": path, "contenido": text[:2000]}
    return {"existe": False, "nota": "Sin security.txt válido: esta web no publica un canal de reporte."}
