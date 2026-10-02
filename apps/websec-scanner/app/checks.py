"""
Checks pasivos de postura de seguridad web.

Todo lo que hay aquí observa únicamente lo que el servidor expone
públicamente a cualquier visitante (cabeceras, certificado TLS,
security.txt). NO sondea rutas, NO prueba parámetros, NO ataca.
Es, en esencia, lo mismo que ve un navegador al abrir la página.
"""
from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

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


def _normalize(url: str) -> str:
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


async def check_http(url: str, timeout: float) -> dict:
    """Analiza las cabeceras HTTP de respuesta. Solo hace una petición GET."""
    url = _normalize(url)
    findings: list[dict] = []
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=True, verify=True, transport=_ipv4_transport()
    ) as client:
        r = await client.get(url, headers={"User-Agent": "MINISOC-websec-scanner/1.0"})

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
        if h in headers and headers[h].strip():
            findings.append({
                "severidad": "baja",
                "titulo": f"La cabecera {h} revela tecnología",
                "detalle": f"{h}: {headers[h]}",
                "remediacion": f"Ocultar o minimizar el valor de '{h}'.",
            })

    # Cookies sin flags de seguridad
    for cookie in r.headers.get_list("set-cookie"):
        low = cookie.lower()
        faltan = [f for f in ("secure", "httponly") if f not in low]
        if faltan:
            nombre = cookie.split("=", 1)[0]
            findings.append({
                "severidad": "media",
                "titulo": f"Cookie '{nombre}' sin flags {', '.join(faltan)}",
                "detalle": "Una cookie sin Secure/HttpOnly es más fácil de robar.",
                "remediacion": "Añadir los atributos Secure, HttpOnly y SameSite.",
            })

    return {
        "url_final": str(r.url),
        "status": r.status_code,
        "https": str(r.url).startswith("https://"),
        "findings": findings,
    }


def check_tls(hostname: str, timeout: float) -> dict:
    """Comprueba el certificado TLS: validez, caducidad y versión del protocolo."""
    findings: list[dict] = []
    ctx = ssl.create_default_context()
    try:
        # Forzar IPv4 (ver nota en _ipv4_transport): resolvemos solo direcciones A.
        addr = socket.getaddrinfo(hostname, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4]
        with socket.create_connection(addr, timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
    except Exception as e:
        return {"ok": False, "error": str(e), "findings": [{
            "severidad": "alta",
            "titulo": "No se pudo establecer TLS",
            "detalle": str(e),
            "remediacion": "Revisar que el puerto 443 y el certificado estén bien configurados.",
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
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, transport=_ipv4_transport()) as client:
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
