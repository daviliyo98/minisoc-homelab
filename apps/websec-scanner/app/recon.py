"""
recon — Reconocimiento pasivo de la superficie expuesta de un dominio.

  • Subdominios a partir de Certificate Transparency (crt.sh): cada certificado
    público emitido queda registrado, así que esto descubre hosts sin tocarlos.
  • Subdomain takeover: CNAMEs que apuntan a un servicio de terceros (S3, Heroku,
    GitHub Pages, Azure…) cuyo destino ya no existe (NXDOMAIN). Cualquiera
    podría registrar ese recurso y servir contenido bajo tu dominio.
  • Exposición de las IPs públicas con Shodan InternetDB (gratuito, sin clave):
    puertos abiertos y CVEs que Shodan asocia a los banners observados.

Ninguna petición llega al objetivo: solo se consulta DNS público, crt.sh y
Shodan. Ojo: el dominio consultado se comparte con esos dos terceros.
"""
from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import httpx

MAX_SUBDOMINIOS = 150
MAX_IPS = 25

# Sufijos de servicios con takeover documentado (can-i-take-over-xyz).
TAKEOVER_SERVICIOS = {
    "s3.amazonaws.com": "Amazon S3", "s3-website": "Amazon S3 (web)",
    "cloudfront.net": "Amazon CloudFront", "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure Cloud Services",
    "cloudapp.azure.com": "Azure", "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage", "azureedge.net": "Azure CDN",
    "github.io": "GitHub Pages", "gitlab.io": "GitLab Pages", "bitbucket.io": "Bitbucket",
    "netlify.app": "Netlify", "netlify.com": "Netlify", "vercel.app": "Vercel",
    "surge.sh": "Surge", "ghost.io": "Ghost", "myshopify.com": "Shopify",
    "pantheonsite.io": "Pantheon", "wordpress.com": "WordPress.com", "zendesk.com": "Zendesk",
    "readme.io": "ReadMe", "helpscoutdocs.com": "Help Scout", "unbouncepages.com": "Unbounce",
    "wpengine.com": "WP Engine", "fly.dev": "Fly.io", "webflow.io": "Webflow",
}

# Puertos que no deberían estar abiertos a Internet en una web corriente.
PUERTOS_SENSIBLES = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 135: "MS-RPC", 139: "NetBIOS",
    445: "SMB", 1433: "MS SQL", 1521: "Oracle", 2375: "Docker API", 2376: "Docker API (TLS)",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}
PUERTOS_WEB = {80, 443, 8080, 8443}

_RES = dns.resolver.Resolver()
_RES.lifetime = 5.0


def _limpiar(dominio: str) -> str:
    d = (dominio or "").strip().lower()
    if "://" in d:
        d = httpx.URL(d).host
    return d.strip(".").removeprefix("www.")


def subdominios_ct(dominio: str, timeout: float = 25.0) -> tuple[list[str], str | None]:
    """Nombres de host vistos en Certificate Transparency para el dominio."""
    datos, error = None, None
    # crt.sh devuelve 502/503 con frecuencia cuando está saturado: 3 intentos con espera.
    for intento in range(3):
        try:
            with httpx.Client(timeout=timeout, headers={"User-Agent": "MINISOC-websec-scanner/1.0"}) as c:
                r = c.get("https://crt.sh/", params={"q": f"%.{dominio}", "output": "json"})
                r.raise_for_status()
                datos = r.json()
                break
        except Exception as e:
            error = e
            time.sleep(2 + 3 * intento)
    if datos is None:
        return [], f"crt.sh no respondió ({type(error).__name__}); es habitual que esté saturado, reintenta más tarde."
    nombres: set[str] = set()
    for cert in datos:
        for n in str(cert.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.").strip(".")
            if n == dominio or n.endswith("." + dominio):
                nombres.add(n)
    return sorted(nombres), None


def _resolver(host: str) -> dict:
    out: dict = {"host": host, "cname": None, "ips": [], "nxdomain": False}
    try:
        ans = _RES.resolve(host, "CNAME")
        out["cname"] = str(ans[0].target).rstrip(".").lower()
    except Exception:
        pass
    try:
        out["ips"] = sorted({r.to_text() for r in _RES.resolve(host, "A")})
    except dns.resolver.NXDOMAIN:
        out["nxdomain"] = True
    except Exception:
        pass
    if out["cname"] and not out["ips"]:
        # ¿El destino del CNAME existe? NXDOMAIN en el destino = CNAME colgante.
        try:
            _RES.resolve(out["cname"], "A")
        except dns.resolver.NXDOMAIN:
            out["cname_nxdomain"] = True
        except Exception:
            pass
    return out


def internetdb(ip: str, timeout: float = 10.0) -> dict | None:
    """Datos de Shodan InternetDB para una IP pública (None si no hay datos)."""
    try:
        if not ipaddress.ip_address(ip).is_global:
            return None
        r = httpx.get(f"https://internetdb.shodan.io/{ip}", timeout=timeout)
        if r.status_code == 404:
            return {"ip": ip, "ports": [], "vulns": [], "cpes": [], "hostnames": [], "tags": []}
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def scan(dominio: str) -> dict:
    dom = _limpiar(dominio)
    if not dom or "." not in dom:
        return {"error": "Dominio no válido."}

    nombres, aviso_ct = subdominios_ct(dom)
    if dom not in nombres:
        nombres.insert(0, dom)
    truncado = len(nombres) > MAX_SUBDOMINIOS
    nombres = nombres[:MAX_SUBDOMINIOS]

    with ThreadPoolExecutor(max_workers=16) as ex:
        hosts = list(ex.map(_resolver, nombres))

    findings: list[dict] = []
    # --- Takeover / CNAME colgante ---
    for h in hosts:
        if not h.get("cname_nxdomain"):
            continue
        servicio = next((v for k, v in TAKEOVER_SERVICIOS.items() if k in h["cname"]), None)
        if servicio:
            findings.append({
                "id": "recon-takeover", "severidad": "alta",
                "titulo": f"Posible subdomain takeover en {h['host']}",
                "detalle": f"{h['host']} es un CNAME a {h['cname']} ({servicio}), que ya no existe (NXDOMAIN). "
                           "Un tercero podría reclamar ese recurso y servir contenido bajo tu dominio.",
                "remediacion": f"Eliminar el registro CNAME de {h['host']} o volver a crear el recurso en {servicio}.",
            })
        else:
            findings.append({
                "id": "recon-dangling-cname", "severidad": "media",
                "titulo": f"CNAME colgante en {h['host']}",
                "detalle": f"{h['host']} apunta a {h['cname']}, que no existe (NXDOMAIN).",
                "remediacion": "Eliminar el registro si ya no se usa, o corregir el destino.",
            })

    # --- Exposición por IP (Shodan InternetDB) ---
    ip_hosts: dict[str, list[str]] = {}
    for h in hosts:
        for ip in h["ips"]:
            ip_hosts.setdefault(ip, []).append(h["host"])
    ips = [ip for ip in ip_hosts if _es_global(ip)][:MAX_IPS]
    with ThreadPoolExecutor(max_workers=8) as ex:
        exposicion = [d for d in ex.map(internetdb, ips) if d]

    for d in exposicion:
        ip, puertos = d["ip"], d.get("ports") or []
        quien = ", ".join(ip_hosts.get(ip, [])[:4])
        sensibles = [f"{p}/{PUERTOS_SENSIBLES[p]}" for p in puertos if p in PUERTOS_SENSIBLES]
        otros = [p for p in puertos if p not in PUERTOS_SENSIBLES and p not in PUERTOS_WEB]
        if sensibles:
            findings.append({
                "id": "recon-sensitive-ports", "severidad": "media",
                "titulo": f"Servicios sensibles expuestos en {ip}",
                "detalle": f"{ip} ({quien}) expone a Internet: {', '.join(sensibles)}.",
                "remediacion": "Cerrar esos puertos en el cortafuegos o limitarlos a IPs de confianza/VPN.",
            })
        if otros:
            findings.append({
                "id": "recon-open-ports", "severidad": "informativo",
                "titulo": f"Otros puertos abiertos en {ip}",
                "detalle": f"{ip} ({quien}): {', '.join(map(str, otros))}.",
                "remediacion": "Verificar que cada servicio expuesto es necesario.",
            })
        if d.get("vulns"):
            cves = sorted(d["vulns"])
            findings.append({
                "id": "recon-known-cves", "severidad": "media",
                "titulo": f"{len(cves)} CVE(s) asociadas a {ip} según Shodan",
                "detalle": f"{ip} ({quien}): {', '.join(cves[:15])}{'…' if len(cves) > 15 else ''}. "
                           "Shodan las infiere por la versión del banner: hay que confirmarlas.",
                "remediacion": "Comprobar la versión real del software expuesto y actualizar/parchear.",
                "cve": cves,
            })

    return {
        "objetivo": dom,
        "subdominios": hosts,
        "total_subdominios": len(hosts),
        "truncado": truncado,
        "exposicion": exposicion,
        "hallazgos": findings,
        "avisos": [a for a in [aviso_ct] if a],
        "aviso": "Reconocimiento pasivo: datos de Certificate Transparency (crt.sh), DNS público y "
                 "Shodan InternetDB. No se envía ninguna petición al objetivo. El dominio consultado "
                 "se comparte con esos servicios.",
    }


def _es_global(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False
