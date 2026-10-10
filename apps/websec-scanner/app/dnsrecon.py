"""
dnsrecon — Reconocimiento DNS pasivo de un dominio.

Consulta los registros públicos del DNS (A, AAAA, MX, NS, SOA, TXT, CAA) y
analiza la POSTURA de infraestructura: redundancia de los servidores de
nombres, si el correo comparte servidor con la web, presencia de CAA/DNSSEC,
etc. Es 100% pasivo: solo pregunta a los DNS públicos, NO toca el servidor
del objetivo (ni fail2ban ni WAF se enteran).

La postura de SUPLANTACIÓN de correo (SPF/DKIM/DMARC en detalle) la cubre
mailcheck.py; aquí solo señalamos el SPF a alto nivel y remitimos a esa
comprobación para el detalle.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

import dns.resolver


def _limpiar_dominio(valor: str) -> str:
    """Admite que llegue una URL o un dominio con espacios/mayúsculas."""
    valor = (valor or "").strip()
    if "://" in valor:
        valor = urlparse(valor).hostname or valor
    return valor.strip().strip(".").lower()


def _q(dominio: str, tipo: str) -> list[str]:
    """Consulta un tipo de registro; devuelve lista de cadenas (o vacío)."""
    try:
        resp = dns.resolver.resolve(dominio, tipo, lifetime=6.0)
    except Exception:
        return []
    out: list[str] = []
    for r in resp:
        out.append(r.to_text().strip())
    return out


def _ips_de(host: str) -> set[str]:
    ips: set[str] = set()
    for t in ("A", "AAAA"):
        for r in _q(host, t):
            ips.add(r.strip())
    return ips


def _misma_red(ips: list[str]) -> bool:
    """¿Todas las IPv4 caen en la misma /24? (redundancia limitada)."""
    redes = set()
    for ip in ips:
        try:
            red = ipaddress.ip_network(f"{ip}/24", strict=False)
            redes.add(str(red))
        except ValueError:
            return False
    return len(redes) == 1


def scan(dominio: str) -> dict:
    """Reconocimiento DNS pasivo + análisis de postura de infraestructura."""
    dom = _limpiar_dominio(dominio)
    if not dom or "." not in dom:
        return {"error": "Dominio no válido."}

    a = _q(dom, "A")
    aaaa = _q(dom, "AAAA")
    mx = _q(dom, "MX")
    ns = _q(dom, "NS")
    soa = _q(dom, "SOA")
    txt = _q(dom, "TXT")
    caa = _q(dom, "CAA")
    dnskey = _q(dom, "DNSKEY")

    findings: list[dict] = []

    # --- Redundancia de los servidores de nombres (NS) ---
    ns_hosts = [x.rstrip(".") for x in ns]
    ns_ips: dict[str, set[str]] = {h: _ips_de(h) for h in ns_hosts}
    todas_ns_ips = sorted({ip for s in ns_ips.values() for ip in s})
    if len(ns_hosts) < 2:
        findings.append({
            "severidad": "media",
            "titulo": "Un solo servidor de nombres (NS)",
            "detalle": f"El dominio declara {len(ns_hosts)} NS. Las buenas prácticas (y los registros .es) recomiendan al menos 2 en redes distintas.",
            "remediacion": "Añadir un segundo servidor DNS en una red/proveedor diferente.",
        })
    elif todas_ns_ips and len(todas_ns_ips) == 1:
        findings.append({
            "severidad": "media",
            "titulo": "Servidores de nombres sin redundancia real",
            "detalle": f"Los {len(ns_hosts)} NS ({', '.join(ns_hosts)}) resuelven a la MISMA IP ({todas_ns_ips[0]}): si ese servidor cae, el dominio entero deja de resolver.",
            "remediacion": "Distribuir los NS en servidores e IPs/redes independientes (idealmente proveedores distintos).",
        })
    elif len(todas_ns_ips) > 1 and _misma_red(todas_ns_ips):
        findings.append({
            "severidad": "baja",
            "titulo": "Servidores de nombres en la misma red",
            "detalle": f"Los NS resuelven a IPs de la misma red /24 ({', '.join(todas_ns_ips)}): redundancia limitada ante un fallo de esa red.",
            "remediacion": "Ubicar al menos un NS en una red/proveedor distinto.",
        })

    # --- ¿Correo y web en el mismo servidor? ---
    ips_web = set(a)
    mx_hosts = []
    for registro in mx:
        partes = registro.split()
        mx_hosts.append(partes[-1].rstrip("."))
    ips_mx: set[str] = set()
    for h in mx_hosts:
        ips_mx |= _ips_de(h)
    comunes = ips_web & ips_mx
    if comunes:
        findings.append({
            "severidad": "baja",
            "titulo": "Correo y web en el mismo servidor",
            "detalle": f"El servidor de correo (MX) y la web comparten IP ({', '.join(sorted(comunes))}): un compromiso de uno expone al otro, y no hay separación de servicios.",
            "remediacion": "Separar el correo y la web en servidores distintos, o usar un servicio de correo gestionado.",
        })

    # --- SPF (a alto nivel; el detalle de suplantación lo da scan-mail) ---
    spf = next((t for t in txt if "v=spf1" in t.lower()), None)
    if not spf:
        findings.append({
            "severidad": "media",
            "titulo": "Sin registro SPF",
            "detalle": "No se publica SPF: facilita que se envíe correo suplantando el dominio.",
            "remediacion": "Publicar un registro SPF y terminarlo en '-all'. Ver la pestaña Correo para el detalle.",
        })
    elif spf.strip().rstrip('"').endswith("+all"):
        findings.append({
            "severidad": "alta",
            "titulo": "SPF permisivo (+all)",
            "detalle": f"El SPF termina en '+all', que autoriza a CUALQUIER servidor a enviar en nombre del dominio: {spf}",
            "remediacion": "Cambiar '+all' por '-all' (rechazo). Ver la pestaña Correo.",
        })

    # --- CAA ---
    if not caa:
        findings.append({
            "severidad": "baja",
            "titulo": "Sin registro CAA",
            "detalle": "No se restringe qué autoridades de certificación (CA) pueden emitir certificados para el dominio: cualquiera puede.",
            "remediacion": "Publicar un registro CAA autorizando solo la(s) CA que usas (p. ej. Let's Encrypt).",
        })

    # --- DNSSEC ---
    if not dnskey:
        findings.append({
            "severidad": "baja",
            "titulo": "DNSSEC no habilitado",
            "detalle": "El dominio no firma sus respuestas DNS (sin DNSKEY): son más fáciles de falsificar (envenenamiento de caché).",
            "remediacion": "Habilitar DNSSEC en el registrador/proveedor DNS.",
        })

    orden = {"alta": 0, "media": 1, "baja": 2, "informativo": 3}
    findings.sort(key=lambda f: orden.get(f["severidad"], 9))

    pen = {"alta": 20, "media": 8, "baja": 3}
    nota = max(0, 100 - sum(pen.get(f["severidad"], 0) for f in findings))

    comprobaciones = [
        {"nombre": "Registro A", "estado": "ok" if a else "falta",
         "detalle": ", ".join(a) if a else "sin A"},
        {"nombre": "IPv6 (AAAA)", "estado": "ok" if aaaa else "info",
         "detalle": ", ".join(aaaa) if aaaa else "sin AAAA"},
        {"nombre": "MX (correo)", "estado": "ok" if mx else "aviso",
         "detalle": ", ".join(mx_hosts) if mx_hosts else "sin MX"},
        {"nombre": "NS redundantes", "estado": "ok" if len(todas_ns_ips) > 1 and not _misma_red(todas_ns_ips) else "aviso",
         "detalle": f"{len(ns_hosts)} NS → {len(todas_ns_ips)} IP(s)"},
        {"nombre": "SPF", "estado": "ok" if spf else "falta",
         "detalle": "presente" if spf else "ausente"},
        {"nombre": "CAA", "estado": "ok" if caa else "aviso",
         "detalle": "presente" if caa else "sin CAA"},
        {"nombre": "DNSSEC", "estado": "ok" if dnskey else "aviso",
         "detalle": "firmado" if dnskey else "sin firmar"},
    ]

    return {
        "dominio": dom,
        "puntuacion": nota,
        "registros": {
            "A": a, "AAAA": aaaa, "MX": mx, "NS": ns,
            "SOA": soa, "TXT": txt, "CAA": caa,
        },
        "comprobaciones": comprobaciones,
        "resumen": {
            "altas": sum(1 for f in findings if f["severidad"] == "alta"),
            "medias": sum(1 for f in findings if f["severidad"] == "media"),
            "bajas": sum(1 for f in findings if f["severidad"] == "baja"),
        },
        "hallazgos": findings,
        "aviso": "Reconocimiento DNS pasivo: solo consulta registros públicos, no "
                 "sondea el servidor. La postura de suplantación de correo "
                 "(SPF/DKIM/DMARC en detalle) se analiza en la pestaña Correo.",
    }
