"""Dispositivos de la red: inventario IoT a partir de ARP y de Pi-hole.

Qué se quiere saber de cada aparato (robot aspirador, Alexa...):
- ¿Está conectado?   -> tabla ARP del host (/proc/net/arp). El portal va en red
  host, así que ve la del propio sistema sin enviar un solo paquete y sin
  NET_RAW: no hace falta ping ni ampliar los permisos del contenedor.
- ¿Qué hace en la red? -> API de Pi-hole v6: cuántas consultas DNS hace, a qué
  dominios y cuántas le bloquea. Es la telemetría que el aparato manda "a casa".

Nombres: los pone Pi-hole, no el portal. En Pi-hole > Group Management > Clients
se da de alta cada aparato por su MAC con un comentario ("Robot aspirador", o
"Robot aspirador | Xiaomi T12" para añadir el modelo). El portal solo lo LEE:
sigue sin escribir nada a partir del navegador, así que no necesita protección
CSRF ni permisos de escritura. Y el mismo cliente sirve en Pi-hole para aplicarle
grupos de bloqueo propios. Lo que no está dado de alta aparece como "sin
identificar": un aparato desconocido en la red es lo primero que hay que mirar.

Credenciales de Pi-hole: PIHOLE_PASSWORD en .env. Mejor una "contraseña de
aplicación" (Pi-hole > Settings > Web interface / API) que la de administrador:
se revoca sola sin tocar la principal.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import Counter
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger("portal.dispositivos")

CADA = max(30, int(os.environ.get("PORTAL_DISPOSITIVOS_CADA", "60")))
RUTA_ARP = Path(os.environ.get("PORTAL_ARP", "/proc/net/arp"))
PIHOLE_API = os.environ.get("PIHOLE_API", "http://127.0.0.1/api").rstrip("/")
PIHOLE_CLAVE = os.environ.get("PIHOLE_PASSWORD", "")
ACTIVO_SI_DNS_EN = 15 * 60           # una consulta DNS en 15 min = está activo
# Ventana de visibilidad: lo no dado de alta en Pi-hole solo se lista si se ha visto
# hace menos de esto. Así el móvil de una visita de hace dos semanas no ensucia la lista.
VENTANA = int(float(os.environ.get("PORTAL_DISPOSITIVOS_VENTANA_H", "3")) * 3600)
MAX_CONSULTAS = 2000                 # por dispositivo y refresco: una Pi no da para más

# Estados de Pi-hole v6 que significan "bloqueada".
BLOQUEADAS = {
    "GRAVITY", "REGEX", "DENYLIST", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME",
    "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA",
    "EXTERNAL_BLOCKED_EDE15", "SPECIAL_DOMAIN",
}

_estado: dict[str, Any] = {"lista": [], "ocultos": 0, "ventana_h": 3, "ts": None, "error": None,
                           "pihole": bool(PIHOLE_CLAVE)}
_sid: str | None = None


def estado() -> dict[str, Any]:
    return _estado


def _mac(valor: str | None) -> str:
    return (valor or "").strip().lower().replace("-", ":")


import re

_MAC = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$")
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Redes internas del propio host: contenedores Docker y Tailscale no son aparatos de casa.
_INTERFACES_VIRTUALES = ("docker", "br-", "veth", "tailscale", "lo", "virbr")


def _es_virtual(mac: str, interfaz: str = "") -> bool:
    return mac.startswith("02:42:") or interfaz.startswith(_INTERFACES_VIRTUALES)


# --- Fuentes locales --------------------------------------------------------------

def leer_arp(ruta: Path = RUTA_ARP) -> dict[str, dict[str, Any]]:
    """MAC -> {ip, completo}. Flags 0x2 = la entrada está resuelta (el vecino respondió)."""
    salida: dict[str, dict[str, Any]] = {}
    try:
        lineas = ruta.read_text(encoding="ascii", errors="replace").splitlines()[1:]
    except OSError as exc:
        log.warning("No se puede leer %s: %s", ruta, exc)
        return salida
    for linea in lineas:
        partes = linea.split()
        if len(partes) < 6:
            continue
        ip, flags, mac, interfaz = partes[0], partes[2], _mac(partes[3]), partes[5]
        if mac in ("", "00:00:00:00:00:00") or _es_virtual(mac, interfaz):
            continue
        salida[mac] = {"ip": ip, "completo": flags == "0x2", "interfaz": interfaz}
    return salida


# --- Pi-hole v6 -----------------------------------------------------------------------

async def _sesion(cliente: httpx.AsyncClient) -> str:
    """Abre sesión una vez y la reutiliza. Pi-hole limita las sesiones simultáneas:
    pedir una nueva en cada refresco acabaría agotándolas."""
    global _sid
    if _sid:
        return _sid
    r = await cliente.post(f"{PIHOLE_API}/auth", json={"password": PIHOLE_CLAVE})
    r.raise_for_status()
    sesion = r.json().get("session") or {}
    if not sesion.get("valid") or not sesion.get("sid"):
        raise PermissionError("Pi-hole rechazó la contraseña")
    _sid = sesion["sid"]
    return _sid


async def _api(cliente: httpx.AsyncClient, ruta: str, **params: Any) -> dict[str, Any]:
    global _sid
    for intento in (1, 2):
        sid = await _sesion(cliente)
        r = await cliente.get(f"{PIHOLE_API}{ruta}", params=params, headers={"X-FTL-SID": sid})
        if r.status_code == 401 and intento == 1:
            _sid = None                     # la sesión caducó: una sola reautenticación
            continue
        r.raise_for_status()
        return r.json()
    raise PermissionError("Pi-hole no acepta la sesión")


async def cerrar_sesion(cliente: httpx.AsyncClient | None = None) -> None:
    """Al apagar el portal, liberar la sesión en vez de dejarla caducar."""
    global _sid
    if not _sid:
        return
    propio = cliente is None
    cliente = cliente or httpx.AsyncClient(timeout=5)
    try:
        await cliente.delete(f"{PIHOLE_API}/auth", headers={"X-FTL-SID": _sid})
    except httpx.HTTPError:
        pass
    finally:
        _sid = None
        if propio:
            await cliente.aclose()


def _comentario(texto: str) -> dict[str, str]:
    """"Robot aspirador | Xiaomi T12" -> nombre y tipo. Sin "|", todo es el nombre."""
    nombre, _, tipo = (texto or "").partition("|")
    return {"nombre": nombre.strip()[:60], "tipo": tipo.strip()[:40]}


async def _clientes(cliente: httpx.AsyncClient) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    """Clientes dados de alta en Pi-hole con comentario: por MAC y por IP."""
    j = await _api(cliente, "/clients")
    por_mac: dict[str, dict[str, str]] = {}
    por_ip: dict[str, dict[str, str]] = {}
    for c in j.get("clients") or []:
        ident = str(c.get("client") or "").strip()
        datos = _comentario(str(c.get("comment") or ""))
        if not ident or not datos["nombre"]:
            continue
        if _MAC.match(ident.lower()):
            por_mac[_mac(ident)] = datos
        elif _IP.match(ident):
            por_ip[ident] = datos
    return por_mac, por_ip


async def _actividad(cliente: httpx.AsyncClient, ip: str, ahora: int) -> dict[str, Any]:
    """Consultas DNS de las últimas 24 h de una IP: total, bloqueadas y dominios."""
    j = await _api(cliente, "/queries", client_ip=ip, length=MAX_CONSULTAS, **{"from": ahora - 86400, "until": ahora})
    consultas = j.get("queries") or []
    dominios: Counter[str] = Counter()
    bloqueados: Counter[str] = Counter()
    for q in consultas:
        dom = str(q.get("domain") or "")[:253]
        if not dom:
            continue
        dominios[dom] += 1
        if str(q.get("status") or "").upper() in BLOQUEADAS:
            bloqueados[dom] += 1
    total = int(j.get("recordsFiltered") or len(consultas))
    return {
        "consultas": total,
        "muestra": len(consultas),
        "bloqueadas": sum(bloqueados.values()),
        "dominios": [
            {"dominio": d, "n": n, "bloqueado": bloqueados.get(d, 0) > 0}
            for d, n in dominios.most_common(8)
        ],
        "dominios_distintos": len(dominios),
    }


# --- Combinación ----------------------------------------------------------------------

async def refrescar(cliente: httpx.AsyncClient | None = None) -> None:
    ahora = int(time.time())
    arp = leer_arp()
    disp: dict[str, dict[str, Any]] = {}

    def base(mac: str) -> dict[str, Any]:
        return disp.setdefault(mac, {
            "mac": mac, "ip": None, "fabricante": "", "nombre_red": "",
            "en_arp": False, "ultima_dns": None, "actividad": None,
            "nombre": "", "tipo": "", "conocido": False,
        })

    for mac, a in arp.items():
        d = base(mac)
        d.update(ip=a["ip"], en_arp=a["completo"])

    error = None
    if PIHOLE_CLAVE:
        propio = cliente is None
        cliente = cliente or httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=3.0), trust_env=False)
        try:
            j = await _api(cliente, "/network/devices", max_devices=100, max_addresses=4)
            for dev in j.get("devices") or []:
                mac = _mac(dev.get("hwaddr"))
                # Pi-hole agrupa a veces por "ip-X.X.X.X" cuando no conoce la MAC.
                if not mac or mac.startswith("ip-") or mac == "00:00:00:00:00:00" or _es_virtual(mac, str(dev.get("interface") or "")):
                    continue
                ips = dev.get("ips") or []
                d = base(mac)
                d["fabricante"] = str(dev.get("macVendor") or "")[:60]
                d["ultima_dns"] = dev.get("lastQuery") or None
                if ips:
                    d["ip"] = d["ip"] or ips[0].get("ip")
                    d["nombre_red"] = str(ips[0].get("name") or "")[:80]
            # Nombres: los clientes dados de alta en Pi-hole (por MAC, o por IP fija).
            por_mac, por_ip = await _clientes(cliente)
            for mac, datos in por_mac.items():
                base(mac).update(datos, conocido=True)   # aunque hoy no esté conectado
            for d in disp.values():
                if not d["conocido"] and d["ip"] in por_ip:
                    d.update(por_ip[d["ip"]], conocido=True)
            # Actividad solo de lo que se va a enseñar.
            objetivo = [d for d in disp.values() if d["ip"] and _visible(d, ahora)]
            resultados = await asyncio.gather(
                *(_actividad(cliente, d["ip"], ahora) for d in objetivo), return_exceptions=True
            )
            for d, r in zip(objetivo, resultados):
                if isinstance(r, BaseException):
                    log.warning("Actividad de %s: %s", d["ip"], r)
                else:
                    d["actividad"] = r
        except (httpx.HTTPError, PermissionError, ValueError) as exc:
            error = f"{type(exc).__name__}: {exc}"[:160]
            log.warning("Pi-hole: %s", error)
        finally:
            if propio:
                await cliente.aclose()

    for d in disp.values():
        dns_reciente = bool(d["ultima_dns"]) and d["ultima_dns"] > ahora - ACTIVO_SI_DNS_EN
        d["estado"] = "activo" if dns_reciente else ("conectado" if d["en_arp"] else "ausente")
        act = d["actividad"]
        d["pct_bloqueo"] = round(100 * act["bloqueadas"] / act["muestra"]) if act and act["muestra"] else None

    orden = {"activo": 0, "conectado": 1, "ausente": 2}
    visibles = [d for d in disp.values() if _visible(d, ahora)]
    _estado.update(
        lista=sorted(visibles, key=lambda d: (not d["conocido"], orden[d["estado"]], d["ip"] or "~")),
        ocultos=len(disp) - len(visibles),
        ventana_h=round(VENTANA / 3600, 1),
        ts=ahora,
        error=error,
    )


def _visible(d: dict[str, Any], ahora: int) -> bool:
    """Dado de alta en Pi-hole, o visto en la ventana: en ARP ahora o con DNS reciente."""
    return d["conocido"] or d["en_arp"] or (d["ultima_dns"] or 0) > ahora - VENTANA


async def actualizador() -> None:
    try:
        while True:
            try:
                await refrescar()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - el bucle no puede morir
                log.warning("Fallo al refrescar dispositivos: %s", exc)
            await asyncio.sleep(CADA)
    finally:
        await cerrar_sesion()
