"""Carga del catálogo (services.yaml) y composición de URLs.

El portal guarda el PUERTO de cada servicio, no la URL completa. La razón es que la
misma cosa se ve distinto según dónde estés: la IP de casa (192.168.1.20) no existe
fuera de la LAN. Duplicar URLs en el catálogo garantiza que una de las dos
se queda obsoleta sin enterarse nadie.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# El compose lo monta en /app/services.yaml en solo lectura. La variable de entorno
# permite probarlo contra otro fichero sin reconstruir la imagen.
CATALOG_PATH = Path(os.environ.get("PORTAL_CATALOG", "/app/services.yaml"))

_cache: tuple[float, dict[str, Any]] | None = None


class CatalogoError(Exception):
    """El catálogo no existe o no es válido."""


def _cargar() -> dict[str, Any]:
    """Lee el catálogo, releyéndolo si el fichero ha cambiado en disco.

    Se cachea por mtime y no con lru_cache: el catálogo va montado en solo lectura y
    la gracia del portal es poder editarlo sin reconstruir la imagen ni reiniciar nada.
    Con una caché simple el fichero se quedaba obsoleto en silencio hasta el próximo
    reinicio del contenedor, que es justo lo que el README promete que no hace falta.
    """
    global _cache

    try:
        mtime = CATALOG_PATH.stat().st_mtime
    except FileNotFoundError as exc:
        raise CatalogoError(f"No existe el catálogo en {CATALOG_PATH}") from exc

    if _cache is not None and _cache[0] == mtime:
        return _cache[1]

    try:
        data = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CatalogoError(f"{CATALOG_PATH.name} no es YAML válido: {exc}") from exc

    if not isinstance(data, dict) or "services" not in data:
        raise CatalogoError("El catálogo debe ser un mapa con la clave 'services'")

    _cache = (mtime, data)
    return data


def redes() -> dict[str, str]:
    """Direcciones base: LAN de casa y tailnet de Tailscale."""
    return dict(_cargar().get("red", {}))


def _host_de_servicio(svc: dict[str, Any], red: dict[str, str], destino: str) -> str:
    """Elige el host con el que componer la URL.

    Un `host` declarado (Prometheus en 127.0.0.1) se usa TAL CUAL, también en destino
    tailnet. El portal corre en red host, así que 127.0.0.1:9090 le responde: sustituirlo
    por la IP del tailnet daría ConnectError porque ahí no escucha nadie. Ese enlace no
    abrirá desde un navegador remoto, y es correcto que se avise con `solo_destino`.
    """
    if svc.get("host"):
        return svc["host"]
    return red.get("lan") if destino == "lan" else red.get("tailnet", "")


def servicios(destino: str = "tailnet") -> list[dict[str, Any]]:
    """Devuelve el catálogo anotado con la URL ya compuesta para `destino`.

    destino: "tailnet" (por defecto, funciona desde cualquier sitio con la VPN)
             "lan"     (más rápido, pero solo dentro de casa)
    """
    red = redes()
    salida: list[dict[str, Any]] = []

    for svc in _cargar()["services"]:
        item = dict(svc)
        host = _host_de_servicio(svc, red, destino)
        item["destino"] = destino
        item["host"] = host
        item["url"] = f"http://{host}:{svc['port']}{svc.get('path', '')}"
        # Con host propio (loopback) el enlace solo abre desde la propia Pi: no se muestra
        # en destino LAN, y en tailnet se avisa.
        item["solo_destino"] = bool(svc.get("host"))
        salida.append(item)

    return salida


def stacks() -> list[str]:
    return sorted({s["stack"] for s in servicios() if s.get("stack")})


def todos_los_tags() -> list[str]:
    tags: set[str] = set()
    for s in servicios():
        tags.update(s.get("tags", []))
    return sorted(tags)