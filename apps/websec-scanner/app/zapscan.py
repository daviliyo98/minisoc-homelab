"""
zapscan — Wrapper de OWASP ZAP (Zed Attack Proxy) por su API REST.

ZAP corre como un contenedor aparte en modo demonio (daemon). Este módulo le
habla por HTTP (http://zap:8080) para dos tipos de escaneo:

  • LIGERO (spider + pasivo): ZAP rastrea el sitio (crawling) y analiza las
    respuestas sin inyectar nada. Encuentra cabeceras ausentes, cookies
    inseguras, fugas de información, contenido mixto, formularios sin CSRF, etc.

  • ACTIVO (ascan): ZAP SÍ inyecta cargas (SQLi, XSS, LFI, inyección de
    comandos...) sobre los parámetros descubiertos. Esto es lo que detecta la
    lógica de aplicación que Nuclei NO ve. Es INTRUSIVO.

Por eso el escaneo activo de ZAP va tras el mismo triple candado que Nuclei
(ver main.py). Ejecútalo SOLO con autorización explícita y por escrito del
titular del sistema.

Diseñado para ejecutarse en un hilo en segundo plano: usa httpx.Client
(síncrono) y hace polling del estado hasta completar o agotar el tiempo.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Callable
from urllib.parse import urlparse

import httpx

# Riesgo de ZAP -> severidad interna del scanner.
RISK_MAP = {
    "High": "alta",
    "Medium": "media",
    "Low": "baja",
    "Informational": "informativo",
}

# Base de la API del demonio ZAP dentro de la red de Docker.
ZAP_BASE_DEFAULT = "http://zap:8080"


class ZapError(RuntimeError):
    """Error controlado durante el escaneo con ZAP."""


def _get(client: httpx.Client, base: str, path: str, api_key: str,
         _reintentos: int = 2, **params) -> dict:
    """Llama a la API JSON de ZAP y devuelve el objeto decodificado.

    Reintenta ante fallos de red/timeout transitorios (ZAP puede estar ocupado
    un instante), pero NO reintenta errores HTTP reales (un 400/500 no se
    arregla repitiendo): esos se propagan para que se vean en el diagnóstico.
    """
    if api_key:
        params["apikey"] = api_key
    url = f"{base}/JSON/{path}"
    ultimo: Exception | None = None
    for intento in range(_reintentos + 1):
        try:
            r = client.get(url, params=params)
            r.raise_for_status()
            return r.json()
        except (httpx.TransportError, httpx.TimeoutException) as e:
            ultimo = e
            time.sleep(1.0 * (intento + 1))
    assert ultimo is not None
    raise ultimo


def zap_disponible(base: str = ZAP_BASE_DEFAULT, api_key: str = "", timeout: float = 4.0) -> bool:
    """¿Responde el demonio ZAP? (se usa para activar/desactivar la opción)."""
    try:
        with httpx.Client(timeout=timeout) as c:
            data = _get(c, base, "core/view/version/", api_key)
            return "version" in data
    except Exception:
        return False


def _poll(
    client: httpx.Client, base: str, path: str, api_key: str, campo: str,
    objetivo: str, deadline: float, intervalo: float = 2.0,
    log: Callable[[str], None] | None = None, etiqueta: str = "", unidad: str = "%",
    **params,
) -> None:
    """Hace polling de un endpoint de estado hasta que el campo llegue a 100
    (spider/ascan) o a 0 (recordsToScan del pasivo), o se agote el tiempo.
    Si se pasa `log`, informa del progreso en cada vuelta."""
    ultimo = None
    while True:
        if time.monotonic() > deadline:
            raise ZapError(f"ZAP superó el tiempo límite durante: {etiqueta or path}.")
        data = _get(client, base, path, api_key, **params)
        try:
            valor = int(data.get(campo, "0"))
        except (TypeError, ValueError):
            valor = 0
        if log and etiqueta and valor != ultimo:
            log(f"{etiqueta}: {valor}{unidad}")
            ultimo = valor
        if (objetivo == "100" and valor >= 100) or (objetivo == "0" and valor <= 0):
            return
        time.sleep(intervalo)


def _esperar_pasivo(
    client: httpx.Client, base: str, api_key: str, deadline: float,
    emit: Callable[[str], None], max_espera: float = 180.0,
) -> None:
    """Espera a que el analizador pasivo de ZAP drene su cola.

    A diferencia del spider/ascan (que llegan a 100 y paran), la cola del
    pasivo (`recordsToScan`) puede fluctuar y no bajar a 0 en equipos lentos
    (p.ej. una Raspberry Pi con muchas páginas). Por eso NO fallamos si no
    llega a 0: esperamos un máximo razonable y, si no, continuamos a recoger
    las alertas (que ya son válidas). Confirmamos el fin con dos lecturas
    seguidas a 0 (una sola podría ser un bajón puntual)."""
    inicio = time.monotonic()
    ceros = 0
    while True:
        ahora = time.monotonic()
        if ahora > deadline:
            emit("Pasivo: presupuesto global agotado; continúo con lo analizado.")
            return
        if ahora - inicio > max_espera:
            emit(f"Pasivo: la cola no se vació en {int(max_espera)}s; continúo con lo analizado.")
            return
        data = _get(client, base, "pscan/view/recordsToScan/", api_key)
        try:
            pend = int(data.get("recordsToScan", "0"))
        except (TypeError, ValueError):
            pend = 0
        emit(f"Pasivo (registros pendientes): {pend}")
        if pend <= 0:
            ceros += 1
            if ceros >= 2:
                emit("Pasivo completado.")
                return
        else:
            ceros = 0
        time.sleep(1.5)


def scan_zap(
    url: str,
    *,
    activo: bool = False,
    base: str = ZAP_BASE_DEFAULT,
    api_key: str = "",
    timeout_total: float = 600.0,
    es_publico: Callable[[str], bool] | None = None,
    log: Callable[[str], None] | None = None,
) -> dict:
    """Escanea una URL autorizada con ZAP y devuelve los hallazgos.

    activo=False -> spider + pasivo (ligero).
    activo=True  -> además, escaneo activo (inyección). INTRUSIVO.
    Si se pasa `log`, informa del progreso de cada fase en directo.
    """
    def emit(msg: str) -> None:
        if log:
            try:
                log(msg)
            except Exception:
                pass

    host = urlparse(url).hostname or ""

    # Anti-SSRF: revalidamos aquí también (defensa en profundidad). ZAP vive en
    # la red de Docker y no debe usarse como pivote hacia servicios internos.
    if es_publico is not None and not es_publico(host):
        return {"ok": False,
                "error": "Objetivo no permitido: resuelve a una dirección interna o reservada.",
                "findings": []}

    deadline = time.monotonic() + timeout_total

    fase = "comprobar ZAP"
    try:
        with httpx.Client(timeout=30.0) as c:
            emit("Comprobando que ZAP responde…")
            if not zap_disponible(base, api_key):
                return {"ok": False,
                        "error": "El servicio ZAP no está disponible. ¿Está arrancado el contenedor 'zap'?",
                        "findings": []}
            emit("ZAP accesible. Iniciando escaneo.")

            # 1) Sembrar el sitio en el árbol de ZAP.
            fase = "acceder a la URL (accessUrl)"
            emit(f"Accediendo a {url}")
            _get(c, base, "core/action/accessUrl/", api_key, url=url, followRedirects="false")

            # 2) Spider: rastrea el sitio (en el ámbito del host de partida).
            fase = "lanzar el spider"
            emit("Spider: rastreando el sitio…")
            r = _get(c, base, "spider/action/scan/", api_key,
                     url=url, recurse="true", subtreeOnly="true", maxChildren="50")
            spider_id = str(r.get("scan", "0"))
            fase = "spider en curso"
            _poll(c, base, "spider/view/status/", api_key, "status", "100",
                  deadline, scanId=spider_id, log=emit, etiqueta="Spider")

            # 3) Esperar a que el escaneo pasivo procese todo lo rastreado
            #    (de forma tolerante: no fallamos si la cola no llega a 0).
            fase = "análisis pasivo"
            emit("Análisis pasivo de lo rastreado…")
            _esperar_pasivo(c, base, api_key, deadline, emit)

            modo = "zap-pasivo"
            # 4) (Opcional) Escaneo activo: inyecta cargas sobre lo descubierto.
            if activo:
                fase = "lanzar el escaneo activo"
                emit("Escaneo ACTIVO (inyección): enviando cargas…")
                r = _get(c, base, "ascan/action/scan/", api_key,
                         url=url, recurse="true", inScopeOnly="false")
                ascan_id = str(r.get("scan", "0"))
                fase = "escaneo activo en curso"
                _poll(c, base, "ascan/view/status/", api_key, "status", "100",
                      deadline, scanId=ascan_id, intervalo=3.0,
                      log=emit, etiqueta="Activo")
                modo = "zap-activo"

            # 5) Recoger alertas del objetivo.
            #    Componente CORRECTO: 'alert' (singular). 'alerts' no existe en
            #    la API de ZAP y devuelve "no_implementor". Sin start/count para
            #    traerlas todas (filtradas por baseurl).
            fase = "recoger alertas"
            emit("Recogiendo alertas…")
            data = _get(c, base, "alert/view/alerts/", api_key, baseurl=url)
            alertas = data.get("alerts", []) or []
            emit(f"{len(alertas)} alerta(s) en bruto recogida(s).")

    except httpx.HTTPStatusError as e:
        cuerpo = ""
        try:
            cuerpo = (e.response.text or "").strip().replace("\n", " ")[:300]
        except Exception:
            pass
        code = e.response.status_code if e.response is not None else "?"
        return {"ok": False,
                "error": f"ZAP devolvió HTTP {code} al {fase}. {cuerpo}".strip(),
                "findings": []}
    except httpx.HTTPError as e:
        return {"ok": False, "error": f"Error de comunicación con ZAP al {fase}: {type(e).__name__}", "findings": []}
    except ZapError as e:
        return {"ok": False, "error": str(e), "findings": []}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "error": f"No se pudo completar el escaneo ZAP al {fase}: {e}", "findings": []}

    findings = _agrupar_alertas(alertas)
    orden = {"alta": 0, "media": 1, "baja": 2, "informativo": 3}
    findings.sort(key=lambda f: orden.get(f["severidad"], 9))
    return {"ok": True, "motor": "zap", "modo": modo, "total": len(findings), "findings": findings}


def _agrupar_alertas(alertas: list[dict]) -> list[dict]:
    """ZAP emite una alerta por cada URL/parámetro afectado. Para el informe,
    agrupamos por tipo de alerta y contamos cuántas instancias hay."""
    grupos: dict[tuple, dict] = {}
    conteo: dict[tuple, int] = defaultdict(int)
    ejemplos: dict[tuple, set] = defaultdict(set)

    for a in alertas:
        nombre = a.get("alert") or a.get("name") or "Hallazgo"
        riesgo = (a.get("risk") or "Informational").split()[0]  # a veces "Medium (…)"
        clave = (nombre, riesgo)
        conteo[clave] += 1
        u = a.get("url")
        if u and len(ejemplos[clave]) < 3:
            ejemplos[clave].add(u)
        if clave not in grupos:
            grupos[clave] = a

    findings: list[dict] = []
    for clave, a in grupos.items():
        nombre, riesgo = clave
        n = conteo[clave]
        desc = (a.get("description") or "").strip()
        urls = sorted(ejemplos[clave])
        detalle = f"{n} instancia(s)."
        if urls:
            detalle += " Ej.: " + ", ".join(urls)
        if desc:
            detalle += f" — {desc[:300]}"
        remediacion = (a.get("solution") or "").strip() or (a.get("reference") or "").strip()[:300] \
            or "Revisar la alerta en la documentación de OWASP ZAP."
        cwe = a.get("cweid")
        titulo = nombre if not cwe or cwe in ("-1", "0") else f"{nombre} (CWE-{cwe})"
        findings.append({
            "severidad": RISK_MAP.get(riesgo, "baja"),
            "titulo": titulo,
            "detalle": detalle,
            "remediacion": remediacion.replace("\n", " ").strip(),
        })
    return findings
