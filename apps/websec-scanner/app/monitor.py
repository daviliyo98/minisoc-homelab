"""
monitor — Monitorización continua de activos, alertas y métricas Prometheus.

  • Un hilo planificador revisa cada minuto qué activos toca volver a escanear
    (según su intervalo) y los escanea en serie, sin saturar la Pi.
  • Tras cada escaneo lo compara con el anterior del mismo activo y avisa por
    webhook y/o Telegram de: hallazgos nuevos (CVSS ≥ ALERT_MIN_CVSS),
    certificado a punto de caducar y bajadas de puntuación.
  • /metrics expone el estado de cada activo en formato Prometheus, para
    dibujarlo y alertar desde Grafana.
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading
import time

import httpx

from . import report, scanners, store, tarifas

ALERT_MIN_CVSS = float(os.environ.get("ALERT_MIN_CVSS", "4.0") or 4.0)
ALERT_CERT_DAYS = int(os.environ.get("ALERT_CERT_DAYS", "21") or 21)
ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
MONITOR_ENABLED = os.environ.get("MONITOR_ENABLED", "1") == "1"

_estado = {"ultimo_ciclo": None, "escaneando": None}


# --------------------------------------------------------------------------- #
#  Alertas
# --------------------------------------------------------------------------- #
def canales() -> list[str]:
    c = []
    if ALERT_WEBHOOK_URL:
        c.append("webhook")
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        c.append("telegram")
    return c


def enviar_alerta(titulo: str, lineas: list[str], datos: dict | None = None) -> dict:
    """Envía la alerta por todos los canales configurados. Devuelve el resultado por canal."""
    texto = f"🛡️ {titulo}\n" + "\n".join(lineas)
    res: dict[str, str] = {}
    if ALERT_WEBHOOK_URL:
        try:
            # 'text' lo entienden Slack/Mattermost/ntfy-JSON; 'content', Discord.
            r = httpx.post(ALERT_WEBHOOK_URL, timeout=10,
                           json={"text": texto, "content": texto[:1900], "titulo": titulo, "datos": datos or {}})
            res["webhook"] = f"HTTP {r.status_code}"
        except Exception as e:
            res["webhook"] = f"error: {type(e).__name__}"
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        try:
            r = httpx.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage", timeout=10,
                           json={"chat_id": TELEGRAM_CHAT_ID, "text": texto[:4000],
                                 "disable_web_page_preview": True})
            res["telegram"] = f"HTTP {r.status_code}"
        except Exception as e:
            res["telegram"] = f"error: {type(e).__name__}"
    if not res:
        print(f"[monitor] Alerta sin canal configurado: {titulo}", file=sys.stderr)
    return res


def _dias_cert(result: dict | None) -> int | None:
    if not result:
        return None
    web = result.get("secciones", {}).get("web") if "secciones" in result else result
    tls = (web or {}).get("tls") or {}
    return tls.get("dias_para_caducar") if tls.get("ok") else None


def evaluar_alertas(asset: dict, anterior: dict | None, actual: dict) -> list[str]:
    """Decide qué avisar comparando dos resultados. Devuelve las líneas del aviso."""
    lineas: list[str] = []
    cambios = report.diff(anterior, actual)
    graves = [f for f in cambios["nuevos"] if (f.get("cvss_score") or 0) >= ALERT_MIN_CVSS]
    if anterior is not None and graves:
        lineas.append(f"{len(graves)} hallazgo(s) nuevo(s) con CVSS ≥ {ALERT_MIN_CVSS}:")
        lineas += [f"  • [{f.get('cvss_score')}] {f.get('titulo')}" for f in graves[:10]]
    dias, dias_antes = _dias_cert(actual), _dias_cert(anterior)
    if dias is not None and dias <= ALERT_CERT_DAYS and (dias_antes is None or dias_antes > ALERT_CERT_DAYS or dias <= 3):
        lineas.append(f"El certificado TLS caduca en {dias} día(s).")
    pa, pb = cambios["puntuacion"]["antes"], cambios["puntuacion"]["ahora"]
    if pa is not None and pb is not None and pb <= pa - 10:
        lineas.append(f"La puntuación ha bajado de {pa} a {pb}.")
    return lineas


# --------------------------------------------------------------------------- #
#  Planificador
# --------------------------------------------------------------------------- #
def escanear_asset(asset: dict) -> str:
    """Escanea un activo, guarda el resultado y alerta si procede. Devuelve el id del escaneo."""
    anterior = store.latest_asset_scan(asset["id"])
    sid = store.new_scan(asset["tipo"], asset["objetivo"], usuario="monitor", asset_id=asset["id"])
    store.touch_asset(asset["id"], time.time())
    _estado["escaneando"] = asset["objetivo"]
    try:
        res = asyncio.run(scanners.run_tipo(asset["tipo"], asset["objetivo"]))
    except scanners.ScanError as e:
        store.fail_scan(sid, e.mensaje)
        return sid
    except Exception as e:
        store.fail_scan(sid, f"{type(e).__name__}: {e}")
        return sid
    finally:
        _estado["escaneando"] = None
    res["scan_id"] = sid
    tarifas.aplicar(res, store.previous_scan(sid))
    store.finish_scan(sid, res)
    lineas = evaluar_alertas(asset, (anterior or {}).get("result"), res)
    if lineas:
        enviar_alerta(f"{asset['objetivo']} ({asset['tipo']})", lineas,
                      {"asset_id": asset["id"], "scan_id": sid, "puntuacion": res.get("puntuacion"),
                       "cvss_max": res.get("cvss_max")})
    return sid


def _bucle(parar: threading.Event) -> None:
    while not parar.is_set():
        _estado["ultimo_ciclo"] = time.time()
        try:
            for asset in store.due_assets(time.time()):
                if parar.is_set():
                    break
                escanear_asset(asset)
        except Exception as e:
            print(f"[monitor] Error en el ciclo: {e}", file=sys.stderr)
        parar.wait(60)


_PARAR = threading.Event()


def start() -> None:
    if MONITOR_ENABLED:
        threading.Thread(target=_bucle, args=(_PARAR,), daemon=True, name="monitor").start()


def stop() -> None:
    _PARAR.set()


def estado() -> dict:
    return {"habilitado": MONITOR_ENABLED, "canales_alerta": canales(),
            "alerta_cvss_min": ALERT_MIN_CVSS, "alerta_dias_certificado": ALERT_CERT_DAYS, **_estado}


# --------------------------------------------------------------------------- #
#  Métricas Prometheus
# --------------------------------------------------------------------------- #
def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def metrics(jobs_en_curso: int = 0) -> str:
    out: list[str] = []

    def m(nombre: str, tipo: str, ayuda: str, muestras: list[tuple[dict, float]]):
        out.append(f"# HELP {nombre} {ayuda}")
        out.append(f"# TYPE {nombre} {tipo}")
        for labels, valor in muestras:
            lab = ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items())
            out.append(f"{nombre}{{{lab}}} {valor}" if lab else f"{nombre} {valor}")

    puntos, cvss, ultimo, cert, hall = [], [], [], [], []
    for a in store.list_assets():
        lab = {"asset": a["objetivo"], "tipo": a["tipo"]}
        s = store.latest_asset_scan(a["id"])
        if not s or not s.get("result"):
            continue
        r = s["result"]
        puntos.append((lab, r.get("puntuacion") or 0))
        cvss.append((lab, r.get("cvss_max") or 0.0))
        ultimo.append((lab, round(s.get("finished") or s["started"])))
        d = _dias_cert(r)
        if d is not None:
            cert.append((lab, d))
        p = r.get("pago_por_hallazgo") or {}
        for sev in ("criticas", "altas", "medias", "bajas", "info"):
            hall.append(({**lab, "severidad": sev}, p.get(sev, 0)))

    m("websec_asset_score", "gauge", "Puntuación 0-100 del último escaneo del activo.", puntos)
    m("websec_asset_cvss_max", "gauge", "CVSS máximo del último escaneo del activo.", cvss)
    m("websec_asset_last_scan_timestamp_seconds", "gauge", "Fin del último escaneo correcto (epoch).", ultimo)
    m("websec_asset_cert_days_remaining", "gauge", "Días hasta que caduca el certificado TLS.", cert)
    m("websec_asset_findings", "gauge", "Hallazgos del último escaneo por tramo CVSS.", hall)
    m("websec_scans", "gauge", "Escaneos en el historial por tipo y estado.",
      [({"tipo": r["tipo"], "status": r["status"]}, r["n"]) for r in store.count_by_status()])
    m("websec_jobs_running", "gauge", "Trabajos en segundo plano en curso o en cola.", [({}, jobs_en_curso)])
    m("websec_assets", "gauge", "Activos monitorizados.", [({}, len(store.list_assets()))])
    return "\n".join(out) + "\n"
