"""Tests sin red: los checks reciben respuestas simuladas (respx) y el DNS se parchea."""
from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest
import respx

ADMIN = {"x-api-key": "a" * 20}
PASIVO = {"x-api-key": "p" * 20}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("API_KEYS", f"fran:admin:{'a' * 20},cli:pasivo:{'p' * 20}")
    monkeypatch.setenv("MONITOR_ENABLED", "0")
    from app import auth, store
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "t.db"))
    auth.reload_keys()
    auth._HITS.clear()
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


# --------------------------------------------------------------------------- #
#  Checks
# --------------------------------------------------------------------------- #
@respx.mock
def test_cookie_flags_por_atributos(monkeypatch):
    from app import checks
    monkeypatch.setattr(checks, "es_publico", lambda h: True)
    respx.get("https://ej.com/").mock(return_value=httpx.Response(200, headers=[
        ("set-cookie", "insecure_id=secure; HttpOnly; Secure; SameSite=Lax"),
        ("set-cookie", "sesion=abc; Path=/"),
    ]))
    res = asyncio.run(checks.check_http("https://ej.com/", 5))
    titulos = [f["titulo"] for f in res["findings"]]
    assert not any("insecure_id" in t for t in titulos)
    assert "Cookie 'sesion' sin flags secure, httponly, samesite" in titulos


def test_contenido_mixto_y_sri():
    from app.checks import analizar_html
    html = """<script src="http://cdn.x.com/a.js"></script>
              <img src="http://img.x.com/i.png">
              <script src="https://cdn.terceros.com/lib.js"></script>
              <script src="https://cdn.ok.com/lib.js" integrity="sha384-x"></script>
              <script src="/local.js"></script>
              <link rel="stylesheet" href="//fonts.terceros2.com/f.css">"""
    ids = {f["id"]: f for f in analizar_html(html, "https://mi.web/")}
    assert set(ids) == {"mixed-content-active", "mixed-content-passive", "no-sri"}
    assert "cdn.terceros.com" in ids["no-sri"]["detalle"]
    assert "fonts.terceros2.com" in ids["no-sri"]["detalle"]
    assert "cdn.ok.com" not in ids["no-sri"]["detalle"]


def test_caa_sube_por_el_arbol(monkeypatch):
    from app import checks
    pedidos = []

    def fake(name, rtype, lifetime=None):
        pedidos.append(name)
        if name == "ejemplo.co.uk":
            return [object()]
        raise Exception("NoAnswer")
    monkeypatch.setattr(checks.dns.resolver, "resolve", fake)
    assert checks.check_caa("www.ejemplo.co.uk")["caa"] is True
    assert pedidos == ["www.ejemplo.co.uk", "ejemplo.co.uk"]


def test_catalogo_cubre_nuevos_ids():
    from app import severity
    fs = [{"id": i, "severidad": "baja", "titulo": i} for i in
          ("mixed-content-active", "no-sri", "cors-wildcard-credentials", "recon-takeover")]
    severity.enrich(fs)
    assert all(f["cvss"] != "—" for f in fs)
    assert fs[3]["severidad_cvss"] == "alta"


# --------------------------------------------------------------------------- #
#  Informes y comparación
# --------------------------------------------------------------------------- #
def _scan(hallazgos, puntuacion=90):
    from app import severity
    severity.enrich(hallazgos)
    return {"id": "abc123", "tipo": "web", "objetivo": "https://ej.com", "started": time.time(),
            "finished": time.time(), "result": {"puntuacion": puntuacion, "cvss_max": 4.3,
                                                "hallazgos": hallazgos, "aviso": "x"}}


def test_diff_y_renderers():
    from app import report
    a = _scan([{"titulo": "Falta la cabecera x-frame-options", "severidad": "media", "detalle": "", "remediacion": ""}])
    b = _scan([{"titulo": "CSP débil", "severidad": "media", "detalle": "<script>", "remediacion": ""}], 80)
    d = report.diff(a["result"], b["result"])
    assert [f["titulo"] for f in d["nuevos"]] == ["CSP débil"]
    assert [f["titulo"] for f in d["corregidos"]] == ["Falta la cabecera x-frame-options"]
    html = report.render_html(b, d)
    assert "&lt;script&gt;" in html and "<script>" not in html.split("<style>")[0]
    sarif = json.loads(report.render_sarif(b))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"][0]["ruleId"] == "csp-weak"
    assert "## Hallazgos" in report.render_md(b, d)


def test_alerta_certificado_solo_al_cruzar_umbral():
    from app import monitor
    web = lambda dias: {"puntuacion": 90, "hallazgos": [], "tls": {"ok": True, "dias_para_caducar": dias}}
    assert any("caduca en 20" in l for l in monitor.evaluar_alertas({}, web(30), web(20)))
    assert not monitor.evaluar_alertas({}, web(19), web(18))   # ya avisado
    assert monitor.evaluar_alertas({}, web(4), web(3))          # recordatorio final


# --------------------------------------------------------------------------- #
#  API: roles, auditoría, historial, trabajos
# --------------------------------------------------------------------------- #
def test_roles_y_auditoria(client):
    assert client.get("/whoami").status_code == 401
    assert client.get("/whoami", headers={"x-api-key": "x" * 20}).status_code == 401
    assert client.get("/whoami", headers=PASIVO).json()["rol"] == "pasivo"
    assert client.post("/assets", json={"objetivo": "ej.com", "tipo": "dns"}, headers=PASIVO).status_code == 403
    assert client.get("/audit", headers=PASIVO).status_code == 403
    acciones = [a["accion"] for a in client.get("/audit", headers=ADMIN).json()]
    assert acciones.count("auth-fallida") == 2 and "permiso-denegado" in acciones


def test_limite_de_peticiones(client, monkeypatch):
    from app import auth
    monkeypatch.setattr(auth, "RATE_LIMIT", 3)
    codigos = [client.get("/whoami", headers=PASIVO).status_code for _ in range(4)]
    assert codigos == [200, 200, 200, 429]


def test_historial_e_informe(client, monkeypatch):
    from app import scanners

    async def fake_web(url, timeout=10.0):
        return {"objetivo": url, "puntuacion": 92, "cvss_max": 3.1, "hallazgos": [], "resumen": {},
                "pago_por_hallazgo": {}, "aviso": ""}
    monkeypatch.setattr(scanners, "run_web", fake_web)
    sid = client.post("/scan", json={"url": "ej.com"}, headers=PASIVO).json()["scan_id"]
    lista = client.get("/scans", headers=PASIVO).json()
    assert lista[0]["id"] == sid and lista[0]["puntuacion"] == 92 and "result" not in lista[0]
    r = client.get(f"/scans/{sid}/report?format=md", headers=PASIVO)
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert client.get(f"/scans/{sid}/diff", headers=PASIVO).status_code == 404  # no hay anterior


def test_trabajo_en_cola_y_cancelacion(client):
    from app import jobs, store

    def lento(sid, cancel):
        for _ in range(100):
            jobs.log(sid, "trabajando")
            time.sleep(0.05)
        return {"ok": True, "findings": []}

    a = jobs.lanzar("nuclei", "https://ej.com", "fran", lento, motor="nuclei", aviso="")
    b = jobs.lanzar("nuclei", "https://ej.com", "fran", lento, motor="nuclei", aviso="")
    time.sleep(0.3)
    assert store.get_scan(a)["status"] == "running"
    assert store.get_scan(b)["status"] == "queued"          # JOBS_MAX_CONCURRENT=1
    assert client.delete(f"/scans/{b}", headers=ADMIN).json() == {"cancelado": True}
    assert client.delete(f"/scans/{a}", headers=ADMIN).json() == {"cancelado": True}
    time.sleep(0.5)
    assert store.get_scan(a)["status"] == "cancelled"
    assert store.get_scan(b)["status"] == "cancelled"
    assert client.get(f"/scan-status/{a}", headers=PASIVO).json()["estado_real"] == "cancelled"


def test_metrics(client):
    r = client.get("/metrics")
    assert r.status_code == 200 and "websec_assets 0" in r.text


def test_testssl_fatal_es_error(monkeypatch, tmp_path):
    from app import tlsdeep
    datos = [{"id": "scanProblem", "severity": "FATAL", "finding": "Neither 'dig' nor 'host'"}]

    def fake_run(cmd, **kw):
        ruta = cmd[cmd.index("--jsonfile") + 1]
        with open(ruta, "w") as fh:
            json.dump(datos, fh)
        return 0, "", ""
    monkeypatch.setattr(tlsdeep, "run_cancelable", fake_run)
    monkeypatch.setattr(tlsdeep, "disponible", lambda: True)
    res = tlsdeep.scan_tls("ej.com", "93.184.216.34")
    assert res["ok"] is False and "dig" in res["error"]
