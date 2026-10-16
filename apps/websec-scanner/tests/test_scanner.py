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
    assert "Almenasec. Todos los derechos reservados. x" in html and "MINISOC" not in html


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


# --------------------------------------------------------------------------- #
#  Cabecera server de CDN y tarifas
# --------------------------------------------------------------------------- #
@respx.mock
def test_server_de_cdn_no_es_hallazgo(monkeypatch):
    from app import checks
    monkeypatch.setattr(checks, "es_publico", lambda h: True)
    respx.get("https://cf.com/").mock(return_value=httpx.Response(200, headers={"server": "cloudflare"}))
    respx.get("https://nx.com/").mock(return_value=httpx.Response(200, headers={"server": "nginx/1.18.0"}))
    t = lambda u: [f["titulo"] for f in asyncio.run(checks.check_http(u, 5))["findings"]]
    assert not any("server" in x for x in t("https://cf.com/"))
    assert "La cabecera server revela tecnología" in t("https://nx.com/")


def _res(*tramos):
    return {"hallazgos": [{"servicio": "web", "titulo": f"h{i}", "severidad_cvss": s} for i, s in enumerate(tramos)]}


def test_presupuesto_primer_escaneo_y_tope(monkeypatch):
    from app import tarifas
    q = tarifas.presupuesto(_res("media", "baja", "info"))
    assert q["modalidad"] == "primer-escaneo" and q["total"] == 190 + 75 + 25 and not q["tope_aplicado"]
    q = tarifas.presupuesto(_res(*["critica"] * 5))
    assert q["tope_aplicado"] and q["total"] == 690
    monkeypatch.setenv("PRECIO_TOPE", "2000")
    assert tarifas.presupuesto(_res(*["critica"] * 5))["total"] == 190 + 5 * 250


def test_presupuesto_reescaneo_solo_nuevos():
    from app import tarifas
    antes = _res("media", "baja")
    ahora = {"hallazgos": antes["hallazgos"] + [{"servicio": "web", "titulo": "nuevo", "severidad_cvss": "alta"}]}
    q = tarifas.presupuesto(ahora, antes)
    assert q["modalidad"] == "re-escaneo" and q["cuota_minima"] == 0 and q["total"] == 150
    assert tarifas.presupuesto(antes, antes)["total"] == 0


def test_informe_con_presupuesto(client, monkeypatch):
    from app import scanners

    async def fake_web(url, timeout=10.0):
        return scanners.completar({"objetivo": url, "puntuacion": 90, "aviso": "",
                                   "hallazgos": [{"id": "csp-weak", "titulo": "CSP débil", "severidad": "media"}]}, "web")
    monkeypatch.setattr(scanners, "run_web", fake_web)
    d = client.post("/scan", json={"url": "ej.com"}, headers=PASIVO).json()
    assert d["presupuesto"]["total"] == 190 + 75
    sid = d["scan_id"]
    assert "Estimación económica" not in client.get(f"/scans/{sid}/report", headers=PASIVO).text
    assert "265 €" in client.get(f"/scans/{sid}/report?precios=1", headers=PASIVO).text
    d2 = client.post("/scan", json={"url": "ej.com"}, headers=PASIVO).json()
    assert d2["presupuesto"]["modalidad"] == "re-escaneo" and d2["presupuesto"]["total"] == 0


def test_full_sin_duplicados_entre_modulos(monkeypatch):
    from app import report, scanners, severity, tarifas

    def sec(serv, *ids_titulos):
        return scanners.completar({"puntuacion": 90, "hallazgos": [
            {"titulo": t, "severidad": "baja"} for t in ids_titulos]}, serv)

    async def web(url, timeout=10.0):
        return sec("web", "Sin registro CAA", "Falta la cabecera x-frame-options")
    monkeypatch.setattr(scanners, "run_web", web)
    monkeypatch.setattr(scanners, "run_mail", lambda d: sec(
        "correo", "Dominio sin DNSSEC", "Sin MTA-STS", "No existe registro SPF", "SPF permite a cualquiera ('+all')"))
    monkeypatch.setattr(scanners, "run_dns", lambda d: sec(
        "dns", "DNSSEC no habilitado", "Sin registro CAA", "Sin registro SPF", "SPF permisivo (+all)"))
    # recon OSINT no aporta solapamientos; lo fijamos vacío para un test determinista (sin red).
    monkeypatch.setattr(scanners, "run_recon", lambda d: sec("recon"))
    res = asyncio.run(scanners.run_full("https://ej.com"))
    titulos = [f["titulo"] for f in report.hallazgos_de(res)]
    assert len(titulos) == len(set(severity.identidad(f) for f in report.hallazgos_de(res))) == 6
    for tema in ("DNSSEC", "CAA", "SPF permi", "registro SPF"):
        assert sum(tema in t for t in titulos) == 1, tema
    sec_de = lambda n: [f["titulo"] for f in res["secciones"][n]["hallazgos"]]
    assert "No existe registro SPF" in sec_de("correo") and "DNSSEC no habilitado" in sec_de("dns")
    assert "Sin registro CAA" in sec_de("dns") and sec_de("web") == ["Falta la cabecera x-frame-options"]
    # Un escaneo antiguo (guardado con duplicados) tampoco los muestra ni los cobra dos veces
    viejo = {"hallazgos": [{"id": "mail-no-dnssec", "titulo": "Dominio sin DNSSEC", "severidad_cvss": "baja"},
                           {"id": "dns-no-dnssec", "titulo": "DNSSEC no habilitado", "severidad_cvss": "baja"}]}
    assert len(report.hallazgos_de(viejo)) == 1
    assert tarifas.presupuesto(viejo)["subtotal_hallazgos"] == 25


# --------------------------------------------------------------------------- #
#  Agrupación TLS por causa raíz, inventario, prioridad y notas operativas
# --------------------------------------------------------------------------- #
def test_tls_agrupa_por_causa_raiz():
    from app import tlsdeep
    raw = [
        {"severidad": "medium", "titulo": "TLS: cipherlist_3DES_IDEA", "detalle": "offered", "plantilla": "cipherlist_3DES_IDEA"},
        {"severidad": "medium", "titulo": "TLS: BEAST_CBC_TLS1", "detalle": "x", "plantilla": "BEAST_CBC_TLS1"},
        {"severidad": "low", "titulo": "TLS: TLS1", "detalle": "offered", "plantilla": "TLS1"},
        {"severidad": "low", "titulo": "TLS: TLS1_1", "detalle": "offered", "plantilla": "TLS1_1"},
        {"severidad": "low", "titulo": "TLS: cipherlist_OBSOLETED", "detalle": "offered", "plantilla": "cipherlist_OBSOLETED"},
        {"severidad": "low", "titulo": "TLS: SWEET32", "detalle": "64 bit", "plantilla": "SWEET32", "cve": ["CVE-2016-2183"]},
        {"severidad": "low", "titulo": "TLS: LUCKY13", "detalle": "cbc", "plantilla": "LUCKY13"},
        {"severidad": "medium", "titulo": "TLS: BREACH", "detalle": "gzip", "plantilla": "BREACH"},
        {"severidad": "medium", "titulo": "TLS: cert_keySize", "detalle": "2048", "plantilla": "cert_keySize"},
    ]
    g = tlsdeep.agrupar_tls(raw)
    ids = {f.get("id") for f in g}
    titulos = {f["titulo"] for f in g}
    # Los 7 de config antigua -> 2 causas raíz; BREACH y cert quedan sueltos.
    assert "tls-proto-obsoleto" in ids and "tls-cifrado-debil" in ids
    assert "TLS: BREACH" in titulos and "TLS: cert_keySize" in titulos
    assert len(g) == 4
    cifrado = next(f for f in g if f.get("id") == "tls-cifrado-debil")
    assert "CVE-2016-2183" in cifrado.get("cve", [])
    assert cifrado["severidad"] == "medium"  # el máximo de sus miembros


def test_catalogo_cubre_tls_raiz():
    from app import severity
    fs = [{"id": i, "severidad": "baja", "titulo": i} for i in ("tls-proto-obsoleto", "tls-cifrado-debil")]
    severity.enrich(fs, "tls")
    assert all(f["cvss"] != "—" and f["severidad_cvss"] == "media" for f in fs)


def test_inventario_saca_detecciones_de_nuclei():
    from app import severity
    fs = [
        {"id": "web-env-exposed", "severidad": "critica", "titulo": "Fichero .env expuesto"},
        {"severidad": "informativo", "titulo": "WAF Detection", "origen": "nuclei"},
        {"severidad": "informativo", "titulo": "Wappalyzer Technology Detection", "origen": "nuclei"},
        {"id": "wp-detected", "severidad": "informativo", "titulo": "WordPress detectado", "origen": "recon-web"},
        {"id": "web-no-securitytxt", "severidad": "informativo", "titulo": "Sin security.txt", "origen": "recon-web"},
    ]
    severity.enrich(fs)
    inv = {f["titulo"] for f in fs if f.get("inventario")}
    assert inv == {"WAF Detection", "Wappalyzer Technology Detection", "WordPress detectado"}
    # .env es un hallazgo real; security.txt es una recomendación, no inventario.
    assert not any(f.get("inventario") for f in fs if f["titulo"] in ("Fichero .env expuesto", "Sin security.txt"))


def test_prioridad_y_orden():
    from app import report, severity
    fs = [
        {"id": "mail-no-dnssec", "severidad": "baja", "titulo": "Dominio sin DNSSEC"},
        {"id": "mail-no-dmarc", "severidad": "baja", "titulo": "No existe registro DMARC"},
        {"id": "wp-user-enum", "severidad": "media", "titulo": "Enumeración de usuarios de WordPress"},
        {"id": "web-env-exposed", "severidad": "critica", "titulo": "Fichero .env expuesto"},
    ]
    severity.enrich(fs)
    prio = {f["id"]: f["prioridad"] for f in fs}
    assert prio == {"web-env-exposed": "P0", "wp-user-enum": "P0",
                    "mail-no-dmarc": "P1", "mail-no-dnssec": "P2"}
    scan = {"id": "p1", "tipo": "activo", "objetivo": "ej.com", "started": None, "finished": None,
            "result": {"hallazgos": fs, "cvss_max": 9.8, "puntuacion": 40}}
    orden = [f["prioridad"] for f in report._ordenados(scan)]
    assert orden == sorted(orden, key=lambda p: {"P0": 0, "P1": 1, "P2": 2}[p])


def test_notas_operativas():
    from app import severity
    fs = [
        {"id": "cookie-flags", "severidad": "media", "titulo": "Cookie 'x' sin flags httponly"},
        {"id": "mail-dmarc-none", "severidad": "baja", "titulo": "DMARC solo en modo observación (p=none)"},
        {"id": "missing-xcto", "severidad": "baja", "titulo": "Falta la cabecera x-content-type-options"},
    ]
    severity.enrich(fs)
    assert "Polylang" in fs[0]["nota_operativa"]
    assert "quarantine" in fs[1]["nota_operativa"]
    assert fs[2].get("nota_operativa") is None  # sin nota definida


def test_informe_separa_hallazgos_de_inventario():
    from app import report, severity
    fs = [
        {"id": "web-env-exposed", "severidad": "critica", "titulo": "Fichero .env expuesto", "detalle": "x"},
        {"severidad": "informativo", "titulo": "WAF Detection", "detalle": "waf", "origen": "nuclei"},
    ]
    severity.enrich(fs)
    scan = {"id": "inv1", "tipo": "activo", "objetivo": "ej.com", "started": None, "finished": None,
            "result": {"hallazgos": fs, "cvss_max": 9.8, "puntuacion": 40, "aviso": "x"}}
    h = report.render_html(scan)
    md = report.render_md(scan)
    assert "Inventario y detecciones" in h and "Inventario y detecciones" in md
    # La detección va al inventario, después de la sección de hallazgos.
    assert h.find("WAF Detection") > h.find("Inventario y detecciones")
    assert h.find("Fichero .env expuesto") < h.find("Inventario y detecciones")


def test_reconweb_soft404_y_deteccion_wp():
    from app import reconweb

    class R:
        def __init__(self, status, body=b""):
            self.status_code = status
            self.content = body

    f404 = (200, 1000)  # el sitio responde 200 a todo, ~1000 B
    assert reconweb._es_soft404(R(404), (404, 0)) is True
    assert reconweb._es_soft404(R(200, b"x" * 1000), f404) is True   # mismo tamaño que el 404
    assert reconweb._es_soft404(R(200, b"x" * 5000), f404) is False  # claramente distinto
    assert reconweb._es_soft404(None, (404, 0)) is True

    wp = '<meta name="generator" content="WordPress 6.5"><link href="/wp-content/x.css">'
    assert reconweb._detecta_wp(wp, None, "https://x", f404) is True
    assert reconweb._detecta_wp("<html>sitio estático</html>", None, "https://x", f404) is False
