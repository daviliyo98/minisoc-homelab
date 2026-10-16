"""
reconweb — Reconocimiento web ACTIVO-LIGERO (solo GET/HEAD sobre el propio sitio).

A diferencia de los módulos pasivos (que solo leen DNS y descargan la portada),
aquí SÍ se piden rutas concretas al servidor para detectar:

  • Ficheros sensibles expuestos (.git, .env, copias de wp-config, backups).
  • Ficheros informativos que revelan tecnología (readme.html, license.txt).
  • Ausencia de /.well-known/security.txt.
  • WordPress: versión y plugins, enumeración de usuarios (REST + author),
    XML-RPC habilitado, wp-login expuesto, application passwords.

No inyecta cargas, no hace fuzzing ni POST destructivos: solo peticiones de
lectura. Aun así es ACTIVO (toca endpoints del objetivo), por lo que en la API
va detrás del rol 'activo' + autorizo=true + anti-SSRF + dominio verificado.
Ejecútalo SOLO sobre sistemas propios o con autorización por escrito.
"""
from __future__ import annotations

import json
import re
import secrets
from urllib.parse import urljoin, urlparse

import httpx

# Nos identificamos: un escáner legítimo debe ser reconocible en los logs del
# objetivo (buena práctica; evita parecer un atacante anónimo).
_UA = "MinisocWebScanner/1.0 (+https://almenasec.com; escaneo autorizado)"
_MAX_BYTES = 4096  # solo necesitamos el principio para firmar el contenido


def _norm_base(url: str) -> str:
    p = urlparse(url if "//" in url else "https://" + url)
    esquema = p.scheme or "https"
    return f"{esquema}://{p.netloc}"


def _firma_404(cliente: httpx.Client, base: str) -> tuple[int, int]:
    """Aprende cómo responde el sitio a una ruta inexistente (soft-404).

    Devuelve (status, longitud_aprox). Si el sitio devuelve 200 a todo, lo
    detectaremos comparando contra esta longitud.
    """
    ruta = f"/{secrets.token_hex(8)}-noexiste-{secrets.token_hex(4)}"
    try:
        r = cliente.get(urljoin(base, ruta))
        return r.status_code, len(r.content or b"")
    except Exception:
        return 404, 0


def _get(cliente: httpx.Client, base: str, ruta: str) -> httpx.Response | None:
    try:
        return cliente.get(urljoin(base, ruta))
    except Exception:
        return None


def _es_soft404(r: httpx.Response | None, f404: tuple[int, int]) -> bool:
    """¿La respuesta es en realidad la página de 'no encontrado' del sitio?"""
    if r is None:
        return True
    if r.status_code in (404, 410):
        return True
    # Si el sitio contesta 200 a todo, comparamos tamaño con el soft-404 base.
    if f404[0] == 200 and r.status_code == 200:
        n = len(r.content or b"")
        if f404[1] and abs(n - f404[1]) <= max(64, f404[1] * 0.05):
            return True
    return False


def _texto(r: httpx.Response) -> str:
    try:
        return (r.content or b"")[:_MAX_BYTES].decode("utf-8", "ignore")
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
#  Ficheros sensibles e informativos
# --------------------------------------------------------------------------- #
def _ficheros_sensibles(cliente, base, f404, host, emit, log) -> None:
    # (ruta, firma(texto, respuesta) -> bool, id, severidad, titulo, detalle, remediacion)
    def _sig_git(t, r):   return t.startswith("ref:") or bool(re.match(r"^[0-9a-f]{40}", t))
    def _sig_gitcfg(t, r): return "[core]" in t
    def _sig_env(t, r):   return bool(re.search(r"^[A-Z0-9_]+\s*=", t, re.M)) and "<html" not in t.lower()
    def _sig_zip(t, r):   return "zip" in (r.headers.get("content-type", "").lower()) or (r.content[:2] == b"PK")
    def _sig_sql(t, r):   return ("sql" in r.headers.get("content-type", "").lower()
                                  or bool(re.search(r"(?i)(CREATE TABLE|INSERT INTO|DROP TABLE)", t)))
    def _sig_any(t, r):   return True

    PRUEBAS = [
        ("/.git/HEAD",            _sig_git,    "web-git-exposed",    "alta",
         "Repositorio Git expuesto (/.git/)",
         "El directorio .git es accesible: permite reconstruir todo el código fuente y, con él, filtrar credenciales y lógica interna.",
         "Bloquear el acceso a /.git/ en el servidor web (deny) o eliminarlo del directorio público; desplegar sin el .git."),
        ("/.git/config",         _sig_gitcfg, "web-git-exposed",    "alta",
         "Repositorio Git expuesto (/.git/)",
         "El fichero .git/config es accesible: confirma un repositorio Git publicado y revela la URL del remoto.",
         "Bloquear el acceso a /.git/ en el servidor web (deny) o eliminarlo del directorio público."),
        ("/.env",                _sig_env,    "web-env-exposed",    "critica",
         "Fichero .env expuesto (secretos en claro)",
         "El fichero .env es accesible y contiene variables de entorno: suele incluir credenciales de base de datos, claves de API y secretos de la aplicación EN CLARO.",
         "Retirar .env del directorio público de inmediato, ROTAR todas las credenciales que contuviera y bloquear ficheros ocultos en el servidor."),
        ("/wp-config.php.bak",   _sig_any,    "web-config-backup",  "critica",
         "Copia de seguridad de wp-config.php accesible",
         "Hay una copia del fichero de configuración de WordPress descargable: expone las credenciales de la base de datos y las claves de seguridad (salts).",
         "Eliminar la copia del directorio público, ROTAR las credenciales de BBDD y regenerar los salts de WordPress."),
        ("/wp-config.php~",      _sig_any,    "web-config-backup",  "critica",
         "Copia de seguridad de wp-config.php accesible",
         "Hay una copia temporal (~) del fichero de configuración de WordPress descargable: expone credenciales de BBDD y salts.",
         "Eliminar la copia del directorio público, ROTAR las credenciales de BBDD y regenerar los salts."),
        ("/backup.zip",          _sig_zip,    "web-backup-exposed", "alta",
         "Copia de seguridad descargable (backup.zip)",
         "Existe un archivo comprimido de backup accesible públicamente: puede contener el sitio completo, la base de datos y secretos.",
         "Retirar los backups del directorio público; guardarlos fuera de la raíz web y con nombres no predecibles."),
        ("/backup.sql",          _sig_sql,    "web-backup-exposed", "alta",
         "Volcado de base de datos accesible (backup.sql)",
         "Hay un volcado SQL accesible públicamente: expone el contenido completo de la base de datos (usuarios, hashes, datos personales).",
         "Retirar el volcado del directorio público de inmediato y evaluar la exposición de datos personales (RGPD)."),
    ]
    vistos = set()
    for ruta, sig, fid, sev, titulo, detalle, remediacion in PRUEBAS:
        if log:
            log(f"reconweb: comprobando {ruta}")
        r = _get(cliente, base, ruta)
        if _es_soft404(r, f404):
            continue
        if r.status_code != 200:
            continue
        t = _texto(r)
        if not sig(t, r):
            continue
        if fid in vistos:
            continue
        vistos.add(fid)
        emit({
            "id": fid, "severidad": sev, "titulo": titulo, "detalle": detalle,
            "remediacion": remediacion,
            "evidencia": f"GET {ruta} → {r.status_code} ({len(r.content or b'')} B)",
        })


def _informativos(cliente, base, f404, emit, log) -> None:
    reveladores = []
    for ruta in ("/readme.html", "/license.txt"):
        if log:
            log(f"reconweb: comprobando {ruta}")
        r = _get(cliente, base, ruta)
        if not _es_soft404(r, f404) and r.status_code == 200:
            reveladores.append(f"{ruta} ({len(r.content or b'')} B)")
    if reveladores:
        emit({
            "id": "web-info-files", "severidad": "baja",
            "titulo": "Ficheros informativos accesibles (fingerprinting)",
            "detalle": "Ficheros estándar accesibles que revelan el gestor de contenidos y su versión, "
                       "facilitando la búsqueda de exploits conocidos: " + ", ".join(reveladores) + ".",
            "remediacion": "Bloquear o eliminar readme.html y license.txt en producción.",
            "evidencia": "; ".join(f"GET {x} → 200" for x in reveladores),
        })

    if log:
        log("reconweb: comprobando /.well-known/security.txt")
    r = _get(cliente, base, "/.well-known/security.txt")
    if r is None or r.status_code != 200:
        emit({
            "id": "web-no-securitytxt", "severidad": "informativo",
            "titulo": "Sin security.txt",
            "detalle": "No se publica /.well-known/security.txt: no hay un canal estándar para reportar "
                       "vulnerabilidades de forma responsable.",
            "remediacion": "Publicar /.well-known/security.txt con Contact, Expires y Preferred-Languages (RFC 9116).",
            "evidencia": f"GET /.well-known/security.txt → {r.status_code if r else 'sin respuesta'}",
        })


# --------------------------------------------------------------------------- #
#  WordPress
# --------------------------------------------------------------------------- #
def _detecta_wp(home_txt: str, cliente, base, f404) -> bool:
    if re.search(r"/wp-(content|includes)/", home_txt) or "wp-json" in home_txt:
        return True
    if re.search(r'name=["\']generator["\'][^>]*WordPress', home_txt, re.I):
        return True
    r = _get(cliente, base, "/wp-login.php")
    return bool(r and r.status_code == 200 and "user_login" in _texto(r))


def _wordpress(cliente, base, host, home_txt, f404, emit, log) -> dict:
    tech = {"wordpress": True, "version": None, "plugins": []}

    # Versión por meta generator de la portada.
    m = re.search(r'name=["\']generator["\']\s+content=["\']WordPress\s*([0-9.]+)', home_txt, re.I)
    if m:
        tech["version"] = m.group(1)

    # Namespaces/plugins vía el índice REST.
    if log:
        log("reconweb: leyendo índice wp-json")
    r = _get(cliente, base, "/wp-json/")
    if r is not None and r.status_code == 200:
        try:
            data = r.json()
            ns = [n for n in data.get("namespaces", []) if n not in ("wp/v2", "wp/v1", "oembed/1.0")]
            tech["plugins"] = ns
        except Exception:
            pass

    plugins = (" · plugins detectados: " + ", ".join(tech["plugins"])) if tech["plugins"] else ""
    emit({
        "id": "wp-detected", "severidad": "informativo",
        "titulo": "WordPress detectado",
        "detalle": f"El sitio funciona con WordPress{(' ' + tech['version']) if tech['version'] else ''}{plugins}.",
        "remediacion": "Mantener el núcleo y los plugins actualizados; ocultar la versión (quitar el meta generator).",
        "evidencia": "wp-content / wp-json presentes en la portada",
    })

    # Enumeración de usuarios vía REST.
    if log:
        log("reconweb: comprobando enumeración de usuarios (REST)")
    usuarios = []
    r = _get(cliente, base, "/wp-json/wp/v2/users")
    if r is not None and r.status_code == 200:
        try:
            for u in r.json():
                usuarios.append({"id": u.get("id"), "slug": u.get("slug"), "name": u.get("name")})
        except Exception:
            pass
    if usuarios:
        muestra = ", ".join(f'{u["slug"]} ("{u["name"]}")' for u in usuarios[:5] if u.get("slug"))
        emit({
            "id": "wp-user-enum", "severidad": "media",
            "titulo": "Enumeración de usuarios de WordPress (REST API)",
            "detalle": "El endpoint /wp-json/wp/v2/users responde sin autenticación y revela los nombres de "
                       "usuario (login/slug) y nombres reales. Es el dato más accionable para un ataque de "
                       "contraseña o phishing dirigido.",
            "remediacion": "Restringir el endpoint REST de usuarios a peticiones autenticadas (plugin de seguridad "
                           "o filtro rest_endpoints), y usar un 'nombre para mostrar' distinto del login.",
            "evidencia": f"GET /wp-json/wp/v2/users → 200; usuarios: {muestra}",
        })

    # XML-RPC habilitado.
    if log:
        log("reconweb: comprobando xmlrpc.php")
    r = _get(cliente, base, "/xmlrpc.php")
    if r is not None and r.status_code in (200, 405) and "XML-RPC" in _texto(r):
        emit({
            "id": "wp-xmlrpc", "severidad": "media",
            "titulo": "XML-RPC habilitado",
            "detalle": "xmlrpc.php está activo. Permite amplificar ataques de fuerza bruta (system.multicall) y "
                       "abusos de pingback para DDoS reflejado.",
            "remediacion": "Deshabilitar XML-RPC si no se usa (Jetpack/app móvil) mediante plugin o regla del "
                           "servidor; si se necesita, limitarlo por IP y método.",
            "evidencia": f"GET /xmlrpc.php → {r.status_code} ('XML-RPC server accepts POST requests only')",
        })

    # wp-login expuesto.
    r = _get(cliente, base, "/wp-login.php")
    if r is not None and r.status_code == 200:
        emit({
            "id": "wp-login-exposed", "severidad": "informativo",
            "titulo": "Página de acceso de WordPress en la ruta por defecto",
            "detalle": "wp-login.php es accesible en su ruta estándar sin protección visible (ni 2FA ni límite de "
                       "intentos detectable desde fuera): facilita el credential stuffing.",
            "remediacion": "Activar 2FA para administradores, limitar intentos de acceso y considerar cambiar la URL "
                           "de login y añadir un CAPTCHA.",
            "evidencia": "GET /wp-login.php → 200",
        })

    return tech


# --------------------------------------------------------------------------- #
#  Punto de entrada
# --------------------------------------------------------------------------- #
def scan(url: str, *, timeout: float = 8.0, log=None) -> dict:
    """Ejecuta el reconocimiento activo-ligero. Devuelve {'ok', 'objetivo', 'findings', 'tecnologia'}."""
    base = _norm_base(url)
    host = urlparse(base).netloc
    findings: list[dict] = []
    emit = findings.append

    headers = {"User-Agent": _UA, "Accept": "*/*"}
    try:
        with httpx.Client(follow_redirects=False, timeout=timeout, headers=headers, verify=True) as cliente:
            if log:
                log(f"reconweb: objetivo {host}")
            f404 = _firma_404(cliente, base)

            home = _get(cliente, base, "/")
            # Si la portada redirige (p. ej. http→https o a /es/), seguimos una vez.
            if home is not None and home.status_code in (301, 302, 303, 307, 308):
                loc = home.headers.get("location", "")
                if loc:
                    nb = _norm_base(urljoin(base, loc))
                    if urlparse(nb).netloc == host or urlparse(nb).netloc.endswith("." + host) or host.endswith("." + urlparse(nb).netloc):
                        base = nb
                        f404 = _firma_404(cliente, base)
                        home = _get(cliente, base, "/")
            home_txt = _texto(home) if home is not None else ""

            _ficheros_sensibles(cliente, base, f404, host, emit, log)
            _informativos(cliente, base, f404, emit, log)

            tecnologia = {}
            if _detecta_wp(home_txt, cliente, base, f404):
                tecnologia = _wordpress(cliente, base, host, home_txt, f404, emit, log)
    except Exception as e:  # noqa: BLE001 — el caller lo reporta como fallo del job
        return {"ok": False, "error": f"reconweb no pudo completarse: {type(e).__name__}: {e}", "findings": []}

    return {"ok": True, "objetivo": host, "findings": findings, "tecnologia": tecnologia}
