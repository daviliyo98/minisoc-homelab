# websec-scanner

Analizador de postura de seguridad web. API en FastAPI que, dada una URL o un
dominio, informa de problemas de configuración. **Pasivo por defecto**: observa
solo lo que el servidor expone públicamente. Los módulos activos (Nuclei, ZAP,
testssl.sh) van detrás de varios candados.

## Alcance y legalidad

- Los módulos pasivos **no sondean rutas, no prueban parámetros, no atacan**.
- Rechaza objetivos internos/reservados (anti-SSRF por resolución DNS, en cada redirección).
- Escanea únicamente sistemas **propios o con autorización explícita**. Con
  `REQUIRE_VERIFIED_DOMAIN=1`, los escaneos activos solo se permiten contra dominios
  cuyo titular ha publicado un token en DNS (`POST /verify`).

## Uso

testssl.sh es un submódulo de git: clona con `git clone --recurse-submodules`, o en un
clon existente ejecuta `git submodule update --init` antes de construir la imagen.

```bash
cp .env.example .env            # genera claves: openssl rand -hex 32
docker compose up -d --build
curl -s -X POST http://192.168.1.20:8001/scan \
  -H "x-api-key: TU_CLAVE" -H "content-type: application/json" \
  -d '{"url":"https://ejemplo-autorizado.com"}' | jq
```

Interfaz web: `http://192.168.1.20:8001/` · Documentación interactiva: `/docs`

## Endpoints

| Endpoint | Rol | Qué hace |
|---|---|---|
| `POST /scan` | pasivo | Cabeceras, TLS, CAA, security.txt, redirección HTTPS, contenido mixto, SRI, CORS |
| `POST /scan-mail` | pasivo | Suplantación de correo: SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC, BIMI |
| `POST /scan-dns` | pasivo | Registros DNS y postura de infraestructura (redundancia NS, CAA, DNSSEC) |
| `POST /scan-recon` | pasivo | Subdominios (Certificate Transparency), subdomain takeover, puertos/CVEs (Shodan InternetDB) |
| `POST /scan-full` | pasivo | Web + correo + DNS en paralelo con puntuación global |
| `POST /scan-active` | activo | Nuclei (sin plantillas destructivas), en segundo plano |
| `POST /scan-zap` | activo | OWASP ZAP spider + pasivo (y activo de inyección con `activo=true`) |
| `POST /scan-tls` | activo | testssl.sh: protocolos, cifrados, cadena, Heartbleed, ROBOT, SWEET32… |
| `GET /scan-status/{id}` | pasivo | Estado de un trabajo en segundo plano (con log) |
| `GET /scans` · `GET /scans/{id}` | pasivo | Historial (filtros `objetivo`, `tipo`, `asset_id`) |
| `GET /scans/{id}/diff` | pasivo | Hallazgos nuevos / corregidos frente al escaneo anterior (o `?contra=<id>`) |
| `GET /scans/{id}/report?format=` | pasivo | Informe `html` (imprimible a PDF), `md`, `json` o `sarif`; `&precios=1` añade el presupuesto |
| `DELETE /scans/{id}` | activo | Cancela un trabajo en curso/en cola, o borra un escaneo terminado |
| `GET/POST/DELETE /assets` | admin* | Activos monitorizados (re-escaneo periódico y alertas) · *listar: pasivo |
| `POST /assets/{id}/run` | admin | Fuerza el escaneo inmediato de un activo |
| `POST /alerts/test` | admin | Prueba los canales de alerta |
| `POST /verify` · `POST /verify/{dominio}/check` | activo | Verificación de propiedad del dominio por TXT |
| `GET /audit` | admin | Quién escaneó qué y cuándo (incluye claves inválidas) |
| `GET /metrics` | — | Métricas Prometheus (opcional `METRICS_TOKEN`) |
| `GET /whoami` | pasivo | Rol de la clave y módulos habilitados |

## Claves y roles

`API_KEYS="fran:admin:<hex>,cliente1:pasivo:<hex>,pentest:activo:<hex>"`. Cada rol incluye
al anterior (`pasivo` < `activo` < `admin`). La antigua `API_KEY` sigue funcionando como admin.
Límite de `RATE_LIMIT_PER_MIN` peticiones por clave. Cada acción queda en la tabla de auditoría
y en stdout como `AUDIT {json}` (apto para CrowdSec/Loki).

## Pago por hallazgo

Cada escaneo terminado lleva `presupuesto`: una estimación con las reglas que publica la web.

| Concepto | Por defecto | Variable |
|---|---:|---|
| Cuota mínima (solo primer escaneo del objetivo) | 190 € | `PRECIO_CUOTA_MINIMA` |
| Crítica (CVSS 9.0–10) | 250 € | `PRECIO_CRITICA` |
| Alta (7.0–8.9) | 150 € | `PRECIO_ALTA` |
| Media (4.0–6.9) | 75 € | `PRECIO_MEDIA` |
| Baja (0.1–3.9) | 25 € | `PRECIO_BAJA` |
| Info | 0 € | — |
| Tope máximo por escaneo | 690 € | `PRECIO_TOPE` |

Solo cuentan hallazgos únicos. En los re-escaneos del mismo objetivo y tipo solo se cobran los
nuevos, sin cuota mínima. Es una estimación previa a la validación manual: en la factura solo
entran los hallazgos confirmados. Importes sin IVA.

## Monitorización continua

Un planificador interno re-escanea cada activo según su intervalo, lo compara con el escaneo
anterior y avisa por **webhook** (`ALERT_WEBHOOK_URL`) y/o **Telegram** de: hallazgos nuevos
con CVSS ≥ `ALERT_MIN_CVSS`, certificado que caduca en ≤ `ALERT_CERT_DAYS` días y bajadas de
puntuación de 10+ puntos. `/metrics` alimenta el dashboard de Grafana
(`stacks/monitoring/grafana/provisioning/dashboards/websec-scanner.json`).

## Trabajos en segundo plano

Nuclei, ZAP y testssl.sh se encolan: como mucho `JOBS_MAX_CONCURRENT` a la vez (1 por defecto,
para no agotar la memoria de la Pi). Se pueden cancelar con `DELETE /scans/{id}`.

## Seguridad del propio contenedor

- Usuario sin privilegios, `read_only`, `cap_drop: ALL`, `no-new-privileges`.
- Lo único escribible: `/tmp` (tmpfs) y el volumen `/data` (SQLite).
- Publicado solo en la LAN (192.168.1.20:8001) y protegido con claves de API.

## Tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

## Hoja de ruta

- [x] Informe descargable (HTML/PDF, Markdown, SARIF)
- [x] Más checks pasivos (contenido mixto, SRI, CORS, cookies por atributos)
- [x] Historial, comparación entre escaneos y monitorización con alertas
- [x] Verificación de propiedad del dominio para los escaneos activos
- [ ] Escaneo ZAP autenticado (contexto con login) e importación de OpenAPI
- [ ] Detección de tecnologías con versión cruzada con OSV/NVD
- [ ] Mapeo de hallazgos a ENS / NIS2 / ISO 27001
