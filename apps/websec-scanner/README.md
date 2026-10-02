# websec-scanner

Analizador **pasivo** de postura de seguridad web. API en FastAPI que, dada una
URL, informa de problemas de configuración observando **solo lo que el servidor
expone públicamente**: cabeceras de seguridad, configuración TLS y `security.txt`.

## Alcance y legalidad

- **No sondea rutas, no prueba parámetros, no ataca.** Hace lo mismo que un navegador.
- Rechaza objetivos internos/loopback (10/8, 192.168/16, 172.16/12, localhost).
- Escanea únicamente sistemas **propios o con autorización explícita** (contrato,
  programa de bug bounty o `security.txt` del propietario).

## Uso

```bash
cp .env.example .env            # genera una clave: openssl rand -hex 32
docker compose up -d --build
curl -s -X POST http://192.168.1.20:8001/scan \
  -H "x-api-key: TU_CLAVE" -H "content-type: application/json" \
  -d '{"url":"https://ejemplo-autorizado.com"}' | jq
```

Documentación interactiva: `http://192.168.1.20:8001/docs`

## Seguridad del propio contenedor

- Usuario sin privilegios, `read_only`, `cap_drop: ALL`, `no-new-privileges`.
- Publicado solo en la LAN (192.168.1.20:8001) y protegido con clave de API.

## Checks actuales

| Check | Detecta |
|---|---|
| Cabeceras HTTP | HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy ausentes; fugas de versión; cookies sin Secure/HttpOnly |
| TLS | Certificado caducado o próximo a caducar, protocolos obsoletos (TLS 1.0/1.1) |
| security.txt | Si la web publica un canal de divulgación responsable (RFC 9116) |

## Hoja de ruta

- [ ] Informe en HTML descargable
- [ ] Más checks pasivos (cabeceras de caché, cookies SameSite, mixed content)
- [ ] Checks activos (fuzzing de rutas) SOLO con lista blanca de dominios autorizados
