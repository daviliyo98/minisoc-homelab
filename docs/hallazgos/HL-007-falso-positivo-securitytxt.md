# HL-007: Falso positivo en la detección de security.txt (soft-404)

| Campo | Valor |
|---|---|
| Fecha | 2026-10-02 |
| Severidad | Media |
| Activo afectado | websec-scanner (lógica de detección) |
| Estado | Resuelto |

## Resumen

El check de `security.txt` del scanner marcaba como existente un archivo que en
realidad no existía. El objetivo (un portal de login corporativo) devolvía su
página de inicio de sesión con código **200 para cualquier ruta** (patrón
"soft-404"), y la detección ingenua lo daba por válido.

## Evidencia

Petición a `/.well-known/security.txt` → respuesta HTTP 200 cuyo cuerpo era:

```html
<!DOCTYPE HTML ...><html><head><title>customer.example.es</title>...
... "Session Expired" ... formulario de login ...
```

La lógica original aceptaba cualquier 200 que contuviera la subcadena "contact":

```python
if r.status_code == 200 and "contact" in r.text.lower():
    return {"existe": True, ...}
```

La página de login contenía esa palabra → falso positivo.

## Impacto

Un falso positivo aquí es grave en el flujo de trabajo: podría llevar a creer
que un sitio **invita** a reportes de seguridad (RFC 9116) cuando no es así, y a
contactar o actuar sin autorización real.

## Remediación

Validación conforme a RFC 9116 antes de aceptar el archivo:

```python
looks_html = "<html" in text.lower() or "<!doctype" in text.lower()
has_contact = re.search(r"(?im)^\s*contact\s*:", text) is not None
is_plain    = "text/html" not in content_type
if has_contact and is_plain and not looks_html:
    ...  # security.txt válido
```

Exige: campo `Contact:` al inicio de línea, tipo de contenido que no sea HTML, y
que el cuerpo no parezca una página web.

## Verificación

| Entrada | Resultado |
|---|---|
| security.txt real (texto plano con `Contact:`) | Detectado ✔️ |
| Página de login HTML con la palabra "contact" | Rechazado ✔️ |

## Lección aprendida

Un "soft-404" (responder 200 para todo) rompe las detecciones ingenuas basadas
en el código de estado o en subcadenas. Validar el **formato** de la respuesta,
no solo su existencia, es la diferencia entre una herramienta fiable y una que
genera ruido. Los falsos positivos erosionan la confianza en cualquier sistema
de detección.
