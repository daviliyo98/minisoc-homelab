# HL-006: Contenedor sin salida de red por preferencia de IPv6

| Campo | Valor |
|---|---|
| Fecha | 2026-10-02 |
| Severidad | Media |
| Activo afectado | websec-scanner (contenedor Docker) |
| Estado | Resuelto |

## Resumen

Al desplegar la API websec-scanner, cualquier escaneo fallaba con un error 500.
El contenedor resolvía los nombres de dominio correctamente pero no podía
establecer ninguna conexión saliente.

## Evidencia

```
# La resolución DNS funcionaba:
$ docker exec websec-scanner python -c "import socket; print(socket.gethostbyname('scanme.nmap.org'))"
45.33.32.156

# Pero la conexión fallaba:
httpx.ConnectError: [Errno 101] Network is unreachable
```

## Análisis

- El host tiene conectividad IPv6 porque el router del ISP la anuncia por
  Router Advertisement (relacionado con HL-001).
- Muchos dominios resuelven también a una dirección IPv6 (registro AAAA), y la
  librería cliente intentaba IPv6 primero.
- La red bridge por defecto de Docker (`docker0`) es solo IPv4, así que el
  intento de salida por IPv6 devolvía "Network is unreachable".
- Error en cascada con un segundo problema: la diana de prueba inicial
  (`scanme.nmap.org`) no sirve HTTPS, lo que daba "Connection refused" y
  despistaba el diagnóstico.

## Remediación

1. Forzar IPv4 en el cliente HTTP y en el socket TLS de la aplicación
   (`local_address="0.0.0.0"` y `getaddrinfo(..., AF_INET)`).
2. Manejo de errores de conexión en la API: devuelve 502/504 con un mensaje
   claro en lugar de un 500 genérico.

## Verificación

```
$ curl -s -X POST .../scan -d '{"url":"https://nmap.org"}'
{"objetivo":"https://nmap.org","puntuacion":45,...,"tls":{"version":"TLSv1.3",...}}
```

## Lección aprendida

Dos causas superpuestas (preferencia de IPv6 + diana sin HTTPS) producían
síntomas distintos que confundían el diagnóstico. Cambiar una variable cada vez
(IPv4 forzado → cambia el error; diana con HTTPS → éxito) permite aislar cada
causa. Además, un servicio robusto nunca debe responder con un 500 ante una
condición de red esperable.
