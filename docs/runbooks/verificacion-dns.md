# Runbook: verificar que un dispositivo pasa por el filtrado DNS

## 1. Desde el host (Pi-hole)

Consultas por cliente en la última hora:

```bash
docker exec pihole pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db \
"SELECT client, COUNT(*) AS consultas
 FROM queries WHERE timestamp > strftime('%s','now')-3600
 GROUP BY client ORDER BY consultas DESC;"
```

Un dispositivo en uso con muy pocas consultas probablemente elude Pi-hole.

## 2. Correlación en directo

```bash
docker exec pihole tail -f /var/log/pihole/pihole.log \
  | grep --line-buffered -E "<IP_CLIENTE>|<DOMINIO_PRUEBA>"
```

En el dispositivo, abrir en una pestaña privada un dominio bloqueado **nunca visitado** (para descartar la caché), por ejemplo `http://pagead2.googlesyndication.com`.

| Resultado en el log | Interpretación |
|---|---|
| `gravity blocked ... is 0.0.0.0` | Filtrado correcto |
| No aparece la consulta | El dispositivo elude Pi-hole (IPv6, DoH, VPN, relay, datos móviles) |

## 3. Desde el dispositivo

| Prueba | Filtrado | Sin filtrar |
|---|---|---|
| `nslookup doubleclick.net` (PC) | `0.0.0.0` | IP real |
| dnsleaktest.com frente a ifconfig.me | Coincide con tu IP pública (Unbound) | IPs de los DNS del ISP |
| test-ipv6.com | Solo IPv4 | IPv6 activo: posible fuga |

## 4. Validar la cadena completa en el host

```bash
dig @127.0.0.1 -p 5335 fail01.dnssec.works | grep status   # SERVFAIL (Unbound valida DNSSEC)
dig @127.0.0.1 doubleclick.net +short                      # 0.0.0.0 (Pi-hole bloquea)
dig @127.0.0.1 wikipedia.org +short                        # IP real (resolución correcta)
```
