# Home Assistant

Control de los aparatos inteligentes de casa: **Xiaomi Robot Vacuum T12** y **Alexa**.
El portal (`apps/homelab-portal`, sección *Dispositivos*) los monitoriza; aquí se
controlan. Separarlo es deliberado: este contenedor guarda tokens de las nubes de
Xiaomi y Amazon, y el portal no debe tenerlos.

## Arranque

```bash
cd ~/minisoc-homelab/stacks/homeassistant
mkdir -p config && chmod 700 config        # tokens en claro: solo el dueño
sudo docker compose up -d
sudo docker logs -f homeassistant          # Ctrl+C cuando ponga "Home Assistant initialized"
```

Abre `http://192.168.1.20:8123` (o `http://100.114.119.53:8123` por Tailscale) y crea
el usuario administrador. **Contraseña larga y única**, y activa la verificación en
dos pasos en *Perfil → Seguridad → Módulos de autenticación multifactor*.

El primer arranque en la Pi tarda unos minutos: descarga dependencias.

## Xiaomi Robot Vacuum T12

Se usa la integración **oficial de Xiaomi**, [`ha_xiaomi_home`](https://github.com/XiaoMi/ha_xiaomi_home).
Sirve para los aparatos MIoT que aparecen en la app Mi Home. Antes de instalarla,
comprueba que el T12 está vinculado a tu cuenta en esa app.

```bash
cd ~/minisoc-homelab/stacks/homeassistant
git clone --depth 1 https://github.com/XiaoMi/ha_xiaomi_home.git /tmp/ha_xiaomi_home
sudo mkdir -p config/custom_components
sudo cp -r /tmp/ha_xiaomi_home/custom_components/xiaomi_home config/custom_components/
rm -rf /tmp/ha_xiaomi_home
sudo docker restart homeassistant
```

En Home Assistant: *Ajustes → Dispositivos y servicios → Añadir integración →
Xiaomi Home*. Te lleva a la web de Xiaomi para iniciar sesión (OAuth 2.0: Home
Assistant no ve tu contraseña). Elige la región de tu cuenta (Europa) y marca el robot.

Para actualizarla, repite el `git clone` y la copia. También se puede instalar con
HACS, pero eso añade otra pieza con acceso a GitHub y a tu configuración.

## Alexa

Integración **Alexa Devices**, incluida en Home Assistant desde la 2025.6:
*Añadir integración → Alexa Devices*. Pide:

- correo y contraseña de Amazon, y
- un código de una **app de autenticación** (Google Authenticator, Aegis...). La
  verificación por SMS no vale: la app de autenticación tiene que ser tu método
  preferido de 2FA en Amazon.

Permite que Alexa diga avisos en voz alta (`notify.send_message`), ver
alarmas y temporizadores y los sensores de temperatura de los Echo que los tienen.
Consulta Amazon cada 5 minutos.

## Seguridad: qué se está aceptando

| Riesgo | Mitigación |
|---|---|
| `config/` guarda los tokens de Xiaomi en **texto plano** (lo dice el propio README de Xiaomi) y la sesión de Amazon | `chmod 700 config`, en `.gitignore`, fuera de cualquier backup que salga de casa sin cifrar |
| La sesión de Amazon permite actuar sobre tu cuenta | 2FA obligatorio con app; revisa *Amazon → Tu cuenta → Dispositivos de confianza* de vez en cuando |
| Home Assistant escucha en LAN y tailnet (8123) | Nunca abrir el puerto en el router; MFA en el usuario de Home Assistant |
| El robot y los Echo "llaman a casa" | Lo ves en el portal: *Dispositivos* → dominios consultados y bloqueados por Pi-hole |

Si algo de esto se queda pendiente, documéntalo como hallazgo en `docs/hallazgos/`.
