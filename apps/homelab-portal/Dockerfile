FROM python:3.12-slim

# Usuario sin privilegios (no root dentro del contenedor), mismo UID que el resto
# de apps del homelab para que los volúmenes compartan propietario.
RUN useradd -m -u 10001 portal

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# /data para la SQLite del historial. Se crea aquí con el dueño correcto porque un
# volumen con nombre copia los permisos de la imagen la primera vez que se monta.
RUN mkdir -p /data && chown portal:portal /data
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER portal
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]