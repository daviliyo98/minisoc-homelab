FROM python:3.12-slim

# Usuario sin privilegios (no root dentro del contenedor)
RUN useradd -m -u 10001 scanner

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

USER scanner
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
