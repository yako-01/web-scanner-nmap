FROM python:3.11-slim

# Instalar utilidades + Java (para ZAP) + jq
RUN apt-get update && \
    apt-get install -y iputils-ping curl nmap dnsutils openjdk-17-jre jq wget unzip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar todo el proyecto a /app
COPY . .

# Instalar OWASP ZAP
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2_15_0_unix.sh -O /tmp/zap.sh && \
    chmod +x /tmp/zap.sh && \
    /tmp/zap.sh -q -dir /opt/zap && \
    rm /tmp/zap.sh

# Crear carpeta de reportes con permisos
RUN mkdir -p /app/reports && chmod -R 777 /app/reports

EXPOSE 5000

CMD ["python", "app.py"]