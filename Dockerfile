FROM python:3.11-slim

# Instalar utilidades + Java + jq + procps
RUN apt-get update && \
    apt-get install -y wget gnupg procps && \
    echo "deb http://deb.debian.org/debian bookworm main" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y openjdk-17-jre-headless iputils-ping curl nmap dnsutils jq wget unzip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install python-owasp-zap-v2.4

# Copiar todo el proyecto
COPY . .

# Instalar OWASP ZAP
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2_16_1_unix.sh -O /tmp/zap.sh && \
    chmod +x /tmp/zap.sh && \
    /tmp/zap.sh -q -dir /opt/zap && \
    rm /tmp/zap.sh

# Crear carpeta de reportes
RUN mkdir -p /app/reports && chmod -R 777 /app/reports

# Verificar que los scripts estén en su lugar
RUN ls -la /app/
RUN ls -la /app/reports/

# Asegurar que el directorio reports tenga los permisos correctos
RUN chown -R root:root /app/reports && chmod -R 777 /app/reports

EXPOSE 5000

CMD ["python", "app.py"]
