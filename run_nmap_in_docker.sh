#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <IP o dominio>"
  exit 1
fi

TARGET="$1"
CONTAINER_NAME="flask_project_container"

# Verificar si el contenedor está ejecutándose
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "Error: El contenedor $CONTAINER_NAME no está ejecutándose."
    echo "Por favor, inicia el contenedor primero con: docker-compose up -d"
    exit 1
fi

echo "Ejecutando escaneo nmap en el contenedor Docker..."
echo "Target: $TARGET"

# Ejecutar el script nmap dentro del contenedor
docker exec "$CONTAINER_NAME" /app/scan_nmap.sh "$TARGET"

echo ""
echo "Escaneo completado. Revisa los archivos generados:"
echo "- Reporte: reports/rapport_nmap_${TARGET}_*.txt"
echo "- Datos intermedios: intermediate/nmap_${TARGET}_*.txt"
