#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <IP o dominio>"
  exit 1
fi

CIBLE="$1"
TIMESTAMP=$(date +"%d%m%Y_%H%M%S")
RAPPORT="reports/rapport_nmap_${CIBLE}_${TIMESTAMP}.txt"
INTERMEDIATE_FILE="intermediate/nmap_${CIBLE}_${TIMESTAMP}.txt"

PORTS="21,22,23,25,53,80,110,143,443,445,465,993,995,1433,1521,3306,3389,5432,5900,8080,8443,27017"

# Preparar directorio para datos intermedios
mkdir -p "intermediate"

# Ejecutar Nmap una sola vez por tipo de escaneo y reutilizar salidas
# Usar timeout para evitar que se cuelgue indefinidamente
echo "Ejecutando escaneo TCP (-sT)..."
NMAP_ST_OUTPUT=$(timeout 300 nmap -sT -p $PORTS -Pn "$CIBLE" 2>/dev/null)
if [ $? -eq 124 ]; then
    echo "Error: Timeout en escaneo TCP después de 5 minutos"
    NMAP_ST_OUTPUT=""
fi

echo "Ejecutando escaneo de versiones (-sV)..."
NMAP_SV_OUTPUT=$(timeout 600 nmap -sV -p $PORTS -Pn "$CIBLE" 2>/dev/null)
if [ $? -eq 124 ]; then
    echo "Error: Timeout en escaneo de versiones después de 10 minutos"
    NMAP_SV_OUTPUT=""
fi

# Construir listas intermedias
IP_LIST=$(nslookup "$CIBLE" 2>/dev/null | grep "Address:" | tail -n +2 | awk '{print $2}')
OPEN_PORTS=$(printf "%s\n" "$NMAP_ST_OUTPUT" | awk '/^[0-9]+\/[a-zA-Z]+/ && $2=="open" {split($1,a,"/"); print a[1]}' | sort -n | uniq)
CLOSED_PORTS=$(printf "%s\n" "$NMAP_ST_OUTPUT" | awk '/^[0-9]+\/[a-zA-Z]+/ && $2=="closed" {split($1,a,"/"); print a[1]}' | sort -n | uniq)
FILTERED_PORTS=$(printf "%s\n" "$NMAP_ST_OUTPUT" | awk '/^[0-9]+\/[a-zA-Z]+/ && $2=="filtered" {split($1,a,"/"); print a[1]}' | sort -n | uniq)
SERVICE_VERSIONS=$(printf "%s\n" "$NMAP_SV_OUTPUT" | awk '/^[0-9]+\/[a-zA-Z]+/ && $2=="open" {svc=$3; ver=""; if (NF>=4) {for(i=4;i<=NF;i++){ver=ver $i " "}} gsub(/^\s+|\s+$/, "", ver); print $1 " " svc " " ver}' | sed 's/\s\+$//')

# También hacer un escaneo rápido para detectar puertos comunes que podrían estar abiertos
echo "Ejecutando escaneo rápido de puertos comunes..."
NMAP_FAST_OUTPUT=$(timeout 120 nmap -F "$CIBLE" 2>/dev/null)
FAST_OPEN_PORTS=$(printf "%s\n" "$NMAP_FAST_OUTPUT" | awk '/^[0-9]+\/[a-zA-Z]+/ && $2=="open" {split($1,a,"/"); print a[1]}' | sort -n | uniq)

# Combinar puertos abiertos de ambos escaneos
ALL_OPEN_PORTS=$(printf "%s\n%s\n" "$OPEN_PORTS" "$FAST_OPEN_PORTS" | sort -n | uniq)

# Escribir fichero intermedio etiquetado por secciones
{
  echo "TARGET: $CIBLE"
  echo "TIMESTAMP: $TIMESTAMP"
  echo "RESOLVED_IPS:"
  if [ -n "$IP_LIST" ]; then echo "$IP_LIST"; fi
  echo "OPEN_PORTS:"
  if [ -n "$ALL_OPEN_PORTS" ]; then echo "$ALL_OPEN_PORTS"; fi
  echo "CLOSED_PORTS:"
  if [ -n "$CLOSED_PORTS" ]; then echo "$CLOSED_PORTS"; fi
  echo "FILTERED_PORTS:"
  if [ -n "$FILTERED_PORTS" ]; then echo "$FILTERED_PORTS"; fi
  echo "SERVICE_VERSIONS:"
  if [ -n "$SERVICE_VERSIONS" ]; then echo "$SERVICE_VERSIONS"; fi
} > "$INTERMEDIATE_FILE"

# Verificar que el fichero intermedio se creó correctamente
if [ -f "$INTERMEDIATE_FILE" ]; then
    echo "Fichero intermedio creado: $INTERMEDIATE_FILE"
    echo "Tamaño del fichero: $(wc -c < "$INTERMEDIATE_FILE") bytes"
else
    echo "Error: No se pudo crear el fichero intermedio"
fi

python3 rapport_nmap.py "$INTERMEDIATE_FILE"

{
 echo "============================================================="
 echo "=========== RAPPORT D'ANALYSE COMPLÈTE AVEC NMAP ============"
 echo "============================================================="
 echo "Cible : $CIBLE"
 echo "Date : $(date)"
 echo ""
 echo "========= 1. RÉSOLUTION DNS – ADRESSES IP ASSOCIÉES ========="

 IP_LIST=$(nslookup "$CIBLE" 2>/dev/null | grep "Address:" | tail -n +2 | awk '{print $2}')
 FIRST_IP=$(echo "$IP_LIST" | head -n 1)
 NUM_IP=$(echo "$IP_LIST" | grep -c .)

 if [ "$NUM_IP" -eq 0 ]; then
  echo "Aucune adresse IP n'a pu être résolue pour le domaine."
 elif [ "$NUM_IP" -eq 1 ]; then
  echo "Adresse IP résolue : $FIRST_IP"
 else
  echo "Le domaine possède plusieurs adresses IP :"
  echo "$IP_LIST"
 fi
 echo ""

 echo "====== 2. ANALYSE DES PORTS VULNÉRABLES (TCP) =============="
 printf "%s\n" "$NMAP_ST_OUTPUT"

 echo ""
 echo "======= 3. DÉTECTION DES SERVICES ET VERSIONS (-sV) ========"
 printf "%s\n" "$NMAP_SV_OUTPUT"

 echo ""
 echo "========== 4. DÉTECTION DE FIREWALL / FILTRAGE =============="
 printf "%s\n" "$NMAP_ST_OUTPUT" | grep -Ei "PORT|open|closed|filtered"

 echo ""
 echo "========== 5. SCAN RAPIDE DES PORTS COMMUNS ================"
 timeout 120 nmap -F $CIBLE 2>/dev/null

} > "$RAPPORT"

echo "Rapport NMAP généré : $RAPPORT"

echo "Intermediate NMAP data generated: $INTERMEDIATE_FILE"


cat "$RAPPORT"