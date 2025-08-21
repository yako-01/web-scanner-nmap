#!/bin/bash

# Hacer el script ejecutable
chmod +x "$0"

CIBLE="$1"
ZAP_PATH="/opt/zap/zap.sh"
API_KEY="12345"
PORT=$(shuf -i 8000-8999 -n 1)
TMP_DIR=$(mktemp -d)
RAPPORT_JSON="$TMP_DIR/zap_report.json"
SCRIPT_PY="/app/re_script.py"
TIMESTAMP=$(date +%s)

#echo "DEBUG - Ruta del script Python: $SCRIPT_PY"
#echo "DEBUG - ¿Existe el script Python? $(test -f "$SCRIPT_PY" && echo "SÍ" || echo "NO")"

if [ -z "$CIBLE" ]; then
    echo "Utilisation : $0 <url_cible>"
    exit 1
fi

# Normalizar URL: probar https primero si el usuario no pasó protocolo
if [[ ! "$CIBLE" =~ ^https?:// ]]; then
    PROBE="https://$CIBLE"
    if curl -skI --max-time 8 "$PROBE" >/dev/null; then
        CIBLE="$PROBE"
    else
        CIBLE="http://$CIBLE"
    fi
fi

# Extraer dominio de forma segura para el nombre del archivo
DOMAINE_CLEAN=$(echo "$CIBLE" | awk -F[/:] '{print $4}' | sed 's/^www\\.//' | sed 's/[^a-zA-Z0-9.-]/_/g')
# Mantener también la URL completa como DOMAINE para el script Python
DOMAINE="$CIBLE"

#echo "DEBUG - Objetivo original: $CIBLE"
#echo "DEBUG - Dominio limpio para archivo: $DOMAINE_CLEAN"

# Configurar ruta de salida con dominio limpio
SORTIE="/app/reports/rapport_zap_${DOMAINE_CLEAN}_${TIMESTAMP}.txt"
#echo "DEBUG - Ruta de salida configurada: $SORTIE"

#echo "DEBUG - Directorio actual: $(pwd)"
#echo "DEBUG - Contenido del directorio actual:"
#ls -la
#echo "DEBUG - Verificando directorio reports:"
#ls -la /app/reports/ || echo "Directorio reports no existe"

echo "Démarrage de ZAP sur le port $PORT..."
"$ZAP_PATH" -daemon -port $PORT -dir "$TMP_DIR" \
  -config api.key=$API_KEY \
  -config api.addrs.addr.name=127.0.0.1 \
  -config api.addrs.addr.regex=false \
  > "$TMP_DIR/zap.log" 2>&1 & #redirige la salida de ZAP a un archivo de log

ZAP_PID=$! #guarda el PID de ZAP en una variable

# Attente que ZAP soit prêt
echo "Vérification de la disponibilité complète de ZAP (et du module Spider)..."
for i in {1..60}; do
    sleep 2

    if ! ps -p $ZAP_PID > /dev/null; then #verifica si el proceso ZAP está en ejecución
        echo "Erreur : ZAP s'est arrêté prématurément"
        cat "$TMP_DIR/zap.log"
        exit 1

    fi    
    # verifica si la API de ZAP está disponible
    curl -s "http://127.0.0.1:$PORT/JSON/core/view/version/?apikey=$API_KEY" | jq -e '.version' > /dev/null || continue

    # verifica si el modulo Spider está disponible
    curl -s "http://127.0.0.1:$PORT/JSON/spider/view/status/?apikey=$API_KEY" | jq -e '.status' > /dev/null && { 
        echo "L'API ZAP et le module Spider sont prêts"
        break
    }

    echo "    En attente du module Spider..."
done

# iniciamineto del Spider
echo "Lancement du spider sur $CIBLE"
SCAN_ID=$(curl -s "http://127.0.0.1:$PORT/JSON/spider/action/scan/?apikey=$API_KEY&url=$CIBLE" | jq -r .scan)
if [ -z "$SCAN_ID" ] || [ "$SCAN_ID" = "null" ]; then #verifica si el spider se ha iniciado correctamente
    echo "Erreur : Impossible de lancer le spider. Voir le log :"
    cat "$TMP_DIR/zap.log" 
    kill $ZAP_PID 2>/dev/null 
    wait $ZAP_PID 2>/dev/null 
    exit 1
fi

while true; do
    STATUT=$(curl -s "http://127.0.0.1:$PORT/JSON/spider/view/status/?apikey=$API_KEY&scanId=$SCAN_ID" | jq -r .status)
    echo "    Progression du spider : $STATUT%"
    [ "$STATUT" = "100" ] && break #si el spider ha terminado, se sale del bucle
    sleep 5
done

# AJAX Spider (mejor para apps SPA)
echo "Lancement de l'AJAX Spider sur $CIBLE"
curl -s "http://127.0.0.1:$PORT/JSON/ajaxSpider/action/scan/?apikey=$API_KEY&url=$CIBLE" >/dev/null
for i in {1..60}; do
    STAT=$(curl -s "http://127.0.0.1:$PORT/JSON/ajaxSpider/view/status/?apikey=$API_KEY" | jq -r .status)
    echo "    Statut AJAX Spider : $STAT"
    [ "$STAT" = "stopped" ] && break
    sleep 5
done

# Configuration agressive, active tous les scanners
curl -s "http://127.0.0.1:$PORT/JSON/ascan/action/enableAllScanners/?apikey=$API_KEY" > /dev/null
#curl -s "http://127.0.0.1:$PORT/JSON/ascan/action/setOptionAttackStrength/?apikey=$API_KEY&attackStrength=HIGH" > /dev/null
#curl -s "http://127.0.0.1:$PORT/JSON/ascan/action/setOptionAlertThreshold/?apikey=$API_KEY&alertThreshold=LOW" > /dev/null

# Scan actif
echo "Lancement du scan actif..."
SCAN_ID=$(curl -s "http://127.0.0.1:$PORT/JSON/ascan/action/scan/?apikey=$API_KEY&url=$CIBLE&recurse=true&inScopeOnly=false" | jq -r .scan)
while true; do
    STATUT=$(curl -s "http://127.0.0.1:$PORT/JSON/ascan/view/status/?apikey=$API_KEY&scanId=$SCAN_ID" | jq -r .status)
    echo "    Progression du scan actif : $STATUT%"
    [ "$STATUT" = "100" ] && break
    sleep 10
done

# Récupération du rapport JSON
echo "Génération du rapport..."
curl -s "http://127.0.0.1:$PORT/JSON/core/view/alerts/?apikey=$API_KEY" -o "$RAPPORT_JSON"
echo "DEBUG - Reporte JSON generado: $RAPPORT_JSON"
echo "DEBUG - ¿Existe el reporte JSON? $(test -f "$RAPPORT_JSON" && echo "SÍ" || echo "NO")"
if [ -f "$RAPPORT_JSON" ]; then
    echo "DEBUG - Tamaño del reporte JSON: $(ls -lh "$RAPPORT_JSON")"
fi

# arrêt de ZAP
kill $ZAP_PID 2>/dev/null
wait $ZAP_PID 2>/dev/null

# Traitement du script Python
#echo "DEBUG - Ejecutando script Python: $SCRIPT_PY"
#echo "DEBUG - Con argumentos: $DOMAINE $RAPPORT_JSON $SORTIE"
python3 "$SCRIPT_PY" "$DOMAINE" "$RAPPORT_JSON" "$SORTIE"

# Verificar que el archivo se creó
#if [ -f "$SORTIE" ]; then
    #echo "DEBUG - Archivo creado exitosamente: $SORTIE"
    #echo "DEBUG - Tamaño del archivo: $(ls -lh "$SORTIE")"
#else
    #echo "DEBUG - ERROR: El archivo no se creó: $SORTIE"
    #echo "DEBUG - Contenido del directorio reports:"
    #ls -la /app/reports/
#fi

echo "Rapport ZAP généré : $SORTIE"

# Nettoyage
rm -rf "$TMP_DIR"
                    