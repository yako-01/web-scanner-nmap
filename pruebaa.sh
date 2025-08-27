#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <IP o dominio>"
  exit 1
fi

CIBLE="$1"
TIMESTAMP=$(date +"%d%m%Y_%H%M%S")
RAPPORT="reports/rapport_nmap_${CIBLE}_${TIMESTAMP}.txt"
LOGFILE="reports/scan.log"

PORTS="21,22,23,25,53,80,110,111,123,135,137,138,139,143,161,389,443,445,465,514,993,995,1025,1433,1521,2049,2082,2083,2222,3128,3306,3389,5432,5900,5985,5986,6379,6660,6667,7001,8000,8080,8081,8443,8888,9000,9200,10000,27017"

{
 echo "============================================================="
 echo "=========== RAPPORT D'ANALYSE COMPLÈTE AVEC NMAP ============"
 echo "============================================================="
 echo "Cible : $CIBLE" | tee -a $LOGFILE
 echo "Date : $(date)" | tee -a $LOGFILE
 echo ""
 echo "============================================================="
 echo "========= 1. RÉSOLUTION DNS – ADRESSES IP ASSOCIÉES ========="
 echo "============================================================="
 echo "lancement du résolveur DNS..." | tee -a $LOGFILE

 IP_LIST=$(nslookup "$CIBLE" 2>/dev/null | grep "Address:" | tail -n +2 | awk '{print $2}')
 FIRST_IP=$(echo "$IP_LIST" | head -n 1)
 NUM_IP=$(echo "$IP_LIST" | grep -c .)

 if [ "$NUM_IP" -eq 0 ]; then
  echo "Aucune adresse IP n'a pu être résolue pour le domaine." | tee -a $LOGFILE
 elif [ "$NUM_IP" -eq 1 ]; then
  echo "Adresse IP résolue : $FIRST_IP" | tee -a $LOGFILE
 else
  echo "Le domaine possède plusieurs adresses IP :" | tee -a $LOGFILE
  echo "$IP_LIST" | tee -a $LOGFILE
 fi

 echo "" | tee -a $LOGFILE
 echo "Analyse des ports vulnérables..." | tee -a $LOGFILE
 echo "============================================================="
 echo "=========== 2. ANALYSE DES PORTS VULNÉRABLES ================"
 echo "============================================================="
 nmap -sT -p $PORTS -Pn $CIBLE

 echo "" | tee -a $LOGFILE
 echo "Détection des services et versions..." | tee -a $LOGFILE
 echo "============================================================="
 echo "=========== 3. DÉTECTION DES SERVICES ET VERSIONS ==========="
 echo "============================================================="
 nmap -sV -p $PORTS -Pn $CIBLE

 echo "" | tee -a $LOGFILE
 echo "Détection de Firewall..." | tee -a $LOGFILE
 echo "============================================================="
 echo "========== 4. DÉTECTION DE FIREWALL / FILTRAGE =============="
 echo "============================================================="
 nmap -sT -p $PORTS -Pn $CIBLE | grep -Ei "PORT|open|closed|filtered"

 echo "" | tee -a $LOGFILE
 echo "Dernière analyse rapide des ports communs..." | tee -a $LOGFILE
 echo "============================================================="
 echo "========== 5. SCAN RAPIDE DES PORTS COMMUNS ================"
 echo "============================================================="
 nmap -F $CIBLE

} > "$RAPPORT"

echo "Rapport NMAP généré : $RAPPORT"

cat "$RAPPORT"











#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <IP o domaine>"
  exit 1
fi

CIBLE="$1"
TIMESTAMP=$(date +"%d%m%Y_%H%M%S")
RAPPORT="reports/rapport_nmap_${CIBLE}_${TIMESTAMP}.txt"
LOGFILE="reports/scan_${CIBLE}_${TIMESTAMP}.log"

PORTS="21,22,23,25,53,80,110,111,123,135,137,138,139,143,161,389,443,445,465,514,993,995,1025,1433,1521,2049,2082,2083,2222,3128,3306,3389,5432,5900,5985,5986,6379,6660,6667,7001,8000,8080,8081,8443,8888,9000,9200,10000,27017"

# ==== Cabecera ====
{
  echo "============================================================="
  echo "=========== RAPPORT D'ANALYSE COMPLÈTE AVEC NMAP ============"
  echo "============================================================="
  echo "Cible : $CIBLE"
  echo "Date : $(date)"
  echo ""
} | tee -a "$RAPPORT" >> "$LOGFILE"

# ==== DNS ====
echo "Résolution DNS..." >> "$LOGFILE"
{
  echo "============================================================="
  echo "========= 1. RÉSOLUTION DNS – ADRESSES IP ASSOCIÉES ========="
  echo "============================================================="
} >> "$RAPPORT"

IP_LIST=$(nslookup "$CIBLE" 2>/dev/null | grep "Address:" | tail -n +2 | awk '{print $2}')
FIRST_IP=$(echo "$IP_LIST" | head -n 1)
NUM_IP=$(echo "$IP_LIST" | grep -c .)

if [ "$NUM_IP" -eq 0 ]; then
  echo "Aucune adresse IP trouvée" | tee -a "$LOGFILE" >> "$RAPPORT"
elif [ "$NUM_IP" -eq 1 ]; then
  echo "Adresse IP résolue : $FIRST_IP" | tee -a "$LOGFILE" >> "$RAPPORT"
else
  echo "Plusieurs adresses IP détectées :" | tee -a "$LOGFILE" >> "$RAPPORT"
  echo "$IP_LIST" | tee -a "$LOGFILE" >> "$RAPPORT"
fi
echo "" | tee -a "$LOGFILE" >> "$RAPPORT"

# ==== Scan des ports vulnérables ====
echo "Analyse des ports vulnérables..." >> "$LOGFILE"
{
  echo "============================================================="
  echo "=========== 2. ANALYSE DES PORTS VULNÉRABLES ================"
  echo "============================================================="
} >> "$RAPPORT"
nmap -sT -p $PORTS -Pn $CIBLE >> "$RAPPORT"

# ==== Services & versions ====
echo "Détection des services et versions..." >> "$LOGFILE"
{
  echo "============================================================="
  echo "=========== 3. DÉTECTION DES SERVICES ET VERSIONS ==========="
  echo "============================================================="
} >> "$RAPPORT"
nmap -sV -p $PORTS -Pn $CIBLE >> "$RAPPORT"

# ==== Firewall ====
echo "Détection de Firewall..." >> "$LOGFILE"
{
  echo "============================================================="
  echo "========== 4. DÉTECTION DE FIREWALL / FILTRAGE =============="
  echo "============================================================="
} >> "$RAPPORT"
nmap -sT -p $PORTS -Pn $CIBLE | grep -Ei "PORT|open|closed|filtered" >> "$RAPPORT"

# ==== Scan rapide ====
echo "Dernière analyse rapide des ports communs..." >> "$LOGFILE"
{
  echo "============================================================="
  echo "========== 5. SCAN RAPIDE DES PORTS COMMUNS ================"
  echo "============================================================="
} >> "$RAPPORT"
nmap -F $CIBLE >> "$RAPPORT"

# ==== Fin ====
echo "Rapport final généré : $RAPPORT" | tee -a "$LOGFILE"