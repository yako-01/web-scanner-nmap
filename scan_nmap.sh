#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <IP o dominio>"
  exit 1
fi

CIBLE="$1"
TIMESTAMP=$(date +"%d%m%Y_%H%M%S")
RAPPORT="reports/rapport_nmap_${CIBLE}_${TIMESTAMP}.txt"

PORTS="21,22,23,25,53,80,110,111,123,135,137,138,139,143,161,389,443,445,465,514,993,995,1025,1433,1521,2049,2082,2083,2222,3128,3306,3389,5432,5900,5985,5986,6379,6660,6667,7001,8000,8080,8081,8443,8888,9000,9200,10000,27017"

{
 echo "============================================================="
 echo "=========== RAPPORT D'ANALYSE COMPLÈTE AVEC NMAP ============"
 echo "============================================================="
 echo "Cible : $CIBLE"
 echo "Date : $(date)"
 echo ""
 echo "============================================================="
 echo "========= 1. RÉSOLUTION DNS – ADRESSES IP ASSOCIÉES ========="
 echo "============================================================="

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

 echo "============================================================="
 echo "====== 2. ANALYSE DES PORTS VULNÉRABLES (TCP) =============="
 echo "============================================================="
 nmap -sT -p $PORTS -Pn $CIBLE

 echo ""
 echo "============================================================="
 echo "======= 3. DÉTECTION DES SERVICES ET VERSIONS (-sV) ========"
 echo "============================================================="
 nmap -sV -p $PORTS -Pn $CIBLE

 echo ""
 echo "============================================================="
 echo "========== 4. DÉTECTION DE FIREWALL / FILTRAGE =============="
 echo "============================================================="
 nmap -sT -p $PORTS -Pn $CIBLE | grep -Ei "PORT|open|closed|filtered"

 echo ""
 echo "============================================================="
 echo "========== 5. SCAN RAPIDE DES PORTS COMMUNS ================"
 echo "============================================================="
 nmap -F $CIBLE

} > "$RAPPORT"

echo "Rapport généré : $RAPPORT"

cat "$RAPPORT"