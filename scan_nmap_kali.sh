#!/bin/bash


if [ -z "$1" ]; then
 echo "Utilisation : $0 <IP ou domaine>"
 exit 1
fi


CIBLE="$1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RAPPORT="reports/rapport_nmap_${CIBLE}_${TIMESTAMP}.txt"


# Résolution DNS – récupération des adresses IP associées au domaine
IP_LIST=$(getent ahosts "$CIBLE" | awk '{ print $1 }' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
FIRST_IP=$(echo "$IP_LIST" | head -n 1)
IP_COUNT=$(echo "$IP_LIST" | grep -c .)


# Ports courants et vulnérables
PORTS_TCP="21,22,23,25,53,80,110,111,123,135,137,138,139,143,161,389,443,445,465,514,993,995,1025,1433,1521,2049,2082,2083,2222,3128,3306,3389,5432,5900,5985,5986,6379,6660,6667,7001,8000,8080,8081,8443,8888,9000,9200,10000,27017"
PORTS_UDP="53,67,69,123,161,162,500,514"


echo "Cible : $CIBLE"
echo "Démarrage de l'analyse..."
echo


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


if [ "$IP_COUNT" -eq 0 ]; then
 echo "Aucune adresse IP n'a pu être résolue pour le domaine."
elif [ "$IP_COUNT" -eq 1 ]; then
 echo "Adresse IP résolue : $FIRST_IP"
else
 echo "Le domaine possède plusieurs adresses IP :"
 echo "$IP_LIST"
fi
echo ""




 echo "============================================================="
 echo "====== 2. ANALYSE DES PORTS VULNÉRABLES (TCP et UDP) ========"
 echo "============================================================="
 echo "↪ TCP (ports sensibles) :"
 sudo nmap -sT -p $PORTS_TCP -Pn $CIBLE
 echo ""
 echo "↪ UDP (ports critiques) :"
 sudo nmap -sT -p $PORTS_UDP -Pn $CIBLE


 echo ""
 echo "============================================================="
 echo "======= 3. DÉTECTION DES SERVICES ET VERSIONS (-sV) ========"
 echo "============================================================="
 sudo nmap -sV -p $PORTS_TCP -Pn $CIBLE


 echo ""
 echo "============================================================="
 echo "======= 4. DÉTECTION DU SYSTÈME D'EXPLOITATION (-O) ========="
 echo "============================================================="
 sudo nmap -O -Pn $CIBLE


 echo ""
 echo "============================================================="
 echo "========== 5. DÉTECTION DE FIREWALL / FILTRAGE =============="
 echo "============================================================="
 echo "↪ État des ports (open, closed, filtered) :"
 sudo nmap -sT -p $PORTS_TCP -Pn $CIBLE | grep -Ei "PORT|open|closed|filtered"


} > "$RAPPORT"


echo ""
echo "Analyse terminée."
echo "Rapport généré : $RAPPORT"


cat "$RAPPORT"
