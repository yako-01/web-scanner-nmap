import json
from collections import defaultdict
import sys
from datetime import datetime

# === Arguments : nom_domaine, fichier_json_entrée, fichier_txt_sortie ===
if len(sys.argv) != 4:
    print("Usage : python3 regroupe.py <nom_domaine> <fichier_json> <fichier_sortie>")
    sys.exit(1)

nom_domaine = sys.argv[1].strip() 
fichier_json = sys.argv[2].strip()
fichier_sortie = sys.argv[3].strip()

#charger le rapport json généré par zap
try:
    with open(fichier_json, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    print(f"[!] Erreur lors de la lecture du fichier JSON : {e}")
    sys.exit(2)

alertes = data.get("alerts", [])

#compter les alertes par niveau de risque
risk_counts = {"high": 0, "medium": 0, "low": 0, "informational": 0}
for a in alertes:
    r = a.get("risk", "").lower()
    if r in risk_counts:
        risk_counts[r] += 1

#regrouper les alertes par type (nom), uniquement High et Medium ===
groupes = defaultdict(list)

for alerte in alertes:
    risque = alerte.get("risk", "").lower()
    if risque not in ["high", "medium"]:
        continue
    nom = alerte.get("alert", "Sans titre")
    groupes[nom].append(alerte)

#écrire le rapport final regroupé
try:
    import os
    output_dir = os.path.dirname(fichier_sortie)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    with open(fichier_sortie, "w", encoding="utf-8") as out:
        #en-tête du rapport
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        out.write("="*60 + "\n")
        out.write("RAPPORT ZAP REGROUPÉ\n")
        out.write("="*60 + "\n")
        out.write(f"Cible : {nom_domaine}\n")
        out.write(f"Date : {now_str}\n")
        out.write("-"*60 + "\n")
        out.write(
            f"Résumé des risques -> High: {risk_counts['high']} | Medium: {risk_counts['medium']} | "
            f"Low: {risk_counts['low']} | Informational: {risk_counts['informational']}\n\n"
        )

        if not groupes:
            out.write("Aucune alerte de niveau High/Medium n'a été détectée.\n")
            out.write("Des alertes Low/Informational peuvent exister mais ne sont pas incluses dans ce rapport.\n")
        else:
            for nom_alerte, instances in groupes.items():
                exemple = instances[0]
                out.write(f"=== {nom_alerte} ===\n")
                out.write(f"Risque : {exemple.get('risk', 'N/A')} | Confiance : {exemple.get('confidence', 'N/A')}\n")
                out.write(f"\nDescription :\n{exemple.get('description', '').strip()}\n")
                out.write(f"\nSolution :\n{exemple.get('solution', '').strip()}\n")

                out.write(f"\nCas détectés ({len(instances)}) :\n")
                for i, alerte in enumerate(instances, 1):
                    out.write(f"{i}. URL : {alerte.get('url', 'N/A')}\n")
                    out.write(f"   Paramètre : {alerte.get('param', 'N/A')}\n")
                    attack = alerte.get("attack", "").strip()
                    evidence = alerte.get("evidence", "").strip()
                    if attack:
                        out.write(f"   Payload : {attack}\n")
                    if evidence:
                        out.write(f"   Preuve : {evidence}\n")
                out.write("\n" + "="*60 + "\n\n")

    print(f"[✓] Rapport regroupé généré : {fichier_sortie}")

except Exception as e:
    print(f"[!] Erreur lors de l’écriture du fichier : {e}")
    sys.exit(3)