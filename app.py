import stat
from flask import Flask, request, render_template, send_from_directory, jsonify # type: ignore
import subprocess
import os
import threading
import time
import json
from datetime import datetime
from threading import Lock


app = Flask(__name__)

#dictionnaire pour stocker l'état des processus
scan_status = {}

#lock global para evitar múltiples escaneos simultáneos
#scan_lock = Lock()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start-scan', methods=['POST'])
def start_scan():
    link = request.form['link']
    scan_type = request.form['type']
    
    #générer un ID unique pour cette analyse
    scan_id = f"scan_{int(time.time())}"
    
    #initialiser le dictionnaire d'état du scan
    scan_status[scan_id] = {
        'status': 'running',
        'progress': 0,
        'message': "Démarrage de l'analyse...",
        'filename': None,
        'error': None,
        'type': scan_type
    }
    
    #commencer l'analyse dans un thread séparé
    thread = threading.Thread(
        target=run_scan_async,
        args=(scan_id, link)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id})

def run_scan_async(scan_id, link):    
    try:
        scan_type = scan_status[scan_id]['type']
        scan_status[scan_id]['message'] = 'Exécution du script...'
        scan_status[scan_id]['progress'] = 1
        #print(f"[DEBUG] run_scan_async -> status: {scan_status[scan_id]}")
        #print(f"[DEBUG] scan type is {scan_type}")

        #obtenir le chemin du script
        if scan_type == 'nmap':
            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan_nmap.sh')
            scan_status[scan_id]['message'] = f'Script path: {script_path}'
            
        elif scan_type == 'zap':
            script_path = os.path.join(os.getcwd(), 'scan_zap.sh')
            scan_status[scan_id]['message'] = f'Script path: {script_path}'

        elif scan_type == 'both':
            nmap_script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan_nmap.sh')
            zap_script_path = os.path.join(os.getcwd(), 'scan_zap.sh')

            #initialiser la structure pour les filenames et les erreurs
            scan_status[scan_id]['filenames'] = []
            results = {'nmap': None, 'zap': None}
            errors = {'nmap': None, 'zap': None}

            def run_one(script_to_run, key):
                try:
                    if not os.path.exists(script_to_run):
                        errors[key] = f"Script non trouvé: {script_to_run}"
                        return
                    os.chmod(script_to_run, 0o755)
                    res = subprocess.run(
                        [script_to_run, link],
                        capture_output=True,
                        text=True,
                        timeout=1800,
                        cwd=os.getcwd()
                    )
                    if res.returncode != 0:
                        errors[key] = res.stderr or "Erreur inconnu"
                        return
                    out = res.stdout
                    filename = None
                    for line in out.splitlines():
                        if "Rapport NMAP généré :" in line:
                            filename = line.split("Rapport NMAP généré :")[1].strip()
                            break
                        if "Rapport ZAP généré :" in line:
                            filename = line.split("Rapport ZAP généré :")[1].strip()
                            break
                    if not filename:
                        errors[key] = "Le fichier généré n'a pas pu être détecté"
                        return
                    if os.path.exists(filename):
                        file_path = filename
                    elif os.path.exists(os.path.join('reports', os.path.basename(filename))):
                        file_path = os.path.join('reports', os.path.basename(filename))
                    else:
                        errors[key] = f"Fichier non trouvé dans: {filename}"
                        return
                    if os.path.getsize(file_path) <= 0:
                        errors[key] = 'Rapport vide'
                        return
                    results[key] = os.path.basename(file_path)
                except subprocess.TimeoutExpired:
                    errors[key] = 'Timeout'
                except Exception as e:
                    errors[key] = str(e)

            #exécution de deux threads en parallèle
            t1 = threading.Thread(target=run_one, args=(nmap_script_path, 'nmap'))
            t2 = threading.Thread(target=run_one, args=(zap_script_path, 'zap'))
            t1.start()
            t2.start()
            t1.join()
            t2.join()

            if errors['nmap'] or errors['zap']:
                scan_status[scan_id]['status'] = 'error'
                scan_status[scan_id]['message'] = f"Erreur dans l'une ou les deux analyses : Nmap= {errors['nmap']}, ZAP= {errors['zap']}"
                scan_status[scan_id]['error'] = scan_status[scan_id]['message']
                return

            # Generar DOCX final con las 3 tablas rellenadas
            """try:
                from generation_rapport import remplir_tableaux_zap
                from generation_rapport import remplir_tableau_ports
                import shutil
                
                # Crear nombre para el DOCX final
                timestamp = datetime.now().strftime("%d%m%Y_%H%M%S")
                final_docx = f"rapport_complet_{timestamp}.docx"
                final_path = os.path.join('reports', final_docx)
                
                # Copiar template
                template_path = "./rapport_template2.docx"
                if os.path.exists(template_path):
                    shutil.copy2(template_path, final_path)
                    
                    # Rellenar tabla de puertos Nmap
                    from generation_rapport import remplir_tableau_ports
                    nmap_file = os.path.join('reports', results['nmap'])
                    if os.path.exists(nmap_file):
                        # Extraer datos Nmap del archivo generado
                        nmap_data = {'OPEN_PORTS': [], 'FILTERED_PORTS': [], 'CLOSED_PORTS': []}
                        # Por ahora datos vacíos, se pueden extraer después si es necesario
                        remplir_tableau_ports(final_path, final_path, nmap_data)
                    
                    # Rellenar tablas ZAP
                    zap_file = os.path.join('reports', results['zap'])
                    if os.path.exists(zap_file):
                        remplir_tableaux_zap(final_path, zap_file)
                    
                    # Solo mostrar el DOCX final
                    scan_status[scan_id]['filenames'] = [final_docx]
                    scan_status[scan_id]['message'] = 'Rapport complet DOCX généré avec succès'
                else:
                    # Fallback: mostrar archivos originales
                    scan_status[scan_id]['filenames'] = [name for name in [results['nmap'], results['zap']] if name]
                    scan_status[scan_id]['message'] = 'Analyses Nmap et ZAP terminées'
                    
            except Exception as e:
                print(f"Erreur lors de la génération du DOCX final: {e}")
                # Fallback: mostrar archivos originales
                scan_status[scan_id]['filenames'] = [name for name in [results['nmap'], results['zap']] if name]
                scan_status[scan_id]['message'] = 'Analyses Nmap et ZAP terminées'
"""

            import traceback

            try: 
                from generation_rapport import remplir_tableaux_zap
                with open("./intermediate/ultimo_output.txt") as f:
                    output_file = f.read().strip()
                    print(f"Archivo DOCX original: {output_file}")  # DEBUG

                    zap_file = os.path.join('reports', results['zap'])
                    print(f"Archivo ZAP: {zap_file}")  # DEBUG

                    if os.path.exists(zap_file):
                        remplir_tableaux_zap(output_file, zap_file)
                    else:
                        print("El archivo ZAP no existe")

                    # Solo mostrar el DOCX final
                    scan_status[scan_id]['filenames'] = [os.path.basename(output_file)]
                    scan_status[scan_id]['message'] = 'Rapport complet DOCX généré avec succès'

            except Exception as e:
                print(f"Erreur lors de la génération du DOCX final: {e}")
                traceback.print_exc()  # <-- muestra el error completo
                # Fallback: mostrar archivos originales
                scan_status[scan_id]['filenames'] = [name for name in [results['nmap'], results['zap']] if name]
                scan_status[scan_id]['message'] = 'Analyses Nmap et ZAP terminées'


            scan_status[scan_id]['status'] = 'completed'
            scan_status[scan_id]['progress'] = 100
            return

        #vérifiez que le script existe et dispose des permis
        if not os.path.exists(script_path):
            scan_status[scan_id]['status'] = 'error'
            scan_status[scan_id]['message'] = f'Script non trouvé: {script_path}'
            scan_status[scan_id]['error'] = 'Script non trouvé'
            #print(f"[DEBUG] run_scan_async -> Script non trouvé: {script_path}")
            return
            
        #rendre le script exécutable
        os.chmod(script_path, 0o755)
        
        #execution du script (ligne bloquante, le thread attend qu'il se termine ou échoue)
        #print(f"[DEBUG] run_scan_async -> execution: {script_path} {link}")
        result = subprocess.run(
            [script_path, link], #ruta al script y argumento que le paso
            capture_output=True, 
            text=True, 
            timeout=1800,
            cwd=os.getcwd()
        )
        
        #print(f"[DEBUG] run_scan_async -> return_code: {result.returncode}")
        
        if result.returncode == 0:
            output = result.stdout
            filename = None
            #chercher le nom du fichier généré
            for line in output.splitlines():
                if "Rapport NMAP généré :" in line:
                    filename = line.split("Rapport NMAP généré :")[1].strip()
                    #print(f"[DEBUG] run_scan_async -> filename detected: {filename}")
                    break
                elif "Rapport ZAP généré :" in line:
                    filename = line.split("Rapport ZAP généré :")[1].strip()
                    #print(f"[DEBUG] run_scan_async -> filename detected: {filename}")
                    break
            
            if filename:
                #vérifiez si le fichier existe dans le chemin complet ou dans les reports/
                if os.path.exists(filename): 
                    file_path = filename
                    #print(f"[DEBUG] run_scan_async -> fichier exists(chemina complet)")
                elif os.path.exists(os.path.join('reports', os.path.basename(filename))): 
                    file_path = os.path.join('reports', os.path.basename(filename))
                    #print(f"[DEBUG] run_scan_async -> fichier exists en reports/: {os.path.basename(file_path)}")
                else:
                    #print(f"[DEBUG] run_scan_async -> fichier non trouvé dans '{filename}' et en 'reports/'")
                    scan_status[scan_id]['status'] = 'error'
                    scan_status[scan_id]['message'] = f'Fichier non trouvé dans: {filename}'
                    scan_status[scan_id]['error'] = 'Fichier non trouvé'
                    return
                
                #vérifiez que le fichier n'est pas vide
                if os.path.getsize(file_path) > 0:
                    #print(f"[DEBUG] run_scan_async -> fichier valide, size={os.path.getsize(file_path)} bytes")
                    
                    # Si es ZAP, rellenar las tablas ZAP en el DOCX existente
                    if scan_type == 'zap':
                        try:
                            from generation_rapport import remplir_tableaux_zap
                            remplir_tableaux_zap(file_path, file_path)
                            scan_status[scan_id]['message'] = "Rapport ZAP DOCX généré avec succès"
                        except Exception as e:
                            print(f"Erreur lors du remplissage des tableaux ZAP: {e}")
                    
                    scan_status[scan_id]['status'] = 'completed'
                    scan_status[scan_id]['progress'] = 100
                    scan_status[scan_id]['filename'] = os.path.basename(file_path)
                    #print(f"[DEBUG] run_scan_async -> filename final (basename): {scan_status[scan_id]['filename']}")
                else:
                    #print(f"[DEBUG] run_scan_async -> fichier vide")
                    scan_status[scan_id]['status'] = 'error'
                    scan_status[scan_id]['message'] = 'Le rapport généré est vide'
                    scan_status[scan_id]['error'] = 'Rapport vide'
            else:
                #print(f"[DEBUG] run_scan_async -> no se encontró 'Rapport ZAP généré :' en la salida del script")
                scan_status[scan_id]['status'] = 'error'
                scan_status[scan_id]['message'] = "Le rapport n'a pas pu être généré"
                scan_status[scan_id]['error'] = 'Fichier non trouvé'
        else:
            #print(f"[DEBUG] run_scan_async -> script erreur, return_code={result.returncode}")
            #print(f"[STDERR] {result.stderr}")
            #print(f"[STDOUT] {result.stdout}")
            scan_status[scan_id]['status'] = 'error'
            scan_status[scan_id]['message'] = f"Erreur dans l'exécution : {result.stderr}"
            scan_status[scan_id]['error'] = result.stderr
            
    except subprocess.TimeoutExpired:
        #print(f"[DEBUG] run_scan_async -> TIMEOUT")
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['message'] = 'Timeout'
        scan_status[scan_id]['error'] = 'Timeout'
    except Exception as e:
        #print(f"[DEBUG] run_scan_async -> excepción: {str(e)}")
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['message'] = f'Erreur inattendu: {str(e)}'
        scan_status[scan_id]['error'] = str(e)
    
    #print(f"[DEBUG] run_scan_async -> fin scan_id={scan_id}, final status={scan_status.get(scan_id)}")


@app.route('/check-status/<scan_id>')
def check_status(scan_id):
    
    if scan_id not in scan_status:
        #print(f"[DEBUG] - ERROR: scan_id {scan_id} non trouvée dans scan_status")
        return jsonify({'error': "ID de l'analyse non trouvé"})
    
    status = scan_status[scan_id]
    
    #simulation de progression
    if status['status'] == 'running' and status['progress'] < 99:
        if status['type'] == 'nmap':
            status['progress'] = min(status['progress'] + 5, 99)
        else:
            status['progress'] = min(status['progress'] + 2, 99)


    return jsonify(status)

@app.route('/progress/<scan_id>')
def progress(scan_id):
    return render_template('progreso.html', scan_id=scan_id)

@app.route('/result/<scan_id>')
def result(scan_id):
    if scan_id not in scan_status:
        return "ID de l'analyse non trouvé", 404
    
    status = scan_status[scan_id]

    #redirection vers /result/ lorsque le status est 'completed'
    if status['status'] == 'completed':
        if status.get('type') == 'both':
            return render_template('resultado.html', filenames=status.get('filenames', []))
        return render_template('resultado.html', filename=status['filename'])
    elif status['status'] == 'error':
        return render_template('error.html', error=status['error'], message=status['message'])
    else:
        return "L'analyse est toujours en cours", 400

@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory('reports', filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='5000', debug=True)

