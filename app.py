from flask import Flask, request, render_template, send_from_directory, jsonify # type: ignore
import subprocess
import os
import threading
import time
import json
from datetime import datetime

app = Flask(__name__)

#dictionnaire pour stocker l'état des processus
scan_status = {}

#REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
#os.makedirs(REPORTS_DIR, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start-scan', methods=['POST'])
def start_scan():
    link = request.form['link']
    
    #générer un ID unique pour cette analyse
    scan_id = f"scan_{int(time.time())}"
    
    #initialiser le dictionnaire d'état du scan
    scan_status[scan_id] = {
        'status': 'running',
        'progress': 0,
        'message': 'Iniciando escaneo...',
        'filename': None,
        'error': None
    }
    
    #commencer l'analyse dans un thread séparé
    thread = threading.Thread(target=run_scan_async, args=(scan_id, link)) #un thread est créé. la fonction run_scan_async s'active. scan_id et link sont les arguments transmis au thread
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id})

def run_scan_async(scan_id, link):
    try:
        scan_status[scan_id]['message'] = 'Exécution du script Nmap...'
        scan_status[scan_id]['progress'] = 2
        
        #obtengir le path du script
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan_nmap.sh')
        scan_status[scan_id]['message'] = f'Script path: {script_path}'
        
        #exécuter le script nmap (ligne bloquante, le thread attend qu'il se termine ou échoue)
        result = subprocess.run(
            [script_path, link], #path du script et argument que je lui passe
            capture_output=True, #capturer stdout et stderr
            text=True, #convertir la sortie en String
            timeout=300, #temps d'exécution maximal
            cwd=os.getcwd() ##assurez qu'il s'exécute dans le bon répertoire
        )
        
        if result.returncode == 0:
            output = result.stdout
            filename = None
            
            #rechercher le nom du fichier généré par le script
            for line in output.splitlines():
                if "Rapport généré :" in line:
                    filename = line.split("Rapport généré :")[1].strip()
                    break

            #définir le statut 'completed' pour rediriger vers /result/
            if filename and os.path.exists(filename):
                if os.path.getsize(filename) > 0:
                    scan_status[scan_id]['status'] = 'completed'
                    scan_status[scan_id]['progress'] = 100
                    scan_status[scan_id]['message'] = "L'analyse a été effectuée avec succès"
                    scan_status[scan_id]['filename'] = os.path.basename(filename)
    #erreur
    except Exception as e:
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['message'] = f'Erreur inattendue: {str(e)}'
        scan_status[scan_id]['error'] = str(e)

@app.route('/check-status/<scan_id>')
def check_status(scan_id):
    if scan_id not in scan_status:
        return jsonify({'error': "ID de l'analyse non trouvé"})
    
    status = scan_status[scan_id]
    
    #simulation de progression
    if status['status'] == 'running' and status['progress'] < 98:
        status['progress'] = min(status['progress'] + 2, 98)
    
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
