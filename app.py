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

# Lock global para evitar múltiples escaneos simultáneos
scan_lock = Lock()
#current_scan = None

#REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
#os.makedirs(REPORTS_DIR, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start-scan', methods=['POST'])
def start_scan():
    #global current_scan #variable global para evitar múltiples escaneos simultáneos
    
    # Verificar si ya hay un escaneo en curso
    #if current_scan is not None:
    #    return jsonify({'error': 'Ya hay un escaneo en curso. Espere a que termine.'}), 400
    
    link = request.form['link']
    scan_type = request.form['type']
    
    #générer un ID unique pour cette analyse
    scan_id = f"scan_{int(time.time())}"
    #print(f"[DEBUG] start_scan -> nuevo scan_id: {scan_id}, link: {link}")
    
    #initialiser le dictionnaire d'état du scan
    scan_status[scan_id] = {
        'status': 'running',
        'progress': 0,
        'message': 'Iniciando escaneo...',
        'filename': None,
        'error': None,
        'type': scan_type
    }
    # Log esencial del estado inicial del scan
    #print(f"[DEBUG] start_scan -> estado inicial: {scan_status[scan_id]}")
    
    #commencer l'analyse dans un thread séparé (una sola vez)
    thread = threading.Thread(
        target=run_scan_async,
        args=(scan_id, link)
    )
    thread.daemon = True
    thread.start()
    #print(f"[DEBUG] start_scan -> hilo lanzado para {scan_id}")
    
    return jsonify({'scan_id': scan_id})

def run_scan_async(scan_id, link):
    #print(f"[DEBUG] run_scan_async -> inicio scan_id={scan_id}, link={link}")
    
    try:
        scan_type = scan_status[scan_id]['type']
       
        scan_status[scan_id]['message'] = 'Ejecutando script...'
        scan_status[scan_id]['progress'] = 1
        #print(f"[DEBUG] run_scan_async -> estado actualizado: {scan_status[scan_id]}")
        print(f"[DEBUG] scan type is {scan_type}")

        #obtengo la ruta absoluta del script
        if scan_type == 'nmap':
            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan_nmap.sh')
            scan_status[scan_id]['message'] = f'Script path: {script_path}'
            #script_path = os.path.join(os.getcwd(), 'scan_zap.sh')
            #scan_status[scan_id]['message'] = f'Script path: {script_path}'

        elif scan_type == 'zap':
            #script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan_zap.sh')
            script_path = os.path.join(os.getcwd(), 'scan_zap.sh')
            scan_status[scan_id]['message'] = f'Script path: {script_path}'
         #print(f"[DEBUG] run_scan_async -> return_code: {result.returncode}")
        """elif scan_type == 'both':
            nmap_script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan_nmap.sh')
            zap_script_path = os.path.join(os.getcwd(), 'scan_zap.sh')

            for script_path in [nmap_script_path, zap_script_path]:
                if os.path.exists(script_path):
                    os.chmod(script_path, 0o755)
                    subprocess.run([script_path, link], capture_output=True, text=True, timeout=1800, cwd=os.getcwd())"""

        
        # Verificar que el script existe y tiene permisos
        if not os.path.exists(script_path):
            scan_status[scan_id]['status'] = 'error'
            scan_status[scan_id]['message'] = f'Script no encontrado: {script_path}'
            scan_status[scan_id]['error'] = 'Script no encontrado'
            print(f"[ERROR] run_scan_async -> script no encontrado: {script_path}")
            return
            
        # Hacer el script ejecutable
        os.chmod(script_path, 0o755)
        
        #ejecuto el script nmap (linea bloqueante, el hilo espera hasta que termina o falla)
        #print(f"[DEBUG] run_scan_async -> ejecutando: {script_path} {link}")
        result = subprocess.run(
            [script_path, link], #ruta al script y argumento que le paso
            capture_output=True, 
            text=True, 
            timeout=1800,
            cwd=os.getcwd() #asegurar que se ejecute en el directorio correcto
        )
        
        #print(f"[DEBUG] run_scan_async -> return_code: {result.returncode}")
        
        if result.returncode == 0:
            #buscar el nombre del archivo generado
            output = result.stdout
            filename = None
            
            for line in output.splitlines():
                if "Rapport NMAP généré :" in line:
                    filename = line.split("Rapport NMAP généré :")[1].strip()
                    print(f"[DEBUG] run_scan_async -> filename detectado: {filename}")
                    break
                elif "Rapport ZAP généré :" in line:
                    filename = line.split("Rapport ZAP généré :")[1].strip()
                    print(f"[DEBUG] run_scan_async -> filename detectado: {filename}")
                    break
            
            if filename:
                # Verificar si el archivo existe en la ruta completa o en reports/
                if os.path.exists(filename): 
                    file_path = filename
                    #print(f"[DEBUG] run_scan_async -> archivo existe (ruta completa)")
                elif os.path.exists(os.path.join('reports', os.path.basename(filename))): 
                    file_path = os.path.join('reports', os.path.basename(filename))
                    #print(f"[DEBUG] run_scan_async -> archivo existe en reports/: {os.path.basename(file_path)}")
                else:
                    print(f"[ERROR] run_scan_async -> archivo no encontrado en '{filename}' ni en 'reports/'")
                    scan_status[scan_id]['status'] = 'error'
                    scan_status[scan_id]['message'] = f'Archivo no encontrado en: {filename}'
                    scan_status[scan_id]['error'] = 'Archivo no encontrado'
                    return
                
                # Verificar que el archivo no esté vacío
                if os.path.getsize(file_path) > 0:
                    #print(f"[DEBUG] run_scan_async -> archivo válido, tamaño={os.path.getsize(file_path)} bytes")
                    scan_status[scan_id]['status'] = 'completed'
                    scan_status[scan_id]['progress'] = 100
                    scan_status[scan_id]['message'] = 'Escaneo completado exitosamente'
                    scan_status[scan_id]['filename'] = os.path.basename(file_path)
                    #print(f"[DEBUG] run_scan_async -> filename final (basename): {scan_status[scan_id]['filename']}")
                else:
                    print(f"[ERROR] run_scan_async -> archivo vacío")
                    scan_status[scan_id]['status'] = 'error'
                    scan_status[scan_id]['message'] = 'El reporte generado está vacío'
                    scan_status[scan_id]['error'] = 'Reporte vacío'
            else:
                print(f"[ERROR] run_scan_async -> no se encontró 'Rapport ZAP généré :' en la salida del script")
                scan_status[scan_id]['status'] = 'error'
                scan_status[scan_id]['message'] = 'No se pudo generar el reporte'
                scan_status[scan_id]['error'] = 'Archivo no encontrado'
        else:
            print(f"[ERROR] run_scan_async -> script falló, return_code={result.returncode}")
            print(f"[STDERR] {result.stderr}")
            print(f"[STDOUT] {result.stdout}")
            scan_status[scan_id]['status'] = 'error'
            scan_status[scan_id]['message'] = f'Error en la ejecución: {result.stderr}'
            scan_status[scan_id]['error'] = result.stderr
            
    except subprocess.TimeoutExpired:
        print(f"[ERROR] run_scan_async -> TIMEOUT")
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['message'] = 'El escaneo tardó demasiado y fue interrumpido'
        scan_status[scan_id]['error'] = 'Timeout'
    except Exception as e:
        print(f"[ERROR] run_scan_async -> excepción: {str(e)}")
        scan_status[scan_id]['status'] = 'error'
        scan_status[scan_id]['message'] = f'Error inesperado: {str(e)}'
        scan_status[scan_id]['error'] = str(e)
    
    #print(f"[DEBUG] run_scan_async -> fin scan_id={scan_id}, estado_final={scan_status.get(scan_id)}")


@app.route('/check-status/<scan_id>')
def check_status(scan_id):
    #print(f"DEBUG - check_status llamado con scan_id: {scan_id}")
    #print(f"DEBUG - scan_status keys: {list(scan_status.keys())}")
    #print(f"DEBUG - scan_status contenido: {scan_status}")
    
    if scan_id not in scan_status:
        #print(f"DEBUG - ERROR: scan_id {scan_id} no encontrado en scan_status")
        return jsonify({'error': "ID de l'analyse non trouvé"})
    
    status = scan_status[scan_id]
    #print(f"DEBUG - Estado encontrado: {status}")
    
    #simulation de progression
    if status['status'] == 'running' and status['progress'] < 99:
        if status['type'] == 'nmap':
            status['progress'] = min(status['progress'] + 5, 99)
        else:
            status['progress'] = min(status['progress'] + 2, 99)

    
    
    return jsonify(status)

@app.route('/progress/<scan_id>')
def progress(scan_id):
    #print(f"DEBUG - progress llamado con scan_id: {scan_id}")
    #print(f"DEBUG - scan_status en progress: {scan_status}")
    #if scan_id in scan_status:
        #print(f"DEBUG - scan_id encontrado en progress: {scan_status[scan_id]}")
    #else:
        #print(f"DEBUG - ERROR: scan_id no encontrado en progress")
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

