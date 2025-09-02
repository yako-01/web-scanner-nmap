import os
import json
import sys
from typing import Dict, List, Tuple
from docx import Document
import datetime


INTERMEDIATE_DIR = "intermediate"
PORTS = [21,22,23,25,53,80,110,143,443,445,465,993,995,1433,1521,3306,3389,5432,5900,8080,8443,27017]
PORT_SERVICE_MAP = {
    "21": "FTP",
    "22": "SSH",
    "23": "Telnet",
    "25": "SMTP",
    "53": "DNS",
    "80": "HTTP",
    "110": "POP3",
    "143": "IMAP",
    "443": "HTTPS",
    "445": "SMB",
    "465": "SMTPS",
    "993": "IMAPS",
    "995": "POP3S",
    "1433": "MSSQL",
    "1521": "Oracle DB",
    "3306": "MySQL",
    "3389": "RDP",
    "5432": "PostgreSQL",
    "5900": "VNC",
    "8080": "HTTP Proxy",
    "8443": "HTTPS Proxy",
    "27017": "MongoDB",
}
dict = {}

def completar_closed_ports(intermediate_file, ports_list):
    """
    :param intermediate_file: Ruta al fichero intermedio generado por el script bash
    :param ports_list: Lista de puertos definidos en scan_nmap.sh
    :return: diccionario con todas las secciones (incluyendo CLOSED_PORTS completado)
    """
    data = {}
    current_key = None

    # Leer fichero intermedio
    with open(intermediate_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.endswith(":"):
                current_key = line[:-1]
                data[current_key] = []
            else:
                if current_key:
                    data[current_key].append(line)

    # Pasar puertos abiertos a int
    open_ports = [int(p) for p in data.get("OPEN_PORTS", []) if p.isdigit()]

    filtered_ports = [int(p) for p in data.get("FILTERED_PORTS", []) if p.isdigit()]

    # Calcular cerrados como diferencia
    closed_ports = [str(p) for p in ports_list if p not in (open_ports and filtered_ports)]

    # Rellenar en data
    data["CLOSED_PORTS"] = closed_ports

    return data


def get_service_name(port, fallback="desconocido"):
    """Devuelve el nombre amigable del servicio asociado a un puerto"""
    return PORT_SERVICE_MAP.get(port, fallback)


def remplir_tableau_ports(docx_template, output_docx, data):
    doc = Document(docx_template)

    # Recorrer tabla(s) del doc
    for table in doc.tables:
        # Detectamos si la tabla es la de puertos (col cabecera contiene "Numéro du port")
        headers = [cell.text.strip().lower() for cell in table.rows[0].cells]
        if "numéro du port" in headers[0]:
            # Borrar las filas excepto la cabecera
            for row in table.rows[1:]:
                tbl = table._tbl
                tbl.remove(row._tr)

            # Añadir filas de puertos abiertos
            for port in data.get("OPEN_PORTS", []):
                row_cells = table.add_row().cells
                row_cells[0].text = port
                row_cells[1].text = get_service_name(port)
                row_cells[2].text = "Ouvert"
            
            for port in data.get("FILTERED_PORTS", []):
                row_cells = table.add_row().cells
                row_cells[0].text = port
                row_cells[1].text = get_service_name(port)
                row_cells[2].text = "Filtré"

            # Añadir filas de puertos cerrados
            for port in data.get("CLOSED_PORTS", []):
                row_cells = table.add_row().cells
                row_cells[0].text = port
                row_cells[1].text = get_service_name(port)
                row_cells[2].text = "Fermé"

    doc.save(output_docx)
    print(f"Documento generado: {output_docx}")

def extract_scan_id(filename: str) -> str:
    """
    Extrae el scan_id (timestamp) del nombre de archivo intermedio.
    Ejemplo: nmap_testphp.vulnweb.com_01092025_103149.txt -> 01092025_103149
    """
    base = os.path.basename(filename)  # nmap_testphp.vulnweb.com_01092025_103149.txt
    parts = base.split("_")
    if len(parts) >= 3:
        return parts[-1].replace(".txt", "")  # -> 01092025_103149
    else:
        raise ValueError(f"No se pudo extraer scan_id del archivo {filename}")

"""
resultado = completar_closed_ports("intermediate/nmap_testphp.vulnweb.com_01092025_103149.txt", PORTS)
print(resultado)

output_file = f"./reports/informe_generado{datetime.datetime.now().strftime('%d%m%Y_%H%M%S')}.docx"
remplir_tableau_ports("./rapport_template.docx", output_file, resultado)
"""



def tags_valors(intermediate_file, ):
    with open(intermediate_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("TARGET:"):
                current_key = line[:1]


    dict = {
        "ENTREPRISE": "",
        "DATE": datetime.now().strftime("%d/%m/%Y"), 
        "SITE": current_key
    }
    return dict


def replace_tags_in_docx(template_path: str, output_path: str, replacements: dict):
    """
    Reemplaza en el docx todos los *TAGS* por los valores dados en replacements.

    :param template_path: Ruta al documento template (docx)
    :param output_path: Ruta al documento de salida (docx)
    :param replacements: Diccionario con pares { "TAG": "valor" }
                         Ejemplo: { "DATE": "01/09/2025", "SITE": "testphp.vulnweb.com" }
    """
    doc = Document(template_path)

    def replace_text_in_paragraph(paragraph, replacements):
        for key, val in replacements.items():
            tag = f"*{key}*"
            if tag in paragraph.text:
                # Recorrer runs porque los tags pueden estar fragmentados
                for run in paragraph.runs:
                    if tag in run.text:
                        run.text = run.text.replace(tag, str(val))

    def replace_text_in_table(table, replacements):
        for row in table.rows:
            for cell in row.cells:
                for paragraph in cell.paragraphs:
                    replace_text_in_paragraph(paragraph, replacements)

    # Reemplazo en párrafos principales
    for paragraph in doc.paragraphs:
        replace_text_in_paragraph(paragraph, replacements)

    # Reemplazo en tablas
    for table in doc.tables:
        replace_text_in_table(table, replacements)

    # Reemplazo en cabeceras/pies de página
    for section in doc.sections:
        header = section.header
        for paragraph in header.paragraphs:
            replace_text_in_paragraph(paragraph, replacements)
        footer = section.footer
        for paragraph in footer.paragraphs:
            replace_text_in_paragraph(paragraph, replacements)

    # Guardar documento final
    doc.save(output_path)






if __name__ == "__main__":
    intermediate_file = sys.argv[1]
    scan_id = extract_scan_id(intermediate_file)

    diccionario_actual = tags_valors(intermediate_file)

    resultado = completar_closed_ports(intermediate_file, PORTS)

    replace_tags_in_docx("./rapport_template.docx", "./reports/informe_definitivo_{scan_id}.docx", diccionario_actual)

    output_file = f"./reports/informe_definitivo_{scan_id}.docx"
    remplir_tableau_ports("./rapport_template.docx", output_file, resultado)





"""
def find_latest_intermediate_file(target: str | None = None) -> str | None:
    if not os.path.isdir(INTERMEDIATE_DIR):
        return None
    candidates: List[Tuple[float, str]] = []
    for name in os.listdir(INTERMEDIATE_DIR):
        if not name.startswith("nmap_") or not name.endswith(".txt"):
            continue
        if target and (f"nmap_{target}_" not in name):
            continue
        full = os.path.join(INTERMEDIATE_DIR, name)
        try:
            mtime = os.path.getmtime(full)
        except OSError:
            continue
        candidates.append((mtime, full))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def parse_intermediate_file(path: str) -> Dict[str, List[str] | str]:
    sections: Dict[str, List[str] | str] = {
        "TARGET": "",
        "TIMESTAMP": "",
        "RESOLVED_IPS": [],
        "OPEN_PORTS": [],
        "CLOSED_PORTS": [],
        "FILTERED_PORTS": [],
        "SERVICE_VERSIONS": [],
    }
    if not path or not os.path.exists(path):
        return sections

    current: str | None = None
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if line.startswith("TARGET:"):
                sections["TARGET"] = line.split(":", 1)[1].strip()
                current = None
                continue
            if line.startswith("TIMESTAMP:"):
                sections["TIMESTAMP"] = line.split(":", 1)[1].strip()
                current = None
                continue
            if line in ("RESOLVED_IPS:", "OPEN_PORTS:", "CLOSED_PORTS:", "FILTERED_PORTS:", "SERVICE_VERSIONS:"):
                current = line[:-1]
                continue
            if current:
                if line.strip() == "":
                    continue
                # Append raw line content to the active list
                lst: List[str] = sections[current]  # type: ignore[assignment]
                lst.append(line.strip())
    return sections


def load_data(target: str | None = None) -> Dict[str, List[str] | str]:
    path = find_latest_intermediate_file(target)
    return parse_intermediate_file(path) if path else {
        "TARGET": target or "",
        "TIMESTAMP": "",
        "RESOLVED_IPS": [],
        "OPEN_PORTS": [],
        "CLOSED_PORTS": [],
        "FILTERED_PORTS": [],
        "SERVICE_VERSIONS": [],
    }


def as_json(target: str | None = None) -> str:
    return json.dumps(load_data(target), ensure_ascii=False, indent=2)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Leer datos intermedios de Nmap y mostrarlos en JSON")
    parser.add_argument("target", nargs="?", help="IP o dominio para filtrar el fichero intermedio más reciente")
    parser.add_argument("--json", action="store_true", help="Imprimir en formato JSON")
    args = parser.parse_args()

    data = load_data(args.target)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(f"TARGET: {data.get('TARGET','')}")
        print(f"TIMESTAMP: {data.get('TIMESTAMP','')}")
        print("RESOLVED_IPS:")
        for v in data.get("RESOLVED_IPS", []):
            print(v)
        print("OPEN_PORTS:")
        for v in data.get("OPEN_PORTS", []):
            print(v)
        print("CLOSED_PORTS:")
        for v in data.get("CLOSED_PORTS", []):
            print(v)
        print("FILTERED_PORTS:")
        for v in data.get("FILTERED_PORTS", []):
            print(v)
        print("SERVICE_VERSIONS:")
        for v in data.get("SERVICE_VERSIONS", []):
            print(v)

"""
