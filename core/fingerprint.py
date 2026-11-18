# core/fingerprint.py
import re

def extraer_info(banner, puerto):
    if not banner or banner == "Sin banner":
        return {"producto": "Desconocido", "version": "Desconocida", "cpe": None}

    # --- Regla 1: SSH ---
    match_ssh = re.search(r"SSH-\d\.\d-([\w\.]+)_?([\d\.\w]+)?", banner)
    if match_ssh:
        return {"producto": match_ssh.group(1), "version": match_ssh.group(2) or "Desconocida", "raw": banner}

    # --- Regla 2: HTTP Headers ---
    # Buscamos cabeceras comunes que delatan tecnología
    headers_tech = {
        "X-Powered-By": r"X-Powered-By:\s*([^\r\n]+)",
        "X-AspNet-Version": r"X-AspNet-Version:\s*([^\r\n]+)",
        "Server": r"Server:\s*([^\r\n]+)"
    }
    
    for tech, patron in headers_tech.items():
        match = re.search(patron, banner, re.IGNORECASE)
        if match:
            server_full = match.group(1).strip()
            # Limpiamos cosas como "PHP/7.4.3" o "Apache/2.4.49"
            partes = server_full.split("/")
            producto = partes[0].strip()
            version = partes[1].split()[0] if len(partes) > 1 else "Desconocida"
            
            # Si la versión tiene letras y números, la limpiamos un poco
            if version != "Desconocida":
                v_match = re.match(r"([\d\.]+)", version)
                if v_match:
                    version = v_match.group(1)
            
            return {"producto": producto, "version": version, "raw": server_full}

    return {"producto": "Desconocido", "version": "Desconocida", "cpe": None}