# intel/cve_engine.py
import requests
import time

# Caché en memoria para no repetir consultas en la misma sesión
_cache_cves = {}

def buscar_cves(producto, version):
    """
    Busca CVEs en el NVD para un producto y versión específicos.
    Devuelve una lista de diccionarios con los CVEs encontrados.
    """
    if producto == "Desconocido" or version == "Desconocida":
        return []

    clave_cache = f"{producto}_{version}".lower()
    if clave_cache in _cache_cves:
        return _cache_cves[clave_cache]

    print(f"    [Intel] Consultando CVEs para {producto} {version}...")
    
    # NVD API 2.0
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # Buscamos por palabra clave, ej: "Apache 2.4.49"
    params = {
        "keywordSearch": f"{producto} {version}",
        "resultsPerPage": 5 # Solo queremos los 5 más relevantes
    }
    
    try:
        # Respetamos el rate limit del NVD
        time.sleep(1.5) 
        respuesta = requests.get(url, params=params, timeout=10)
        
        if respuesta.status_code == 200:
            datos = respuesta.json()
            resultados = []
            
            for vuln in datos.get("vulnerabilities", []):
                cve = vuln["cve"]
                descripcion = cve["descriptions"][0]["value"]
                
                # Intentamos obtener la severidad CVSS
                severidad = "UNKNOWN"
                metrics = cve.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    severidad = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                elif "cvssMetricV2" in metrics:
                    severidad = metrics["cvssMetricV2"][0]["baseSeverity"]

                resultados.append({
                    "id": cve["id"],
                    "severidad": severidad,
                    "descripcion": descripcion[:150] + "..." # Cortamos el texto
                })
            
            _cache_cves[clave_cache] = resultados
            return resultados
        else:
            print(f"    [Intel] Error HTTP {respuesta.status_code} al consultar NVD")
            
    except Exception as e:
        print(f"    [Intel] Error de conexión al NVD: {e}")
        
    return []