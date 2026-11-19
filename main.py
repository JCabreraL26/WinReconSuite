# main.py
import argparse
import json
import datetime
from local.audit import recolectar_datos, evaluar_riesgos
from local.sysmon_ids import analizar_eventos_sysmon
from core.scanner import descubrir_hosts, escanear_puertos, obtener_banner
from core.fingerprint import extraer_info
from intel.cve_engine import buscar_cves
from report.generator import generar_html_local, generar_html_red

def guardar_json(datos, nombre):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    archivo = f"{nombre}_{ts}.json"
    with open(archivo, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=4, ensure_ascii=False)
    print(f"\n[+] Datos JSON guardados en {archivo}")

def ejecutar_auditoria_local(escanear_sysmon=False):
    print("[*] Ejecutando auditoría local...\n")
    datos = recolectar_datos()
    riesgos = evaluar_riesgos(datos)
    
    alertas_sysmon = []
    if escanear_sysmon:
        print("\n[*] Ejecutando análisis de Sysmon (IDS)...")
        alertas_sysmon = analizar_eventos_sysmon()
        if not alertas_sysmon:
            print("    ✅ Sysmon: No se detectaron amenazas recientes.")

    print(f"\n--- EQUIPO: {datos['hostname']} ({datos['so']}) ---")
    if not riesgos:
        print("✅ No se encontraron riesgos locales críticos.")
    else:
        for r in riesgos:
            print(f"[{r['severidad']}] {r['hallazgo']}\n   ↳ {r['detalle']}")
            
    guardar_json({
        "datos_crudos": datos, 
        "hallazgos": riesgos,
        "sysmon_alertas": alertas_sysmon
    }, "auditoria_local")
    
    generar_html_local(datos, riesgos, alertas_sysmon)

def ejecutar_escaneo_red(rango_red, lista_puertos):
    print(f"[*] Iniciando análisis de red en {rango_red}...\n")
    
    # Corrección para Localhost: Nos saltamos el ARP si es 127.0.0.1
    if rango_red in ("127.0.0.1", "localhost"):
        hosts = [{"ip": "127.0.0.1", "mac": "00:00:00:00:00:00 (Loopback)"}]
        print("[+] Escaneando interfaz de Loopback (Localhost)...")
    else:
        hosts = descubrir_hosts(rango_red)
        print(f"[+] Se encontraron {len(hosts)} hosts activos.")
    
    resultados_red = []
    
    for h in hosts:
        ip = h["ip"]
        print(f"\n--- Escaneando Host: {ip} (MAC: {h['mac']}) ---")
        
        # Llamamos al escáner pasando la lista de puertos elegida
        puertos_abiertos = escanear_puertos(ip, lista_puertos)
        
        servicios = []
        for p in puertos_abiertos:
            banner = obtener_banner(ip, p)
            print(f"  [ABIERTO] Puerto {p:<6} | Banner: {banner.splitlines()[0] if banner else 'N/A'}")
            
            info = extraer_info(banner, p)
            cves = []
            
            if info["producto"] != "Desconocido":
                print(f"      ↳ Producto: {info['producto']} | Versión: {info['version']}")
                cves = buscar_cves(info["producto"], info["version"])
                
                if cves:
                    for c in cves:
                        print(f"      ⚠️  [{c['severidad']}] {c['id']}: {c['descripcion']}")
            
            servicios.append({
                "puerto": p, 
                "banner": banner,
                "fingerprint": info,
                "cves": cves
            })
            
        resultados_red.append({
            "ip": ip,
            "mac": h["mac"],
            "servicios": servicios
        })
        
    guardar_json(resultados_red, "escaneo_red")
    generar_html_red(resultados_red)

# ==========================================
# BLOQUE DE EJECUCIÓN PRINCIPAL (CLI)
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WinRecon Suite - Auditoría de Seguridad Ética")
    
    parser.add_argument("--local", action="store_true", help="Ejecutar auditoría local (Windows)")
    parser.add_argument("--sysmon", action="store_true", help="Ejecutar análisis de Sysmon")
    parser.add_argument("--red", type=str, help="IP o rango de red a escanear (ej. 192.168.1.14 o 192.168.1.0/24)")
    
    # Nuevos argumentos para controlar la cantidad de puertos
    grupo_puertos = parser.add_mutually_exclusive_group()
    grupo_puertos.add_argument("--top", action="store_true", help="Escanear solo los ~20 puertos más comunes (Rápido)")
    grupo_puertos.add_argument("--full", action="store_true", help="Escanear TODOS los 65535 puertos (Lento, ideal para auditar tu IP)")
    
    args = parser.parse_args()
    
    if not args.local and not args.red:
        parser.print_help()
        exit()

    # 1. Auditoría Local
    if args.local:
        ejecutar_auditoria_local(escanear_sysmon=args.sysmon)
        
    # 2. Escaneo de Red
    if args.red:
        # Lógica para elegir la lista de puertos
        if args.full:
            puertos_a_escanear = range(1, 65536)
            print("[!] MODO FULL: Se escanearán los 65.535 puertos. Esto puede tardar varios minutos...")
        elif args.top:
            puertos_a_escanear = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5900, 8080, 8000, 8443, 27017]
            print("[*] MODO TOP: Escaneando puertos comunes...")
        else:
            puertos_a_escanear = range(1, 1025)
            print("[*] MODO DEFAULT: Escaneando puertos del 1 al 1024...")
            
        ejecutar_escaneo_red(args.red, puertos_a_escanear)