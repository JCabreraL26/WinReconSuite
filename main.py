# main.py
import argparse
import json
import datetime
import sys
from local.audit import recolectar_datos, evaluar_riesgos
from local.sysmon_ids import analizar_eventos_sysmon # <-- Nuevo módulo IDS
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
    
    # 1. Recolección y Evaluación Local (Winreg + psutil)
    datos = recolectar_datos()
    riesgos = evaluar_riesgos(datos)
    
    # 2. IDS Sysmon (Opcional)
    alertas_sysmon = []
    if escanear_sysmon:
        print("\n[*] Ejecutando análisis de Sysmon (IDS)...")
        alertas_sysmon = analizar_eventos_sysmon()
        if not alertas_sysmon:
            print("    ✅ Sysmon: No se detectaron amenazas recientes.")

    # 3. Mostrar resultados locales
    print(f"\n--- EQUIPO: {datos['hostname']} ({datos['so']}) ---")
    if not riesgos:
        print("✅ No se encontraron riesgos locales críticos.")
    else:
        for r in riesgos:
            print(f"[{r['severidad']}] {r['hallazgo']}\n   ↳ {r['detalle']}")
            
    # 4. Guardar JSON (unificamos todo)
    guardar_json({
        "datos_crudos": datos, 
        "hallazgos": riesgos,
        "sysmon_alertas": alertas_sysmon
    }, "auditoria_local")
    
    # 5. Generar Reporte HTML
    generar_html_local(datos, riesgos, alertas_sysmon) # type: ignore

def ejecutar_escaneo_red(rango_red, top_puertos):
    print(f"[*] Iniciando análisis de red en {rango_red}...\n")
    hosts = descubrir_hosts(rango_red)
    print(f"[+] Se encontraron {len(hosts)} hosts activos.")
    
    resultados_red = []
    
    for h in hosts:
        ip = h["ip"]
        print(f"\n--- Escaneando Host: {ip} (MAC: {h['mac']}) ---")
        puertos_abiertos = escanear_puertos(ip, top_puertos)
        
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
    parser.add_argument("--sysmon", action="store_true", help="Ejecutar análisis de Sysmon (Requiere admin y Sysmon instalado)")
    parser.add_argument("--red", type=str, help="Rango de red a escanear (ej. 192.168.1.0/24)")
    parser.add_argument("--top", action="store_true", help="Escanear solo los puertos más comunes (rápido)")
    
    args = parser.parse_args()
    
    # Si no se pasa ningún argumento, mostrar la ayuda
    if not args.local and not args.red:
        parser.print_help()
        sys.exit(0)

    # 1. Ejecutar Auditoría Local
    if args.local:
        ejecutar_auditoria_local(escanear_sysmon=args.sysmon)
        
    # 2. Ejecutar Escaneo de Red
    if args.red:
        top_100 = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5900, 8080]
        puertos_a_escanear = top_100 if args.top else range(1, 1025)
        
        ejecutar_escaneo_red(args.red, puertos_a_escanear)