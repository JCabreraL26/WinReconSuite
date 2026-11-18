# report/generator.py
import os
import datetime

def generar_html_local(datos, hallazgos, alertas_sysmon=None, archivo_salida="reporte_local.html"):
    """Genera un reporte HTML para la auditoría local."""
    
    # Colores por severidad
    colores = {"CRÍTICA": "#dc3545", "ALTA": "#fd7e14", "MEDIA": "#ffc107", "BAJA": "#17a2b8"}
    
    filas_hallazgos = ""
    for h in hallazgos:
        color = colores.get(h['severidad'], "#6c757d")
        filas_hallazgos += f"""
        <tr>
            <td style="color: white; background-color: {color}; font-weight: bold; text-align: center;">{h['severidad']}</td>
            <td><strong>{h['hallazgo']}</strong><br><small>{h['detalle']}</small></td>
        </tr>
        """
        
    if not hallazgos:
        filas_hallazgos = "<tr><td colspan='2' style='text-align:center;'>✅ No se encontraron riesgos locales.</td></tr>"

    html = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Reporte de Auditoría Local - {datos['hostname']}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; color: #333; margin: 0; padding: 20px; }}
            .container {{ max-width: 900px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            .info-box {{ background: #e9ecef; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px; border: 1px solid #dee2e6; }}
            th {{ background-color: #343a40; color: white; text-align: left; }}
            .footer {{ margin-top: 40px; font-size: 0.8em; color: #6c757d; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Reporte de Auditoría de Seguridad Local</h1>
            <div class="info-box">
                <p><strong>Equipo:</strong> {datos['hostname']}</p>
                <p><strong>Sistema Operativo:</strong> {datos['so']}</p>
                <p><strong>Usuario Auditado:</strong> {datos['usuario']}</p>
                <p><strong>Fecha del Reporte:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <h2>🚨 Hallazgos de Seguridad</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 20%;">Severidad</th>
                        <th>Descripción del Hallazgo</th>
                    </tr>
                </thead>
                <tbody>
                    {filas_hallazgos}
                </tbody>
            </table>
            
            <div class="footer">
                Generado por WinRecon Suite - Herramienta de Auditoría Ética
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(archivo_salida, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Reporte visual generado: {archivo_salida}")

def generar_html_red(resultados_red, archivo_salida="reporte_red.html"):
    """Genera un reporte HTML para el escaneo de red."""
    
    secciones_hosts = ""
    for host in resultados_red:
        filas_servicios = ""
        for s in host["servicios"]:
            prod = s["fingerprint"].get("producto", "Desconocido")
            ver = s["fingerprint"].get("version", "Desconocida")
            
            # Formatear CVEs
            cves_html = ""
            if s.get("cves"):
                cves_html = "<ul style='margin:0; padding-left:15px; color:#dc3545; font-size:0.85em;'>"
                for c in s["cves"]:
                    cves_html += f"<li><strong>{c['id']}</strong> ({c['severidad']})</li>"
                cves_html += "</ul>"
            else:
                cves_html = "<span style='color:#28a745;'>Limpio</span>"

            filas_servicios += f"""
            <tr>
                <td><strong>{s['puerto']}</strong></td>
                <td>{prod} {ver}</td>
                <td>{cves_html}</td>
            </tr>
            """
            
        if not host["servicios"]:
            filas_servicios = "<tr><td colspan='3' style='text-align:center; color:#6c757d;'>No se encontraron puertos abiertos (Top 100)</td></tr>"

        secciones_hosts += f"""
        <div class="host-card">
            <h3>💻 Host: {host['ip']} <small style="color:#6c757d;">({host['mac']})</small></h3>
            <table>
                <thead>
                    <tr>
                        <th style="width: 15%;">Puerto</th>
                        <th style="width: 35%;">Tecnología Detectada</th>
                        <th>Vulnerabilidades (CVEs)</th>
                    </tr>
                </thead>
                <tbody>
                    {filas_servicios}
                </tbody>
            </table>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Reporte de Reconocimiento de Red</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; color: #333; margin: 0; padding: 20px; }}
            .container {{ max-width: 1000px; margin: auto; }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            .host-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 30px; }}
            .host-card h3 {{ margin-top: 0; color: #2980b9; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ padding: 10px; border: 1px solid #dee2e6; text-align: left; }}
            th {{ background-color: #f1f3f5; }}
            .footer {{ margin-top: 40px; font-size: 0.8em; color: #6c757d; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🌐 Reporte de Reconocimiento de Red</h1>
            <p><strong>Fecha del Reporte:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            {secciones_hosts}
            <div class="footer">
                Generado por WinRecon Suite - Herramienta de Auditoría Ética
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(archivo_salida, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Reporte visual generado: {archivo_salida}")