# local/audit.py
import subprocess
import psutil
import winreg
import socket
import getpass

def ejecutar_ps(comando):
    """Ejecuta un comando de PowerShell y devuelve el texto limpio."""
    try:
        resultado = subprocess.run(
            ["powershell", "-Command", comando],
            capture_output=True, text=True, timeout=10
        )
        return resultado.stdout.strip()
    except Exception as e:
        return f"Error: {e}"

def recolectar_datos():
    """Recolecta información de seguridad del sistema local."""
    info = {}
    info["usuario"] = getpass.getuser()
    info["hostname"] = socket.gethostname()
    info["so"] = ejecutar_ps("(Get-CimInstance Win32_OperatingSystem).Caption")

    # Antivirus y Firewall
    info["antivirus_activo"] = ejecutar_ps("(Get-MpComputerStatus).RealTimeProtectionEnabled") == "True"
    info["firewall_activo"] = "True" in ejecutar_ps("(Get-NetFirewallProfile).Enabled")

    # RDP
    try:
        clave = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Terminal Server")
        rdp_val, _ = winreg.QueryValueEx(clave, "fDenyTSConnections")
        info["rdp_habilitado"] = (rdp_val == 0)
    except Exception:
        info["rdp_habilitado"] = "Desconocido"

    # Puertos
    puertos = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == "LISTEN":
            try:
                proc = psutil.Process(conn.pid).name() if conn.pid else "Desconocido"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc = "Sistema/Protegido"
            puertos.append({"puerto": conn.laddr.port, "ip": conn.laddr.ip, "proceso": proc, "pid": conn.pid}) # type: ignore
            
    info["puertos_abiertos"] = list({p["puerto"]: p for p in puertos}.values())
    return info

def evaluar_riesgos(datos):
    """Aplica reglas de negocio y devuelve una lista de hallazgos."""
    hallazgos = []
    
    # Regla: Print Spooler expuesto
    for p in datos["puertos_abiertos"]:
        if p["proceso"].lower() == "spoolsv.exe" and p["ip"] == "0.0.0.0":
            hallazgos.append({"severidad": "CRÍTICA", "hallazgo": "Print Spooler expuesto", "detalle": "Riesgo de PrintNightmare."})
            break
            
    if not datos["firewall_activo"]:
        hallazgos.append({"severidad": "ALTA", "hallazgo": "Firewall desactivado", "detalle": "El equipo es vulnerable a ataques de red."})
        
    if datos.get("rdp_habilitado") == True:
        hallazgos.append({"severidad": "ALTA", "hallazgo": "RDP habilitado", "detalle": "Riesgo de fuerza bruta o BlueKeep."})

    return hallazgos