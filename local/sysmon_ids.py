r"""
================================================================================
 IDS CASERO PARA WINDOWS BASADO EN SYSMON — v3 (Integrado en WinRecon)
================================================================================
"""

import subprocess
import xml.etree.ElementTree as ET
import json
import os
import ipaddress
import re
import math
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

# =============================================================================
# CONFIGURACIÓN
# =============================================================================

LOG_FILE = "sysmon_alerts.jsonl"
STATE_FILE = "sysmon_state.txt"

NS = {"def": "http://schemas.microsoft.com/win/2004/08/events/event"}

LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "cscript.exe", "wscript.exe", "curl.exe", "forfiles.exe",
    "msiexec.exe", "schtasks.exe", "sc.exe",
}

PADRES_BENIGNOS = (
    "code.exe", "code - insiders.exe",
    "devenv.exe", "pycharm64.exe", "idea64.exe", "webstorm64.exe",
    "goland64.exe", "rider64.exe", "sublime_text.exe", "notepad++.exe",
    "windowsterminal.exe", "wt.exe",
    "git.exe", "githubdesktop.exe", "sourcetree.exe", "fork.exe",
    "explorer.exe", "gk.exe", "gitkraken.exe", "gitkraken-cli.exe",
)

PATRONES_SOSPECHOSOS = [
    r"-e(nc(odedcommand)?)?\b", r"-nop\b", r"-w(indowstyle)?\s+hidden",
    r"-exec(utionpolicy)?\s+bypass", r"downloadstring", r"invoke-expression",
    r"\biex\b", r"frombase64string", r"urlcache", r"http[s]?://",
    r"\\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
    r"whoami|net\s+user|net\s+group|nltest|dsquery",
]

COMANDOS_BENIGNOS_CMD = (
    "git rev-parse", "git status", "git log", "git diff", "git config",
    "wsl.exe -l", "wsl -l", "pyenv which", "pyenv version",
    "shellintegration.ps1", "wevtutil qe microsoft-windows-sysmon",
    "npm-prefix.js", "npm.cmd", "npx.cmd", "yarn.cmd", "pnpm.cmd",
    "code.cmd --list-extensions", "code.cmd --install-extension",
    "code.cmd --uninstall-extension", "cmd ver", "ver",
)

PUERTOS_INFRAESTRUCTURA = {53, 80, 443}
PUERTOS_RAROS = {4444, 5555, 1337, 31337, 8080, 8443, 445, 3389, 5985, 5986}

PROCESOS_RED_BENIGNOS = (
    "code.exe", "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe",
    "onedrive.exe", "teams.exe", "slack.exe", "discord.exe",
    "svchost.exe", "searchhost.exe", "widgets.exe", "backgroundtaskhost.exe",
    "dropbox.exe", "spotify.exe", "steam.exe", "outlook.exe", "winword.exe", 
    "excel.exe", "powerpnt.exe", "microsoftedgeupdate.exe", "googleupdate.exe",
)

REDES_PRIVADAS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
        "::1/128", "fe80::/10", "fc00::/7",
    )
]

NOMBRES_TEMP_BENIGNOS = ("__psscriptpolicytest_", "~df", "~$", "etilqs_")

DNS_BENIGNOS = (
    ".applicationinsights.azure.com", ".visualstudio.com", ".vscode-cdn.net",
    ".github.com", ".githubusercontent.com", ".githubcopilot.com",
    ".microsoft.com", ".windowsupdate.com", ".msftncsi.com",
    ".akadns.net", ".googleapis.com", ".gitkraken.com", ".gitkraken.dev",
    ".microsoft", ".microsoftonline.com", ".office.com", ".office.net",
    ".sharepoint.com", ".onedrive.com", ".static.microsoft",
    ".onecdn.static.microsoft", ".windows.net", ".microsoftpersonalcontent.com",
)

CLAVES_PERSISTENCIA = (
    "\\currentversion\\run", "\\currentversion\\runonce",
    "\\policies\\explorer\\run", "\\winlogon\\shell", "\\winlogon\\userinit",
)

CREADORES_SISTEMA_APPX = (
    "svchost.exe", "backgroundtaskhost.exe", "appinstaller.exe",
    "appxsvc", "systemsettings.exe", "runtimebroker.exe",
)

CREADORES_TEMP_BENIGNOS = (
    "msedgewebview2.exe", "msedge.exe", "chrome.exe", "firefox.exe",
    "googleupdate.exe", "microsoftedgeupdate.exe",
)

RUTAS_BENIGNAS_APPDATA = (
    "\\code\\user\\globalstorage\\", "\\code\\user\\workspacestorage\\",
    "\\github.copilot-chat\\", "\\github.copilot\\", "\\continue.continue\\",
    "\\ms-python\\", "\\ms-vscode\\",
)

# =============================================================================
# FUNCIONES AUXILIARES
# =============================================================================

def ip_es_privada(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in REDES_PRIVADAS)
    except ValueError:
        return True

def entropia(s: str) -> float:
    if not s: return 0.0
    conteo = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in conteo.values())

def es_dga_probable(dominio_base: str) -> bool:
    partes = dominio_base.split(".")
    nombre = partes[0] if len(partes) > 1 else dominio_base
    if len(nombre) < 10: return False
    ent = entropia(nombre)
    vocales = sum(1 for c in nombre if c in "aeiou")
    digitos = sum(1 for c in nombre if c.isdigit())
    total = len(nombre)
    return (ent > 3.5 and (vocales / total) < 0.25 and (digitos / total) > 0.15)

def leer_ultimo_recordid() -> Optional[str]:
    if not os.path.exists(STATE_FILE): return None
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            contenido = f.read().strip()
        if contenido.isdigit(): return contenido
        return None
    except OSError:
        return None

def guardar_ultimo_recordid(rid: int) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        f.write(str(rid))

def emitir_alerta(severidad: str, eid: str, mensaje: str, data: dict) -> dict:
    """Crea la alerta, la imprime, la guarda en JSONL y devuelve el dict."""
    alerta = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "severidad": severidad,
        "event_id": eid,
        "mensaje": mensaje,
        "data": data,
    }

    print(f"    [{severidad}] (EID {eid}) {mensaje}")
    for campo in ("Image", "CommandLine", "ParentImage", "TargetImage",
                  "DestinationIp", "DestinationPort", "QueryName", "TargetObject"):
        valor = data.get(campo)
        if valor: print(f"        {campo}: {valor}")
        elif campo == "Image": print(f"        {campo}: <desconocido>")

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(alerta, ensure_ascii=False) + "\n")
    
    return alerta

# =============================================================================
# REGLAS DE DETECCIÓN (Devuelven una tupla si hay alerta, None si no)
# =============================================================================

def regla_process_create(eid: str, d: dict, image: str, cmdline: str, parent: str):
    bin_name = os.path.basename(image)
    parent_bin = os.path.basename(parent)

    if parent.endswith(("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")) and bin_name in LOLBINS:
        return ("CRIT", eid, f"Office lanzó shell ({parent_bin} -> {bin_name})", d)

    if bin_name not in LOLBINS: return None

    if any(re.search(p, cmdline) for p in PATRONES_SOSPECHOSOS):
        return ("CRIT", eid, f"LOLBin con args sospechosos: {bin_name}", d)

    if any(b in cmdline for b in COMANDOS_BENIGNOS_CMD): return None
    if parent.endswith(PADRES_BENIGNOS): return None
    if parent_bin in LOLBINS: return None

    if bin_name in ("powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe", "mshta.exe", "certutil.exe"):
        return ("WARN", eid, f"LOLBin ejecutado: {bin_name}", d)

    return None

def regla_network_connect(eid: str, d: dict, image: str):
    dst = d.get("DestinationIp") or ""
    port = d.get("DestinationPort") or ""
    bin_name = os.path.basename(image)

    if not dst or ip_es_privada(dst): return None
    try: port_i = int(port)
    except ValueError: port_i = 0

    if port_i in PUERTOS_INFRAESTRUCTURA and bin_name in LOLBINS:
        return ("WARN", eid, f"LOLBin en puerto {port_i}: {bin_name} -> {dst}", d)

    if port_i in PUERTOS_INFRAESTRUCTURA and bin_name in PROCESOS_RED_BENIGNOS: return None
    if port_i in PUERTOS_RAROS and bin_name not in PROCESOS_RED_BENIGNOS:
        return ("WARN", eid, f"Conexión externa {bin_name} -> {dst}:{port}", d)

    return None

def regla_process_access(eid: str, d: dict, image: str):
    target = (d.get("TargetImage") or "").lower()
    if target.endswith("lsass.exe"):
        return ("CRIT", eid, f"Acceso a LSASS desde {image}", d)
    return None

def regla_file_create(eid: str, d: dict):
    target = (d.get("TargetFilename") or "").lower()
    image = (d.get("Image") or "").lower()

    extensiones_peligrosas = (".exe", ".dll", ".ps1", ".bat", ".vbs", ".hta")
    rutas_sospechosas = ("\\temp\\", "\\appdata\\", "\\downloads\\", "\\public\\")

    if not target.endswith(extensiones_peligrosas): return None
    if not any(x in target for x in rutas_sospechosas): return None
    if any(b in target for b in NOMBRES_TEMP_BENIGNOS): return None
    if ("\\appdata\\" in target and any(r in target for r in RUTAS_BENIGNAS_APPDATA)): return None
    if ("\\windowsapps\\" in target and any(image.endswith(c) for c in CREADORES_SISTEMA_APPX)): return None
    if ("\\temp\\" in target and any(image.endswith(c) for c in CREADORES_TEMP_BENIGNOS)): return None

    return ("WARN", eid, f"Archivo ejecutable en ruta sospechosa: {target}", d)

def regla_registry_event(eid: str, d: dict):
    obj = (d.get("TargetObject") or "").lower()
    if any(k in obj for k in CLAVES_PERSISTENCIA):
        return ("CRIT", eid, f"Persistencia en registro: {obj}", d)
    return None

def regla_dns_query(eid: str, d: dict):
    q = (d.get("QueryName") or "").lower()
    if not q or q.endswith(DNS_BENIGNOS): return None

    partes = q.rstrip(".").split(".")
    dominio_base = ".".join(partes[-2:]) if len(partes) >= 2 else q

    if es_dga_probable(dominio_base):
        return ("WARN", eid, f"DNS sospechoso (DGA?): {q}", d)
    return None

# =============================================================================
# ORQUESTADOR PRINCIPAL
# =============================================================================

def analizar_eventos_sysmon():
    """Lee Sysmon, aplica reglas y devuelve la lista de alertas generadas."""
    ultimo = leer_ultimo_recordid()
    ultimo_int = int(ultimo) if ultimo else None
    cmd = ["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational", "/c:500", "/rd:true", "/f:xml"]
    
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return []

    if res.returncode != 0:
        print("[-] wevtutil error: Asegúrate de ejecutar como Administrador.")
        return []

    xml_output = f"<Events>{res.stdout}</Events>"
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return []

    eventos = root.findall(".//def:Event", NS)
    max_rid = ultimo_int if ultimo_int is not None else 0
    alertas_generadas = []

    for ev in eventos:
        rid_elem = ev.find(".//def:EventRecordID", NS)
        if rid_elem is None or rid_elem.text is None: continue
        try: rid = int(rid_elem.text)
        except ValueError: continue

        if ultimo_int is not None and rid <= ultimo_int: continue
        max_rid = max(max_rid, rid)

        eid_elem = ev.find(".//def:EventID", NS)
        eid = eid_elem.text if (eid_elem is not None and eid_elem.text is not None) else "?"

        d = {}
        for data in ev.findall(".//def:Data", NS):
            name = data.attrib.get("Name")
            if name: d[name] = data.text or ""

        image = (d.get("Image") or "").lower()
        cmdline = (d.get("CommandLine") or "").lower()
        parent = (d.get("ParentImage") or "").lower()

        alerta = None
        if eid == "1": alerta = regla_process_create(eid, d, image, cmdline, parent)
        elif eid == "3": alerta = regla_network_connect(eid, d, image)
        elif eid == "10": alerta = regla_process_access(eid, d, image)
        elif eid == "11": alerta = regla_file_create(eid, d)
        elif eid == "13": alerta = regla_registry_event(eid, d)
        elif eid == "22": alerta = regla_dns_query(eid, d)

        if alerta:
            alertas_generadas.append(alerta)
            emitir_alerta(*alerta)

    guardar_ultimo_recordid(max_rid)
    
    if len(eventos) > 0:
        print(f"[*] Sysmon: {len(eventos)} eventos analizados | {len(alertas_generadas)} alertas nuevas.")
        
    return alertas_generadas

if __name__ == "__main__":
    analizar_eventos_sysmon()