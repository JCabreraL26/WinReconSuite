# 🛡️ WinRecon Suite

Herramienta modular de reconocimiento y auditoría de seguridad para entornos Windows, desarrollada en Python. Diseñada para Ethical Hackers y consultores de ciberseguridad.

![Reporte de WinRecon](screenshot_reporte.png)
*(Reemplaza esto con tu captura)*

## 🚀 Características
- **Auditoría Local:** Detecta configuraciones inseguras (RDP expuesto, Print Spooler, Firewall).
- **IDS Sysmon:** Analiza eventos de Sysmon (MITRE ATT&CK) buscando LOLBins, persistencia y accesos a LSASS.
- **Reconocimiento de Red:** ARP Sweep (Scapy) y escaneo de puertos concurrente (Top/Full).
- **Inteligencia de Amenazas:** Fingerprinting de servicios y consulta automática de CVEs en el NVD.
- **Reportes Visuales:** Genera dashboards en HTML listos para entregar al cliente.

## 🛠️ Instalación y Uso (Desarrollo)
1. Clona el repositorio: `git clone https://github.com/TU_USUARIO/WinReconSuite.git`
2. Crea un entorno virtual: `python -m venv .venv`
3. Actívalo: `.\.venv\Scripts\Activate.ps1`
4. Instala dependencias: `pip install -r requirements.txt`

### Ejemplo de uso:
```powershell
python main.py --local --sysmon --red 192.168.1.0/24 --top