📄 DOCUMENTO DE REQUISITOS TÉCNICOS Y DE PRODUCTO
Proyecto: WinRecon Suite (Herramienta Modular de Reconocimiento y Auditoría)
Versión: 1.0 (Fase de Reconocimiento)
Entorno Objetivo: Windows 10 / 11 / Server
Rol del Desarrollador: Pentester / Ethical Hacker
Estado: Borrador para aprobación

1. Resumen Ejecutivo
WinRecon Suite será una herramienta de línea de comandos (CLI) desarrollada en Python, diseñada específicamente para auditorías de seguridad en entornos Windows. A diferencia de escáneres genéricos, esta herramienta combinará el reconocimiento de red (estilo Nmap: descubrimiento, escaneo de puertos y fingerprinting) con la auditoría local del sistema operativo (baseline de seguridad, lectura de Sysmon). Finalmente, correlacionará los banners de servicios con bases de datos de vulnerabilidades (CVEs).

2. Objetivos (Goals)
Reconocimiento Híbrido: Unificar el descubrimiento de red (ARP/Scapy) y el escaneo de puertos (Sockets/Scapy) en un solo flujo.

Inteligencia de Servicios: Implementar un motor de fingerprinting para identificar productos y versiones (ej. OpenSSH 8.2, Apache 2.4.49).

Correlación de Vulnerabilidades: Consultar APIs (como NVD) o bases de datos locales para identificar CVEs asociados a las versiones detectadas.

Auditoría Local Profunda: Evaluar la postura de seguridad de la máquina donde se ejecuta (puertos en 0.0.0.0, estado del Firewall, RDP, Spooler, persistencia en el Registro).

Modularidad y Despliegue: Diseñar el código para que pueda ser empaquetado como un .exe (PyInstaller) y desplegado vía GitHub o scripts remotos.

3. No-Objetivos (Out of Scope en esta fase)
No será una herramienta de explotación (no lanzará payloads de reverse shell ni exploits activos).

No tendrá interfaz gráfica (GUI) en esta versión inicial (se planifica para la Fase 4).

No evadirá soluciones EDR/AV avanzadas (se ejecutará con permisos de Administrador locales).

4. Requisitos Funcionales (Módulos)
4.1. Módulo de Red (core/network.py)
Descubrimiento (ARP Sweep): Usar scapy para encontrar hosts activos en la LAN (evadiendo bloqueos de ICMP).

Escaneo de Puertos:

Implementar SYN Scan (Half-Open) con scapy para mayor sigilo.

Implementar TCP Connect Scan con socket como fallback.

Capacidad de escanear rangos (1-1024, top 100, etc.) con concurrencia (ThreadPoolExecutor).

4.2. Módulo de Fingerprinting (core/fingerprint.py)
Envío de sondas específicas por puerto (ej. HEAD / para HTTP, lectura pasiva para SSH/MySQL).

Uso de Expresiones Regulares (Regex) para extraer el producto y la versión del banner (ej. SSH-2.0-OpenSSH_8.2p1 -> Producto: OpenSSH, Versión: 8.2p1).

Soporte para envolver conexiones en TLS/SSL para puertos como 443.

4.3. Módulo de Auditoría Local (local/audit.py)
Uso de psutil para mapear puertos locales a procesos (PID y nombre).

Detección de configuraciones inseguras (Winreg): RDP expuesto, SMBv1 activo, Firewall desactivado, Print Spooler expuesto.

Extracción de telemetría: Integrar el script de Sysmon (opcional, vía EVTX o subprocess) para buscar procesos maliciosos (TTPs).

4.4. Módulo de Inteligencia de CVEs (intel/cve_engine.py)
Normalización de banners a un formato estándar (CPE).

Consulta a la API del NVD (National Vulnerability Database) manejando límites de peticiones.

Caché local (SQLite o JSON) para evitar consultar la misma versión repetidamente y permitir uso offline.

4.5. Módulo de Reportes (report/generator.py)
Exportación de datos crudos a JSON (estándar para automatización).

Generación de un reporte estructurado en TXT para consola.

(Futuro cercano) Generación de reporte ejecutivo en HTML para clientes.

5. Requisitos No Funcionales (Técnicos)
5.1. Arquitectura y Estructura de Directorios
El proyecto debe ser estrictamente modular. Estructura propuesta:

text
WinRecon/
├── main.py                 # Orquestador (CLI con argparse)
├── requirements.txt        # Dependencias (scapy, psutil, requests, jinja2)
├── README.md               # Documentación para GitHub
├── core/
│   ├── scanner.py          # Lógica de red
│   └── fingerprint.py      # Extracción de versiones
├── intel/
│   └── cve_engine.py       # Consultas a NVD
├── local/
│   └── audit.py            # Auditoría local (Registry, psutil)
└── report/
    └── generator.py        # Salida TXT/JSON/HTML
5.2. Entorno de Desarrollo (VS Code + Entorno Virtual)
Para garantizar que las dependencias no interfieran con el sistema operativo del desarrollador o del cliente, se utilizará un entorno virtual.

Recomendación: Usar venv (nativo de Python) en lugar de Miniconda. Es más ligero, fácil de auditar y suficiente para nuestras librerías. Miniconda solo sería útil si tuviéramos que manejar librerías de C complejas, pero scapy y psutil se manejan bien con pip.

Configuración en VS Code:

Abrir la carpeta del proyecto en VS Code.

Abrir la terminal integrada (Ctrl + ñ).

Crear el entorno: python -m venv .venv

Activar el entorno (PowerShell): .\.venv\Scripts\Activate.ps1
(Si da error de políticas de ejecución, ejecutar como admin: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser).

Instalar dependencias: pip install scapy psutil requests

En VS Code, presionar Ctrl + Shift + P -> Python: Select Interpreter y elegir el de la carpeta .venv.

5.3. Despliegue y Empaquetado
GitHub: El repositorio incluirá un archivo requirements.txt para que los usuarios instalen las dependencias con pip install -r requirements.txt.

Empaquetado (PyInstaller): Se incluirá un script build.bat que ejecute pyinstaller --onefile --uac-admin main.py para generar un .exe ejecutable en las PCs de los clientes sin necesidad de que tengan Python instalado.

5.4. Seguridad y Ética
El script de auditoría local debe requerir permisos de Administrador (para leer ciertas claves del registro y todos los sockets).

La herramienta mostrará un Disclaimer en su ejecución inicial: "Uso exclusivo para auditorías autorizadas. El usuario es responsable del uso indebido."

6. Fases del Proyecto (Roadmap)
Fase 1 (Actualmente): Scripts Prueba de Concepto (PoC). (Lo que estamos haciendo en las carpetas Scapy y Mini_Nmap).

Fase 2: Modularización y Estructura. Empaquetar los PoCs en la arquitectura de carpetas propuesta. Implementar argparse en el main.py.

Fase 3: Inteligencia y Correlación. Implementar el motor de CVE (consultas a NVD) y unificar la auditoría local.

Fase 4: Interfaz Gráfica (Último paso). Crear una GUI usando CustomTkinter o PySide6 que lea los JSON generados y muestre un dashboard visual (semáforos de riesgo, gráficas de red) para que el reporte sea atractivo para el cliente de la consultoría.

7. Próximos Pasos (Acción Inmediata)
Con el documento aprobado, el siguiente paso técnico es configurar el Entorno Virtual (.venv) en VS Code y crear el esqueleto de la estructura de carpetas. Luego, migraremos tu código actual (mini_nmap_localv2.py, local_enum.py) a los módulos respectivos (core/scanner.py y local/audit.py).