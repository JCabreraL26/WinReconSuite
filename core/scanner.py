# core/scanner.py
import socket
import psutil
from concurrent.futures import ThreadPoolExecutor
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP
from scapy.all import srp, sr1, conf

# Silenciar advertencias de Scapy
conf.verb = 0

def descubrir_hosts(rango_red):
    """Realiza un ARP Scan para encontrar hosts vivos en la red local."""
    print(f"[*] Buscando hosts en {rango_red} (ARP Scan)...")
    paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rango_red)
    
    respondidos, _ = srp(paquete, timeout=3, verbose=False)
    
    hosts = []
    for enviado, recibido in respondidos:
        hosts.append({"ip": recibido.psrc, "mac": recibido.hwsrc})
    return hosts

def escanear_puerto_tcp(host, puerto, timeout=0.5):
    """Escaneo TCP Connect usando sockets (más compatible en Windows)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        resultado = s.connect_ex((host, puerto))
        s.close()
        return puerto if resultado == 0 else None
    except Exception:
        return None

def escanear_puertos(host, lista_puertos, hilos=100):
    """Escanea una lista de puertos concurrentemente."""
    print(f"[*] Escaneando {len(lista_puertos)} puertos en {host}...")
    abiertos = []
    
    # Usamos un wrapper para pasar el host a la función del pool
    def probar(p):
        return escanear_puerto_tcp(host, p)

    with ThreadPoolExecutor(max_workers=hilos) as pool:
        resultados = pool.map(probar, lista_puertos)
        
    for r in resultados:
        if r is not None:
            abiertos.append(r)
            
    return sorted(abiertos)

def obtener_banner(host, puerto, timeout=1.5):
    """Intenta conectarse y leer el banner de un servicio."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        if s.connect_ex((host, puerto)) != 0:
            s.close()
            return None

        banner = b""
        try:
            # Intentamos leer pasivamente (SSH, FTP, etc)
            banner = s.recv(1024)
        except socket.timeout:
            pass

        # Si es HTTP, enviamos petición para obtener headers
        if puerto in {80, 443, 8000, 8080, 8443} or banner == b"":
            try:
                peticion = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: WinRecon/1.0\r\n\r\n"
                s.sendall(peticion.encode())
                # Leemos más datos para capturar todas las cabeceras
                banner = s.recv(4096)
            except Exception:
                pass

        s.close()
        
        if banner:
            # Intentamos decodificar, pero filtramos caracteres no imprimibles
            texto = banner.decode('utf-8', errors='replace').strip()
            # Si la mayoría son caracteres raros, decimos que es binario
            printable_ratio = sum(c.isprintable() or c in '\r\n\t' for c in texto) / len(texto) if texto else 0
            if printable_ratio < 0.7:
                return "Binario (SMB/NetBIOS/RDP)"
            return texto
        return "Sin banner"
        
    except Exception as e:
        # ESTE ERA EL BLOQUE QUE FALTABA
        # Atrapa cualquier error de red (timeout general, host caído, etc.)
        return None