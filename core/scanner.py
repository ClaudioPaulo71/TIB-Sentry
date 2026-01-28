from scapy.all import ARP, Ether, srp
import socket
from manuf import manuf

# Inicializa a base de dados de fabricantes (OUI)
# O parâmetro update=False evita que o scan demore tentando baixar a base toda vez
mac_parser = manuf.MacParser(update=False)

def get_vendor(mac_address):
    """Identifica o fabricante pelo endereço MAC."""
    vendor = mac_parser.get_manuf(mac_address)
    if vendor:
        return vendor
    return "Generic Device"

def get_hostname(ip):
    """Tenta resolver o nome do dispositivo na rede."""
    try:
        # Tenta a resolução DNS reversa padrão
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.timeout):
        # Se falhar, retorna um marcador claro para o banco não se confundir
        return "Unknown_Host"

def scan_network(network_range, status_ref=None):
    """Realiza a varredura ARP e coleta dados dos dispositivos."""
    print(f"[*] TIB-Sentry: Iniciando varredura em {network_range}")
    
    # Criando o pacote de descoberta (Camada 2)
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Enviando e recebendo pacotes
    try:
        result = srp(packet, timeout=3, verbose=False)[0]
    except Exception as e:
        print(f"[!] Erro no Scapy: {e}")
        return []

    devices = []
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        
        # Coleta de informações
        hostname = get_hostname(ip)
        vendor = get_vendor(mac)

        devices.append({
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'vendor': vendor
        })
        print(f"[+] Detectado: {ip} | {vendor} | {hostname}")

    result = srp(packet, timeout=3, verbose=False)[0]
    devices = []
    
    for sent, received in result:
        # CHECK DE INTERRUPÇÃO:
        if status_ref and status_ref.get("stop_requested"):
            print("[!] Varredura interrompida pelo usuário.")
            return [] # Retorna lista vazia para não bagunçar o banco
            
        # ... (resto da lógica de hostname e vendor) ...
    
    return devices