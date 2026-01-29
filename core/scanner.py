import scapy.all as scapy
import socket
import requests
from mac_vendor_lookup import MacLookup # Nova biblioteca

# Inicializa o banco de dados de MACs (faz o download na primeira vez)
print("[*] Atualizando banco de dados de Fabricantes...")
try:
    mac_lookup = MacLookup()
    # Se der erro de permissão ou internet, ele usa o cache se existir
except:
    pass

def get_hostname(ip):
    try:
        # Tenta pegar o nome completo
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown" # Deixe "Unknown" aqui, vamos tratar no front-end ou Nmap

def get_mac_vendor(mac):
    try:
        return mac_lookup.lookup(mac)
    except:
        return "Generic Device" # Mais profissional que "Unknown Vendor"

# --- FUNÇÃO PRINCIPAL DE SCAN ---
def scan_network(network_range, status_ref=None):
    print(f"[*] TIB-Sentry: Iniciando varredura em {network_range}")
    
    # Cria o pacote ARP Request
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request
    
    # Envia e recebe (timeout garante que não fica preso)
    # verbose=False limpa o terminal
    result = scapy.srp(packet, timeout=2, verbose=False)[0]
    
    devices = [] 
    
    for sent, received in result:
        # 1. Checa se o usuário pediu STOP
        if status_ref and status_ref.get("stop_requested"):
            print("[!] Varredura interrompida pelo usuário.")
            return [] 

        # 2. Extrai os dados
        ip = received.psrc
        mac = received.hwsrc
        
        # Chama as funções auxiliares definidas acima
        vendor = get_mac_vendor(mac)
        hostname = get_hostname(ip)
        
        # 3. Mostra no Terminal (Debug)
        print(f"[+] Detectado: {ip} | {vendor} | {hostname}")
        
        # 4. Adiciona na lista para salvar no banco
        device_data = {
            'ip': ip, 
            'mac': mac, 
            'vendor': vendor, 
            'hostname': hostname
        }
        devices.append(device_data)
    
    return devices