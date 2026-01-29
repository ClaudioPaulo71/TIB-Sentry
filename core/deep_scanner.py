import nmap
import sys

def scan_device_vulnerabilities(ip_address):
    """
    Versão simplificada para garantir execução.
    Retorna: (portas, risco, os_detectado, nome_maquina_descoberto)
    """
    nm = nmap.PortScanner()
    print(f"[*] Iniciando Deep Scan em {ip_address}...")
    
    try:
        # ARGUMENTOS MAIS SIMPLES (Sem scripts complexos por enquanto)
        # -sS: Scan Stealth (rápido)
        # -O: Tenta detectar o SO
        # -Pn: Não pinga (assume online)
        # --top-ports 50: Olha apenas as 50 portas mais comuns (para ser rápido)
        arguments = '-sS -O -Pn --top-ports 50'
        
        # Executa o scan
        nm.scan(ip_address, arguments=arguments)
        
        # DEBUG: Mostra no terminal o que aconteceu
        print(f"    > Comando rodado: {nm.command_line()}")
        
        # Verificação de falha do Nmap
        if ip_address not in nm.all_hosts():
            print(f"    > ERRO: O Nmap não retornou dados para {ip_address}.")
            print(f"    > Scan Info: {nm.scaninfo()}")
            return "Offline", "UNREACHABLE", "Unknown", None

        # 1. Processa Portas
        open_ports = []
        risk_score = 0
        
        # Garante que temos dados de protocolo
        if 'tcp' in nm[ip_address]:
            for port in nm[ip_address]['tcp']:
                state = nm[ip_address]['tcp'][port]['state']
                name = nm[ip_address]['tcp'][port]['name']
                if state == 'open':
                    open_ports.append(f"{port}/{name}")
                    # Cálculo simples de risco
                    if port in [21, 23, 445, 3389]: risk_score += 30
                    elif port in [80, 443, 8080]: risk_score += 10

        ports_str = ", ".join(open_ports) if open_ports else "No Open Ports"
        
        # Define Risco
        if risk_score >= 50: risk_label = "CRITICAL"
        elif risk_score >= 10: risk_label = "WARNING"
        elif open_ports: risk_label = "SAFE"
        else: risk_label = "CLEAN"

        # 2. Detecção de SO
        detected_os = "Unknown OS"
        if 'osmatch' in nm[ip_address] and nm[ip_address]['osmatch']:
            # Pega o primeiro match com maior precisão
            detected_os = nm[ip_address]['osmatch'][0]['name']

        # 3. Nome (Simplificado: Pega só o Hostname do DNS reverso)
        discovered_hostname = nm[ip_address].hostname()
        if not discovered_hostname:
            discovered_hostname = None

        return ports_str, risk_label, detected_os, discovered_hostname

    except Exception as e:
        print(f"[!] Erro CRÍTICO no Scanner: {e}")
        return "Error", "Unknown", "Unknown", None