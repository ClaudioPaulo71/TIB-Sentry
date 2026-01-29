import os
import threading
from flask import Flask, render_template, request, redirect, url_for
from api.models import db, Asset, AuditLog # Adicione AuditLog aqui
from core.scanner import scan_network
from database.manager import update_inventory
from core.deep_scanner import scan_device_vulnerabilities
from datetime import datetime

app = Flask(__name__)

# Dicionário para rastrear status de audits individuais {asset_id: "running" ou "done"}
audit_tasks = {}

# Configuração do Banco de Dados na Raiz
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'sentry_inventory.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Cria o banco e as tabelas se não existirem
with app.app_context():
    db.create_all()

# Variável global para o status do scan
scan_status = {"running": False, "stop_requested": False}

@app.route('/')
def dashboard():
    # 1. Busca todos os ativos (para preencher a tabela)
    all_assets = Asset.query.order_by(Asset.ip_address).all()
    
    # 2. CÁLCULO DAS ESTATÍSTICAS (Para os Gráficos)
    total = len(all_assets)
    
    # Conta direto no banco de dados quantos temos de cada tipo
    critical = Asset.query.filter_by(risk_level='CRITICAL').count()
    warning = Asset.query.filter_by(risk_level='WARNING').count()
    safe = Asset.query.filter_by(risk_level='SAFE').count()
    
    # Matemática simples: O que sobrar é "Desconhecido/Offline"
    unknown = total - (critical + warning + safe)

    # 3. Pega mensagem da URL (se houver)
    msg = request.args.get('msg')
    
    # 4. Renderiza enviando o pacote 'stats' junto
    return render_template('dashboard.html', 
                           assets=all_assets, 
                           scanning=scan_status.get("running", False), # .get evita erro se a chave não existir
                           msg=msg,
                           stats={
                               'critical': critical,
                               'warning': warning,
                               'safe': safe,
                               'unknown': unknown
                           })

@app.route('/scan')
def run_scan():
    if not scan_status["running"]:
        # Dispara o scan em uma Thread separada
        thread = threading.Thread(target=background_scan)
        thread.start()
        return redirect(url_for('dashboard', msg="Scan iniciado em segundo plano..."))
    
    return redirect(url_for('dashboard', msg="Um scan já está em curso."))

@app.route('/stop_scan')
def stop_scan():
    if scan_status["running"]:
        scan_status["stop_requested"] = True
        return redirect(url_for('dashboard', msg="Solicitação de parada enviada..."))
    return redirect(url_for('dashboard'))

def background_scan():
    scan_status["running"] = True
    scan_status["stop_requested"] = False
    print("--- DEBUG: Thread de Scan Iniciada ---") 
    
    try:
        # Confirme se o IP aqui bate com a sua rede
        target_network = "192.168.1.0/24" 
        
        print(f"--- DEBUG: Escaneando rede {target_network}... ---")
        
        # Passa o status para permitir o Stop
        scanned_data = scan_network(target_network, status_ref=scan_status)
        
        print(f"--- DEBUG: Scan retornou {len(scanned_data)} dispositivos ---")
        
        if scanned_data:
            with app.app_context(): # CRÍTICO: Threads precisam de contexto para usar o Banco
                update_inventory(scanned_data)
                print("--- DEBUG: Banco de dados atualizado! ---")
        else:
            print("--- DEBUG: Nenhum dispositivo encontrado (Scan vazio ou interrompido) ---")

    except Exception as e:
        print(f"!!! ERRO CRÍTICO NA THREAD: {e} !!!") 
        import traceback
        traceback.print_exc() 
        
    finally:
        scan_status["running"] = False
        scan_status["stop_requested"] = False
        print("--- DEBUG: Thread Finalizada ---")

# Certifique-se de que esta linha está no topo do arquivo, junto com as outras variáveis globais!
# audit_tasks = {} 

@app.route('/deep_scan/<int:asset_id>')
def trigger_deep_scan(asset_id):
    Asset.query.get_or_404(asset_id)
    
    # 1. Marca a tarefa como "RODANDO" no dicionário global
    audit_tasks[asset_id] = "running"
    
    def run_job(target_id):
        with app.app_context():
            try:
                local_asset = Asset.query.get(target_id)
                
                if local_asset:
                    print(f"[*] Thread: Auditando {local_asset.ip_address}...")
                    
                    # Roda o Scanner (retorna 4 valores)
                    ports, risk, detected_os, discovered_name = scan_device_vulnerabilities(local_asset.ip_address)
                    
                    # --- CAMINHO 1: DISPOSITIVO OFFLINE ---
                    if ports == "Offline":
                        print(f"[!] Aviso: {local_asset.ip_address} não respondeu. Gravando log de falha.")
                        
                        # Grava log de falha mas NÃO mexe nos dados do ativo
                        new_log = AuditLog(
                            asset_id=local_asset.id,
                            risk_level="UNREACHABLE",
                            open_ports="Dispositivo Offline ou Firewall Bloqueando",
                            detected_os="N/A"
                        )
                        db.session.add(new_log)

                    # --- CAMINHO 2: SUCESSO (ONLINE) ---
                    else:
                        # Atualiza dados técnicos
                        local_asset.open_ports = ports
                        local_asset.risk_level = risk

                        # ATUALIZA O RELÓGIO: "Eu vi este dispositivo agora!"
                        local_asset.last_seen = datetime.now()  # <--- ADICIONE ESTA LINHA
                        
                        # Lógica de Nome
                        if discovered_name and discovered_name != "user":
                            local_asset.hostname = discovered_name
                        elif local_asset.hostname in ["Unknown", "Unknown_Host", "Generic Device"]:
                            if detected_os and detected_os not in ["Unknown", "Unknown OS"]:
                                local_asset.hostname = detected_os

                        # Grava log de Sucesso
                        new_log = AuditLog(
                            asset_id=local_asset.id,
                            risk_level=risk,
                            open_ports=ports,
                            detected_os=detected_os
                        )
                        db.session.add(new_log)
                        print(f"[*] SUCESSO: Dados atualizados para {local_asset.ip_address}")

                    # Salva tudo no banco
                    db.session.commit()
            
            except Exception as e:
                print(f"[!] Erro Crítico na Thread de Audit: {e}")
            
            finally:
                # 2. O PULO DO GATO: Marca como "PRONTO" (seja sucesso ou erro)
                # Isso avisa o JavaScript para recarregar a página
                audit_tasks[target_id] = "done"

    # Inicia a Thread
    thread = threading.Thread(target=run_job, args=(asset_id,))
    thread.start()
    
    # Redireciona passando a flag '?auditing=ID' para ativar o radar do JavaScript
    return redirect(url_for('dashboard', msg="Auditoria iniciada em segundo plano...", auditing=asset_id))

@app.route('/update_asset/<int:asset_id>', methods=['POST'])
def update_asset(asset_id):
    asset = Asset.query.get_or_404(asset_id)
    
    # 1. Captura os dados vindos do Formulário HTML
    new_name = request.form.get('hostname')
    new_status = request.form.get('status') # <--- O PULO DO GATO (Estava faltando isso)
    
    # 2. Atualiza o Banco de Dados se o dado existir
    if new_name:
        asset.hostname = new_name
    
    if new_status:
        asset.status = new_status # Atualiza a coluna 'status' (Unknown, Known, Rogue)
    
    # 3. Salva
    db.session.commit()
    
    # Redireciona com mensagem de sucesso
    return redirect(url_for('dashboard', msg=f"Ativo {asset.ip_address} atualizado com sucesso!"))

from flask import jsonify # Importe isso no topo se não tiver!

@app.route('/api/status/<int:asset_id>')
def check_audit_status(asset_id):
    # Retorna o status atual ("running", "done", ou "unknown")
    status = audit_tasks.get(asset_id, "unknown")
    return jsonify({"status": status})


if __name__ == '__main__':
    # 'host=0.0.0.0' permite acesso de outros PCs na rede
    app.run(host='0.0.0.0', port=5000, debug=True)