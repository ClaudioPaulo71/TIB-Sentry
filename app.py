import os
from flask import Flask, render_template
from api.models import db
from core.scanner import scan_network
from database.manager import update_inventory
from flask import request, redirect, url_for
from api.models import Asset
import threading

app = Flask(__name__)

# Configuração do Banco de Dados na Raiz
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'sentry_inventory.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Cria o banco e as tabelas se não existirem
with app.app_context():
    db.create_all()

@app.route('/')
def dashboard():
    # Apenas lê o que já está no banco de dados
    all_assets = Asset.query.order_by(Asset.ip_address).all()
    return render_template('dashboard.html', assets=all_assets, scanning=scan_status["running"])

# Criamos uma variável global para o status (opcional, para exibir na tela)
scan_status = {"running": False, "stop_requested": False}

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
    scan_status["stop_requested"] = False # Resetamos a flag ao começar
    
    from core.scanner import scan_network
    from database.manager import update_inventory
    
    # IMPORTANTE: Vamos passar a flag para o scanner
    scanned_data = scan_network("192.168.1.0/24", status_ref=scan_status)
    
    if scanned_data: # Só atualiza se o scan não foi cancelado no meio
        update_inventory(scanned_data)
    
    scan_status["running"] = False
    scan_status["stop_requested"] = False


@app.route('/update_asset/<int:id>', methods=['POST'])
def update_asset(id):
    asset = db.session.get(Asset, id)
    if asset:
        # Pegando os dados do formulário
        asset.hostname = request.form.get('hostname')
        asset.status = request.form.get('status')
        
        db.session.add(asset) # Re-adiciona para garantir que o SQLAlchemy rastreie a mudança
        db.session.commit()
        print(f"✅ Sucesso: {asset.mac_address} agora é {asset.hostname} [{asset.status}]")
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)