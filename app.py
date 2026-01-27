import os
from flask import Flask, render_template
from api.models import db
from core.scanner import scan_network
from database.manager import update_inventory
from flask import request, redirect, url_for
from api.models import Asset

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
    return render_template('dashboard.html', assets=all_assets)

@app.route('/scan')
def run_scan():
    # Esta rota agora é a única que dispara o Scapy
    from core.scanner import scan_network
    from database.manager import update_inventory
    
    scanned_data = scan_network("192.168.1.0/24")
    update_inventory(scanned_data)
    
    return redirect(url_for('dashboard'))


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