from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Inicializamos o Banco de Dados aqui mesmo para evitar erros de importação
db = SQLAlchemy()

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), unique=True, nullable=False)
    mac_address = db.Column(db.String(17), nullable=False)
    hostname = db.Column(db.String(100), default="Unknown")
    vendor = db.Column(db.String(100), default="Unknown")
    last_seen = db.Column(db.DateTime, default=datetime.now)
    
    # Campos de Auditoria
    open_ports = db.Column(db.String(500), default="Pending Scan") 
    risk_level = db.Column(db.String(20), default="Unknown")
    status = db.Column(db.String(20), default="Unknown")

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    
    # Detalhes do registro
    risk_level = db.Column(db.String(20))
    open_ports = db.Column(db.String(500))
    detected_os = db.Column(db.String(100))
    
    # Relacionamento
    asset = db.relationship('Asset', backref=db.backref('audit_logs', lazy=True))