from app import app
from database.models import db

print("--- INICIANDO RESET DO BANCO DE DADOS ---")
with app.app_context():
    # 1. Apaga todas as tabelas existentes (o banco velho)
    db.drop_all()
    print("[OK] Tabelas antigas apagadas.")

    # 2. Cria as tabelas novas (com as colunas de auditoria)
    db.create_all()
    print("[OK] Novas tabelas criadas com sucesso!")

print("--- CONCLUÍDO ---")
