from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100))
    ip_address = db.Column(db.String(50), nullable=False)
    mac_address = db.Column(db.String(50), unique=True, nullable=False)
    vendor = db.Column(db.String(100)) # Ex: Apple, Intel, Espressif
    status = db.Column(db.String(20), default="Unknown") # Known, Unknown, Rogue
    last_seen = db.Column(db.DateTime, server_default=db.func.now())