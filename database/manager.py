from api.models import db, Asset

def update_inventory(scanned_devices):
    new_devices_count = 0
    for dev in scanned_devices:
        # Tenta localizar o dispositivo pelo MAC
        existing_asset = db.session.query(Asset).filter_by(mac_address=dev['mac']).first()
        
        if existing_asset:
            # ATUALIZAÇÃO CRÍTICA: Se o banco tem "Workstation" ou "Identificando", 
            # nós forçamos o dado novo que o scanner acabou de pegar
            if existing_asset.hostname in ["Workstation", "Desconhecido", "None", None]:
                existing_asset.hostname = dev['hostname']
            
            if existing_asset.vendor in ["Identificando...", "Unknown", "Generic Device"]:
                existing_asset.vendor = dev['vendor']
            
            existing_asset.ip_address = dev['ip'] # IP pode mudar (DHCP)
            existing_asset.last_seen = db.func.now()
        else:
            # CRIAÇÃO: Novo dispositivo encontrado
            new_asset = Asset(
                hostname=dev['hostname'],
                ip_address=dev['ip'],
                mac_address=dev['mac'],
                vendor=dev['vendor'],
                status="Unknown"
            )
            db.session.add(new_asset)
            new_devices_count += 1
    
    db.session.commit()
    return new_devices_count