import uuid

def generate_uuid():
    """
    Gera um ID único estatisticamente garantido (UUID) sem a necessidade
    de verificar um arquivo de registro.
    """
    raw_uuid = str(uuid.uuid4())
    return raw_uuid

def generate_filename():
    id = generate_uuid()
    return f"report_{id}"