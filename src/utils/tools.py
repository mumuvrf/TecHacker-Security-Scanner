import uuid

def generate_uuid():
    """
    Gera um ID único estatisticamente garantido (UUID) sem a necessidade
    de verificar um arquivo de registro.
    """
    raw_uuid = str(uuid.uuid4())
    return raw_uuid

def generate_filename() -> str:
    """
    Gera um nome único (str) para o arquivo de relatório a partir de um ID.
    """
    id = generate_uuid()
    return f"report_{id}"