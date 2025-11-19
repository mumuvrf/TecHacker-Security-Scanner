FROM python:3.12-slim

# Define a variável de ambiente para que o Python não escreva arquivos .pyc no disco
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Define o diretório de trabalho dentro do container
WORKDIR /app

# --- INSTALAÇÃO DE DEPENDÊNCIAS DE SISTEMA (NMAP) ---
# O Nmap é necessário, pois a aplicação back-end usa um wrapper Nmap.
RUN apt-get update && \
    apt-get install -y nmap --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Copia e instala as dependências do Python
# O requirements.txt está no diretório raiz do projeto (ver docker-compose.yml)
COPY requirements.txt /app/

# Instala as dependências. Usa --no-cache-dir para manter a imagem menor.
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código da aplicação
# O conteúdo de /src (o app.py) será copiado para /app no container
COPY src/ /app

# Expõe a porta que o FastAPI usará
EXPOSE 8000

# Comando para iniciar o servidor Uvicorn
# O comando original era 'uvicorn app:app --reload'. 
# Para produção no Docker, removemos --reload e o host deve ser 0.0.0.0.
# O arquivo principal do FastAPI deve ser 'app.py' contendo 'app = FastAPI()'.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]