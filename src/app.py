from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from fastapi.middleware.cors import CORSMiddleware

from scanner import Scanner
from report_generator import ReportGenerator
from utils.tools import generate_filename # Importa a função para gerar o nome do arquivo

app = FastAPI(
    title="Vulnerability Scanner API",
    description="API para rodar scans de vulnerabilidade e gerar relatórios."
)

# Adicione o middleware CORS
origins = [
    "http://localhost:5173",  # Onde o React geralmente roda
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelo de dados para a entrada da requisição POST
class ScanRequest(BaseModel):
    url: str

# Rota principal para rodar o scan
@app.post("/run", response_model=Dict[str, Any])
def run_vulnerability_scan(request: ScanRequest):
    """
    Roda um scan de vulnerabilidade no site especificado e gera um relatório.
    """
    url = request.url

    # 1. Validação simples da URL (pode ser mais robusta)
    if not url or not url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="URL inválida. Certifique-se de incluir http:// ou https://"
        )

    try:
        filename = generate_filename() 
        scanner = Scanner(url)
        scanner.run() 
        vulnerabilities = scanner.getVulnerabilities() 
        
        report_generator = ReportGenerator(url, vulnerabilities)
        
        # 1. GERAÇÃO DO JSON
        report_data = report_generator.generate_json_report() 
        
        # 2. GERAÇÃO DO MARKDOWN
        markdown_content = report_generator.generate_markdown_report()
        
        # 3. Adiciona o conteúdo Markdown ao JSON de retorno
        report_data["markdownContent"] = markdown_content
        report_data["id"] = filename # Adicionamos o ID que é o nome do arquivo
        
        return report_data
        
    except Exception as e:
        # Tratamento de exceções que possam ocorrer durante o scan
        print(f"Erro durante o scan: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Ocorreu um erro interno durante a execução do scan: {str(e)}"
        )

# Rota de health check (opcional, mas boa prática)
@app.get("/")
def health_check():
    return {"status": "ok", "service": "Vulnerability Scanner API"}