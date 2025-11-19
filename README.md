# 🛡️ TechHacker Security Scanner Pro

Bem-vindo ao **TechHacker Security Scanner Pro**, uma solução de cibersegurança full-stack projetada para identificar e relatar vulnerabilidades comuns em aplicações web e infraestrutura.

Este projeto combina um poderoso back-end em **FastAPI** (Python) com um front-end interativo em **React/Vite**, orquestrados para execução portátil via **Docker Compose**.

**Vídeo ilustrando o uso da aplicação**: https://youtu.be/i6FspCzAjII

## 🚀 Visão Geral do Projeto

O **TechHacker Security Scanner** é um projeto de duplo propósito:

1.  **Back-end (`src/`):** Uma API RESTful construída com FastAPI que lida com a lógica de segurança.

      * **Scanner de Aplicação:** Detecta vulnerabilidades de **Cross-Site Request Forgery (CSRF)** inspecionando a ausência de tokens anti-CSRF em formulários POST e a configuração insegura de cookies (`SameSite`).
      * **Scanner de Infraestrutura:** Utiliza o **Nmap** (via `libnmap`) para realizar varreduras em portas abertas e serviços expostos no alvo.
      * **Geração de Relatórios:** Automatiza a consolidação dos achados em um relatório no formato **Markdown** (para download) e JSON.

2.  **Front-end (`dashboard-scanner/`):** Um painel (Dashboard) interativo construído com React e Vite. Ele fornece uma interface amigável para:

      * Iniciar novos scans contra URLs/IPs.
      * Visualizar o resumo das vulnerabilidades por nível de risco (Crítico, Alto, Médio, Baixo).
      * Detalhar cada achado (descrição, risco e mitigação).
      * Baixar o relatório final em Markdown.

## 📦 Arquitetura de Execução (Docker)

O projeto é configurado para ser executado com Docker Compose, garantindo que o ambiente, incluindo o Nmap, seja isolado e consistente em qualquer sistema operacional (incluindo Kali Linux).

| Componente | Tecnologia | Porta Externa | Dockerfile |
| :--- | :--- | :--- | :--- |
| **Backend** | FastAPI (Python 3.12) + Nmap | `8000` | `src/Dockerfile` |
| **Frontend** | React/Vite + Nginx | `5173` | `dashboard-scanner/Dockerfile` |

## 🛠️ Pré-requisitos

Para rodar o projeto, você precisa ter instalado:

1.  **Docker:** Necessário para construir e gerenciar os containers.
2.  **Docker Compose:** Necessário para orquestrar os serviços `backend` e `frontend`.

## ⚙️ Como Iniciar o Projeto

Siga os passos abaixo para construir e executar a aplicação completa.

### Passo 1: Estrutura do Projeto

Verifique se a sua estrutura de diretórios corresponde a este layout (baseado na imagem fornecida):

```
.
├── dashboard-scanner/  (Front-end React/Vite)
│   ├── package.json
│   └── Dockerfile  
├── src/                (Back-end FastAPI)
│   ├── app.py
│   ├── scanner.py
│   ├── report\_generator.py
│   └── Dockerfile  
├── docker-compose.yml
└── requirements.txt    (Dependências Python)

````

### Passo 2: Construir e Subir os Containers

Na pasta raiz do projeto (onde está o `docker-compose.yml`), execute o comando para construir as imagens e iniciar os serviços:

```bash
docker compose up --build -d
````

  * O comando construirá a imagem do `backend` (instalando o Python 3.12 e o Nmap) e a imagem do `frontend` (construindo o Vite e configurando o Nginx).
  * O flag `-d` executa os containers em modo *detached* (segundo plano).

### Passo 3: Acessar a Aplicação

Após alguns segundos, os serviços estarão rodando:

| Serviço | Acesso (Host) |
| :--- | :--- |
| **Frontend (Dashboard)** | `http://localhost:5173` |
| **Backend (API)** | `http://localhost:8000` |

Você pode verificar o status dos containers com:

```bash
docker compose ps
```

### Passo 4: Comunicação Interna (APIs)

É fundamental lembrar que, dentro da rede Docker, o Front-end deve se comunicar com o Back-end usando o nome do serviço (definido no `docker-compose.yml`):

**URL da API a ser usada no código React/Vite:**

```
http://backend:8000/
```

### 🛑 Como Parar e Remover os Containers

Para parar e remover os containers, redes e volumes criados pelo `docker compose`:

```bash
docker compose down
```
