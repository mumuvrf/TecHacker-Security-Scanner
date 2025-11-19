#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import subprocess
import json
import requests

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from bs4 import BeautifulSoup

from urllib.parse import urljoin, urlparse

class Scanner:
    def __init__(self, url):
        self.url = url
        self.hostname = urlparse(self.url).hostname
        self.vulnerabilities = []

    def getVulnerabilities(self):
        return self.vulnerabilities

    def detect_csrf_vulnerabilities(self):
        """
        Detecta potenciais vulnerabilidades de CSRF em uma URL e retorna
        o resultado padronizado, incluindo mitigação e detalhes técnicos.

        Args:
            target_url (str): A URL para escanear.

        Returns:
            list: Uma lista de dicionários padronizados, cada um detalhando uma descoberta.
        """
        
        # Nomes comuns para tokens CSRF (não exaustivo)
        common_token_names = [
            'csrf_token', 'authenticity_token', 'nonce', '_token',
            '__requestverificationtoken', 'csrfmiddlewaretoken'
        ]

        try:
            # 1. Inicia uma sessão para capturar e inspecionar cookies
            session = requests.Session()
            response = session.get(self.url, timeout=10)
            response.raise_for_status() # Garante que a requisição foi bem-sucedida

            # 2. Análise de Cookies (Atributo SameSite)
            for cookie in session.cookies:
                samesite_val = cookie._rest.get('SameSite') or cookie._rest.get('samesite')
                
                # Normaliza para lowercase para comparação, se existir
                samesite_attr = samesite_val.lower() if samesite_val else 'none'
                # ---------------------

                # Condição: SameSite ausente ou configurado como 'None'
                if not samesite_val or samesite_attr == 'none':
                    self.vulnerabilities.append({
                        "type": "CSRF - Configuração Insegura de Cookie",
                        "description": f"O cookie '{cookie.name}' não possui o atributo 'SameSite=Strict' ou 'SameSite=Lax'.",
                        "risk": "Médio",
                        "mitigation": "Defina o atributo 'SameSite' como **Strict** para cookies de sessão e **Lax** para cookies não críticos que precisam funcionar após redirecionamentos externos.",
                        "technical_details": {
                            "name": cookie.name,
                            "value": cookie.value,
                            "samesite_status": samesite_val # Usa a variável corrigida
                        }
                    })

            # 3. Análise de Formulários (Tokens Anti-CSRF)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                # Focamos em formulários que mudam o estado (POST)
                if form.get('method', 'get').lower() == 'post':
                    has_token = False
                    
                    # Procura por inputs hidden com nomes de token conhecidos
                    hidden_inputs = form.find_all('input', {'type': 'hidden'})
                    for input_tag in hidden_inputs:
                        input_name = input_tag.get('name', '').lower()
                        if any(token_name in input_name for token_name in common_token_names):
                            has_token = True
                            break
                    
                    # Se nenhum token foi encontrado, reporta a vulnerabilidade
                    if not has_token:
                        form_action = form.get('action', 'N/A')
                        full_form_url = urljoin(self.url, form_action)
                        
                        self.vulnerabilities.append({
                            "type": "CSRF - Ausência de Token no Formulário",
                            "description": f"O formulário POST para '{full_form_url}' parece não ter um token anti-CSRF.",
                            "risk": "Alto",
                            "mitigation": "Implemente tokens **Anti-CSRF sincronizados (Synchronizer Token Pattern)**. O token deve ser único por sessão e validado no servidor a cada requisição POST.",
                            "technical_details": {
                                "action_url": full_form_url,
                                "method": "POST",
                                "form_snippet": str(form).split('\n')[0] + '...' # Adiciona um snippet do form
                            }
                        })

        except requests.exceptions.RequestException as e:
            self.vulnerabilities.append({
                "type": "Erro de Scan",
                "description": f"Não foi possível acessar a URL: {e}",
                "risk": "Informacional",
                "mitigation": "Verificar se o alvo está ativo e acessível na rede.",
                "technical_details": {}
            })

        return
    
    def wapiti_automated_scan(self):
        """
        Executa um scan automatizado com o Wapiti e processa os resultados JSON.
        Inclui mapeamento de mitigação específica por tipo de vulnerabilidade.
        """
        print(f"[*] Executando Wapiti scan em: {self.url}...")
        output_file = "wapiti_report.json"
        
        command = [
            "wapiti",
            "-u", self.url,
            "-f", "json",
            "-o", output_file,
            # Configuração padrão de scan completo (pode ser ajustada)
        ]
        
        # Mapeamento de Mitigação Otimizado
        MITIGATION_MAPPING = {
            "SQL Injection": "Sempre use **Prepared Statements** (Consultas Parametrizadas) ou **Stored Procedures** para separar o código SQL dos dados fornecidos pelo usuário.",
            "Cross Site Scripting (XSS)": "Aplique **codificação de saída (Output Encoding)** em todos os dados fornecidos pelo usuário antes de renderizá-los no HTML, especialmente em tags como `<script>`, `onerror`, e `href`.",
            "Local File Inclusion (LFI) / Path Traversal": "Evite passar entradas do usuário diretamente para funções de manipulação de sistema de arquivos. Use uma **whitelist** de nomes de arquivo permitidos.",
            "Server Side Request Forgery (SSRF)": "Implemente uma **whitelist** de URLs ou IPs internos que o servidor não pode acessar. Valide e filtre rigorosamente a entrada de URL fornecida pelo usuário.",
            "Header Injection": "Nunca inclua entradas do usuário diretamente em cabeçalhos HTTP de resposta sem saneamento. Limite a entrada a caracteres alfanuméricos.",
            "Command Execution": "Nunca passe entradas não validadas para funções que executam comandos do sistema operacional (e.g., `os.system`). Use **APIs seguras** específicas da linguagem.",
            "Information Disclosure": "Remova banners de servidor, mensagens de erro detalhadas (stack traces) e caminhos de arquivo dos outputs públicos. Configure o servidor para não listar diretórios."
        }
        
        RISK_MAPPING = {
            "critical": "Crítico",
            "high": "Alto",
            "medium": "Médio",
            "low": "Baixo",
            "info": "Informacional"
        }

        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=600) 
            
            if process.returncode != 0:
                print(f"[!] Erro ao executar Wapiti (RC: {process.returncode}): {process.stderr}")
                self.vulnerabilities.append({
                    "type": "Erro de Scan - Wapiti",
                    "description": f"Falha na execução do Wapiti. Mensagem: {process.stderr.strip()}",
                    "risk": "Informacional",
                    "mitigation": "Instalar ou verificar a instalação e o PATH do Wapiti.",
                    "technical_details": {"url": self.url}
                })
                return

            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    report = json.load(f)

                for category_data in report.get('vulnerabilities', []):
                    category_name = category_data.get('category', 'Vulnerabilidade Desconhecida')
                    risk_level = category_data.get('level', 'info').lower()
                    
                    specific_mitigation = MITIGATION_MAPPING.get(category_name, 
                        "Consulte a documentação da OWASP para esta vulnerabilidade e siga as melhores práticas de desenvolvimento seguro (SDLC)."
                    )

                    for vulnerability in category_data.get('vulnerabilities', []):
                        self.vulnerabilities.append({
                            "type": f"Wapiti - {category_name}",
                            "description": vulnerability.get('info', 'Detalhes não fornecidos pelo scanner.'),
                            "risk": RISK_MAPPING.get(risk_level, 'Informacional'),
                            "mitigation": specific_mitigation,
                            "technical_details": {
                                "url": vulnerability.get('url'),
                                "parameter": vulnerability.get('parameter'),
                                "attack_type": vulnerability.get('attack')
                            }
                        })
                
            else:
                self.vulnerabilities.append({
                    "type": "Erro de Scan - Wapiti",
                    "description": "O Wapiti foi executado, mas o arquivo de relatório JSON não foi encontrado.",
                    "risk": "Informacional",
                    "mitigation": "Verificar as permissões e o diretório de saída do Wapiti.",
                    "technical_details": {"file": output_file}
                })

        except subprocess.TimeoutExpired:
            self.vulnerabilities.append({
                "type": "Erro de Scan - Wapiti",
                "description": "O Wapiti atingiu o tempo limite de execução (600 segundos).",
                "risk": "Informacional",
                "mitigation": "Aumentar o tempo limite ou rodar o scan manualmente.",
                "technical_details": {"url": self.url}
            })
        except Exception as e:
            self.vulnerabilities.append({
                "type": "Erro de Processamento",
                "description": f"Erro ao processar a saída do Wapiti: {e}",
                "risk": "Informacional",
                "mitigation": "Revisar o código de processamento da saída JSON.",
                "technical_details": {"url": self.url}
            })

        finally:
            if os.path.exists(output_file):
                os.remove(output_file)
        
        return

    def nmap_vulnerability_scan(self, options = "-sV -sS"):
        """
        Executa um scan Nmap e retorna os resultados padronizados como vulnerabilidades/descobertas,
        incluindo classificação de risco e recomendações de mitigação.
        
        Args:
            options (str): Opções de linha de comando do Nmap.

        Returns:
            list: Lista de dicionários padronizados.
        """
        
        # Execução do Processo Nmap
        nm = NmapProcess(self.hostname, options)
        rc = nm.run()

        if rc != 0:
            # Em produção, logar o erro stderr é crucial
            raise Exception(f"NMap scan failed: {nm.stderr}")
        
        try:
            report = NmapParser.parse(nm.stdout)
        except NmapParserException as e:
            raise Exception(f"Exception raised while parsing scan: {e.msg}")

        # Dicionário de Mitigação e Risco Simplificado (Base de Conhecimento)
        # Em um sistema real, isso viria de um banco de dados ou arquivo de configuração.
        risky_ports = {
            '21': {'risk': 'Médio', 'mitigation': 'Certifique-se de que o FTP é necessário. Prefira SFTP/SCP.'},
            '23': {'risk': 'Alto', 'mitigation': 'O protocolo Telnet transmite dados em texto claro. Substitua IMEDIATAMENTE por SSH.'},
            '80': {'risk': 'Informacional', 'mitigation': 'Considere redirecionar todo o tráfego para HTTPS (Porta 443).'},
            '3306': {'risk': 'Alto', 'mitigation': 'O banco de dados MySQL não deve estar exposto à internet pública. Use VPN ou restrinja o IP no firewall.'},
            '3389': {'risk': 'Médio', 'mitigation': 'RDP exposto é alvo frequente de brute-force. Use VPN e autenticação forte.'}
        }

        # Processamento dos Resultados
        for host in report.hosts:
            # Identificação do Host
            host_name = host.hostnames[0] if host.hostnames else host.address
            
            for service in host.services:
                # Focamos apenas em portas abertas para o relatório de vulnerabilidades
                if service.state == 'open':
                    port_str = str(service.port)
                    
                    # Define Risco e Mitigação baseados na porta (Heurística)
                    # Se a porta não estiver mapeada, usa um padrão genérico
                    kb_entry = risky_ports.get(port_str, {
                        'risk': 'Informacional',
                        'mitigation': 'Verifique se este serviço é estritamente necessário. Aplique regras de Firewall (Princípio do Menor Privilégio).'
                    })

                    # Constrói o objeto padronizado
                    vuln_entry = {
                        "type": "Infraestrutura - Porta/Serviço Exposto",
                        "description": f"O serviço '{service.service}' está rodando e acessível na porta {service.port}/{service.protocol} no host {host_name}.",
                        "risk": kb_entry['risk'],
                        "mitigation": kb_entry['mitigation'],
                        "technical_details": {
                            "host": host_name,
                            "ip_address": host.address,
                            "port": service.port,
                            "protocol": service.protocol,
                            "service_name": service.service,
                            "banner": service.banner  # Banner grabbing é vital para identificar versões vulneráveis
                        }
                    }
                    
                    self.vulnerabilities.append(vuln_entry)

        return
    
    def run(self):
        self.detect_csrf_vulnerabilities()
        self.wapiti_automated_scan()
        self.nmap_vulnerability_scan()