#!/usr/bin/env python
# -*- coding: utf-8 -*-

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class Scanner:
    def __init__(self, url):
        self.url = url
        self.vulnerabilities = []

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
                samesite_attr = cookie.samesite.lower() if cookie.samesite else 'none'
                
                # Condição: SameSite ausente ou configurado como 'None'
                if not cookie.samesite or samesite_attr == 'none':
                    self.vulnerabilities.append({
                        "type": "CSRF - Configuração Insegura de Cookie",
                        "description": f"O cookie '{cookie.name}' não possui o atributo 'SameSite=Strict' ou 'SameSite=Lax'.",
                        "risk": "Médio",
                        "mitigation": "Defina o atributo 'SameSite' como **Strict** para cookies de sessão e **Lax** para cookies não críticos que precisam funcionar após redirecionamentos externos.",
                        "technical_details": {
                            "name": cookie.name,
                            "value": cookie.value,
                            "samesite_status": cookie.samesite
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
        nm = NmapProcess(self.url, options)
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