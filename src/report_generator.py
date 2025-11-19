import datetime
import json
from pathlib import Path

class ReportGenerator:
    def __init__(self, url, filename, vulnerabilities):
        self.url = url
        self.filepath = Path('results') / filename
        self.vulnerabilities = vulnerabilities
        self.report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.risk_order = ["Crítico", "Alto", "Médio", "Baixo", "Informacional"]

        # Pré-cálculo de estatísticas
        self.risk_counts = {risk: 0 for risk in self.risk_order}
        self.grouped_vulnerabilities = {risk: [] for risk in self.risk_order}
        
        for vuln in self.vulnerabilities:
            risk = vuln.get("risk", "Informacional")
            if risk in self.risk_counts:
                self.risk_counts[risk] += 1
                self.grouped_vulnerabilities[risk].append(vuln)
        
        self.total_findings = sum(self.risk_counts.values())

    def generate_markdown_report(self) -> str:
        """
        Gera o relatório completo de vulnerabilidades no formato Markdown aprimorado.
        """
        report_content = []
        
        # 1. Título Principal e Metadados
        report_content.append(f"# 🛡️ Relatório de Varredura de Vulnerabilidades")
        report_content.append(f"* **Alvo (URL/IP):** `{self.url}`")
        report_content.append(f"* **Data do Scan:** {self.report_date}")
        report_content.append(f"* **Total de Descobertas:** **{self.total_findings}**\n")
        report_content.append("---")
        
        # --- SUMÁRIO EXECUTIVO APRIMORADO ---
        report_content.append("\n## 📝 Sumário Executivo")
        
        # 2. Visão Geral do Scan
        report_content.append(f"O presente relatório detalha os achados de segurança para o alvo **{self.url}**, resultantes de uma varredura combinada de infraestrutura e aplicação, concluída em {self.report_date}. O objetivo é fornecer uma base acionável para a remediação.")
        
        report_content.append("\n### Metodologia de Varredura")
        report_content.append("O scan utilizou duas metodologias principais para uma cobertura abrangente:")
        report_content.append("\n* **Análise de Aplicação (CSRF):** Foco em vulnerabilidades de Cross-Site Request Forgery (CSRF) e configurações inseguras de Cookies (`SameSite`), essenciais para a integridade da sessão do usuário.")
        report_content.append("* **Análise de Infraestrutura (Nmap):** Foco na detecção de portas abertas e serviços expostos, visando identificar potenciais pontos de entrada na rede.")

        report_content.append("\n### Resultados Consolidados")
        
        if self.total_findings == 0:
            report_content.append("\n**Status:** Nenhuma vulnerabilidade de risco (Crítico, Alto, Médio) foi identificada neste scan.")
        else:
            critical_high = self.risk_counts["Crítico"] + self.risk_counts["Alto"]
            if critical_high > 0:
                 report_content.append(f"\n**ATENÇÃO:** Foram identificadas **{critical_high}** vulnerabilidades de risco **Crítico/Alto**. A remediação imediata é essencial para mitigar o risco de exploração e potencial perda de dados.")
            else:
                 report_content.append("\n**Status:** Não foram encontradas vulnerabilidades Críticas ou Altas. Recomenda-se focar na correção dos achados de risco Médio para fortalecer a postura defensiva.")

            summary_table = [
                "\n| Nível de Risco | Contagem | Prioridade de Remediação |",
                "| :--- | :---: | :--- |"
            ]
            
            # Gera as linhas da tabela em ordem decrescente de risco
            for risk_level in self.risk_order:
                count = self.risk_counts[risk_level]
                if count > 0:
                    priority = "Ação Imediata (Bloqueio ou Patch)" if risk_level == "Crítico" else \
                               "Prioridade Máxima (Hotfix)" if risk_level == "Alto" else \
                               "Prioridade de Sprint (Correção Planejada)" if risk_level == "Médio" else \
                               "Revisão e Boas Práticas" if risk_level == "Baixo" else \
                               "Documentação e Limpeza"
                    summary_table.append(f"| **{risk_level}** | {count} | {priority} |")
            
            report_content.extend(summary_table)

        # 3. Explicação dos Níveis de Risco
        report_content.append("\n### Chave de Nível de Risco")
        report_content.append("* **Crítico/Alto:** Vulnerabilidades que, se exploradas, permitem acesso não autorizado, execução remota de código (RCE) ou perda de dados sensíveis. Exigem intervenção imediata.")
        report_content.append("* **Médio:** Vulnerabilidades que podem levar à escalonamento de privilégios ou impacto de segurança moderado (ex: Clickjacking, falta de headers CSP).")
        report_content.append("* **Baixo/Informacional:** Achados que representam exposição de informações (ex: banners de servidor) ou a ausência de melhores práticas de segurança. Não representam risco de exploração imediata, mas devem ser corrigidos como parte da higiene de segurança.")

        report_content.append("\n---")

        # --- DETALHES DAS VULNERABILIDADES (por Risco) ---
        report_content.append("\n## 🚨 Detalhamento das Descobertas")
        
        # Itera sobre os níveis de risco na ordem correta
        for risk_level in self.risk_order:
            findings = self.grouped_vulnerabilities[risk_level]
            
            if not findings:
                continue
                
            report_content.append(f"\n### {risk_level} ({len(findings)} Descobertas)")
            
            # Itera sobre as vulnerabilidades dentro do nível de risco
            for i, vuln in enumerate(findings, 1):
                vuln_type = vuln.get('type', 'Geral')
                description = vuln.get('description', 'Descrição não fornecida.')
                mitigation = vuln.get('mitigation', 'Mitigação Padrão: Revisão da configuração de segurança.')
                technical_details = vuln.get('technical_details', {})
                
                report_content.append(f"\n#### {i}. Tipo: {vuln_type}")
                report_content.append(f"\n> **Descrição:** {description}")
                
                # Mitigação
                report_content.append("\n##### 🛠️ Recomendação de Mitigação")
                report_content.append(f"* **Ação:** {mitigation}")
                
                # Detalhes Técnicos (Formatado como um bloco de código ou lista)
                if technical_details:
                    report_content.append("\n##### ⚙️ Detalhes Técnicos")
                    report_content.append("```json")
                    
                    # Usa json.dumps para formatar os detalhes técnicos, garantindo uma saída JSON limpa
                    report_content.append(json.dumps(technical_details, indent=2))
                        
                    report_content.append("```")
                
                report_content.append("\n***") # Separador para cada vulnerabilidade

        # --- CONCLUSÃO ---
        report_content.append("\n## Fim do Relatório")
        report_content.append("A segurança é um processo contínuo. Este relatório serve como ponto de partida para a remediação e deve ser integrado ao ciclo de desenvolvimento de software (SDLC).")
        
        full_report = "\n".join(report_content)

        with open(f"{self.filepath}.md", "w", encoding="utf-8") as f:
            f.write(full_report)

        return
