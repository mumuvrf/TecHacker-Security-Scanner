import datetime

class ReportGenerator:
    def __init__(self, url, filename, vulnerabilities):
        self.url = url
        self.filename = filename
        self.vulnerabilities = vulnerabilities

    def generate_markdown_report(self) -> str:
        """
        Gera um relatório completo de vulnerabilidades no formato Markdown.

        Args:
            vulnerabilities (list): Lista de dicionários de vulnerabilidades padronizados.
            target_url (str): A URL ou alvo que foi escaneado.

        Returns:
            str: O conteúdo completo do relatório em Markdown.
        """
        
        # 1. Preparação e Estatísticas
        report_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Mapeamento e Contagem de Riscos
        risk_order = ["Crítico", "Alto", "Médio", "Baixo", "Informacional"]
        risk_counts = {risk: 0 for risk in risk_order}
        
        # Agrupamento das vulnerabilidades por Nível de Risco
        grouped_vulnerabilities = {risk: [] for risk in risk_order}

        for vuln in self.vulnerabilities:
            risk = vuln.get("risk", "Informacional") # Default para Informacional se faltar
            if risk in risk_counts:
                risk_counts[risk] += 1
                grouped_vulnerabilities[risk].append(vuln)

        total_findings = sum(risk_counts.values())

        # 2. Construção do Relatório
        report_content = []
        
        # Título Principal e Metadados
        report_content.append(f"# 🛡️ Relatório de Varredura de Vulnerabilidades")
        report_content.append(f"\n* **Alvo (URL/IP):** `{self.url}`")
        report_content.append(f"* **Data do Scan:** {report_date}")
        report_content.append(f"* **Total de Descobertas:** **{total_findings}**\n")
        report_content.append("---")
        
        # --- SUMÁRIO EXECUTIVO ---
        report_content.append("\n## 📝 Sumário Executivo")
        
        if total_findings == 0:
            report_content.append("Nenhuma vulnerabilidade ou descoberta de risco foi identificada neste scan.")
        else:
            summary_table = [
                "| Nível de Risco | Contagem | Prioridade |",
                "| :--- | :---: | :--- |"
            ]
            
            # Gera as linhas da tabela em ordem decrescente de risco
            for risk_level in risk_order:
                count = risk_counts[risk_level]
                if count > 0:
                    priority = "Ação Imediata" if risk_level in ["Crítico", "Alto"] else "Prioridade de Sprint" if risk_level == "Médio" else "Revisão"
                    summary_table.append(f"| **{risk_level}** | {count} | {priority} |")
            
            report_content.extend(summary_table)

        report_content.append("\nO scan automatizado identificou vulnerabilidades e descobertas de infraestrutura. As seções a seguir detalham cada achado por nível de risco, fornecendo recomendações de mitigação para a equipe de desenvolvimento e infraestrutura.")
        report_content.append("\n---")

        # --- DETALHES DAS VULNERABILIDADES (por Risco) ---
        report_content.append("\n## 🚨 Detalhamento das Descobertas")
        
        # Itera sobre os níveis de risco na ordem correta
        for risk_level in risk_order:
            findings = grouped_vulnerabilities[risk_level]
            
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
                    
                    # Formata os detalhes técnicos para exibição limpa
                    for key, value in technical_details.items():
                        report_content.append(f"{key}: {value}")
                        
                    report_content.append("```")
                
                report_content.append("\n***") # Separador para cada vulnerabilidade

        # --- CONCLUSÃO ---
        report_content.append("\n## Fim do Relatório")
        report_content.append("A segurança é um processo contínuo. Este relatório serve como ponto de partida para a remediação.")
        
        full_report = "\n".join(report_content)

        with open(self.filename+".md", "w", encoding="utf-8") as f:
            f.write(full_report)

        return
