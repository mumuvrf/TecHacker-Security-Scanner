import sys
from scanner import Scanner
from report_generator import ReportGenerator
from utils.tools import generate_filename

from pathlib import Path

if __name__ == "__main__":
    if(len(sys.argv) > 1):
        url = sys.argv[1]
    else:
        raise Exception("Please specify the domain URL on calling")
    
    filename = generate_filename()
    
    scanner = Scanner(url)
    scanner.run()

    vulnerabilities = scanner.getVulnerabilities()

    report_generator = ReportGenerator(url, vulnerabilities)
    md_report = report_generator.generate_markdown_report()

    filepath = Path(__file__).resolve().parent / "results" / filename
    with open(f"{filepath}.md", "w", encoding="utf-8") as f:
        f.write(md_report)

    print(f"Scan concluído! Seu relatório de segurança está disponível em /src/results/{filename}.md")