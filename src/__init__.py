import sys
from scanner import Scanner
from report_generator import ReportGenerator

def generate_filename():
    return "report_0"

if __name__ == "__main__":
    if(len(sys.argv) > 1):
        url = sys.argv[1]
    else:
        raise Exception("Please specify the domain URL on calling")
    
    filename = generate_filename()
    
    scanner = Scanner(url)
    scanner.run()

    vulnerabilities = scanner.getVulnerabilities()

    report_generator = ReportGenerator(url, filename, vulnerabilities)
    report_generator.generate_markdown_report()