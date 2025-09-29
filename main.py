import argparse
from scanner import scan_headers
from report_generator import generate_html_report_jinja
import os
import sys

def check_template():
    if not os.path.exists("templates/report.html.j2"):
        print("❌ Шаблон отчёта не найден.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="CORS и безопасность заголовков")
    parser.add_argument("url", help="Целевой URL для сканирования")
    parser.add_argument("--html", help="Путь для сохранения HTML-отчёта", default="report.html")
    args = parser.parse_args()

    check_template()
    results = scan_headers(args.url)
    generate_html_report_jinja(results, output_path=args.html)
    print(f"✅ Сканирование завершено. Отчёт сохранён в: {args.html}")

if __name__ == "__main__":
    main()
