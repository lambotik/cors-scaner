"""
Генератор HTML отчетов для CORS Scanner.
"""

import os
import jinja2
from typing import Dict, Any


def generate_html_report(scan_results: Dict[str, Any], output_path: str = "security_report.html") -> bool:
    """
    Генерирует HTML отчет в новом формате.
    """
    try:
        # Настройка Jinja2 environment
        template_loader = jinja2.FileSystemLoader(searchpath="./")
        template_env = jinja2.Environment(loader=template_loader)

        # Загрузка шаблона (теперь он в основном файле)
        template = template_env.get_template("report.html")

        # Рендеринг шаблона с данными
        html_content = template.render(**scan_results)

        # Сохранение в файл
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return True

    except Exception as e:
        print(f"❌ Ошибка генерации HTML отчета: {e}")
        return False


def generate_html_report_jinja(scan_results: Dict[str, Any], output_path: str = "report.html") -> bool:
    """
    Альтернативное название для обратной совместимости.
    """
    return generate_html_report(scan_results, output_path)


# Для обратной совместимости с старым кодом
if not os.path.exists("templates"):
    os.makedirs("templates")