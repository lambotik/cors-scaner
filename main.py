#!/usr/bin/env python3
"""
CORS Scanner - Командный интерфейс для сканирования безопасности HTTP-заголовков.

Модуль предоставляет CLI для проверки security-заголовков веб-сайтов
с возможностью генерации HTML и текстовых отчетов.
"""

import argparse
import os
import sys
from typing import Optional
from scanner import scan_headers
from report_generator import generate_html_report_jinja
from report import save_report_to_file


def check_template() -> None:
    """
    Проверяет наличие необходимых шаблонов для генерации отчетов.
    Raises:
        SystemExit: Если шаблон отчета не найден
    Note:
        Проверяет наличие templates/report.html для Jinja2 шаблонов
    """
    template_path = "templates/report.html"
    if not os.path.exists(template_path):
        print("❌ Шаблон отчёта не найден.")
        print(f"   Ожидаемый путь: {template_path}")
        print("   Убедитесь, что папка templates существует и содержит report.html")
        sys.exit(1)


def validate_url(url: str) -> bool:
    """
    Проверяет корректность формата URL.
    Args:
        url (str): URL для валидации
    Returns:
        bool: True если URL валиден, False в противном случае
    """
    # Базовая проверка формата URL
    if not url.startswith(('http://', 'https://')):
        print(f"⚠️  Предупреждение: URL не содержит протокол, будет использован HTTPS")
        return True

    # Можно добавить более сложную валидацию с помощью urllib.parse
    return True


def print_summary(results: dict, output_format: str, output_path: str) -> None:
    """
    Выводит краткую сводку результатов сканирования.
    Args:
        results (dict): Результаты сканирования от scan_headers()
        output_format (str): Формат вывода ('html', 'text', 'both')
        output_path (str): Путь для сохранения отчета
    """
    print("\n" + "=" * 50)
    print("📊 СВОДКА СКАНИРОВАНИЯ")
    print("=" * 50)
    print(f"🎯 Цель: {results['target']}")
    print(f"📅 Время: {results['date']}")
    print(f"🛡️  Оценка безопасности: {results['security_score']}%")
    print(f"📋 Заголовков проверено: {results['total_headers']}")
    print(f"⚠️  Проблем обнаружено: {len(results['issues'])}")
    print(f"💾 Формат отчета: {output_format}")
    print(f"📁 Файл отчета: {output_path}")
    print("=" * 50)


def setup_argparse() -> argparse.ArgumentParser:
    """
    Настраивает парсер аргументов командной строки.
    Returns:
        argparse.ArgumentParser: Настроенный парсер аргументов
    """
    parser = argparse.ArgumentParser(
        description="CORS Scanner - Анализ безопасности HTTP-заголовков",
        epilog="""
Примеры использования:
  %(prog)s https://example.com
  %(prog)s https://google.com --html google_report.html
  %(prog)s https://yandex.ru --format text --output scan_result.txt
  %(prog)s https://github.com --format both --verbose
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Обязательный аргумент - URL для сканирования
    parser.add_argument(
        "url",
        help="Целевой URL для сканирования (с http:// или https://)"
    )

    # Опциональные аргументы
    parser.add_argument(
        "--html",
        help="Путь для сохранения HTML-отчёта (по умолчанию: report.html)",
        default="report.html"
    )

    parser.add_argument(
        "--format", "-f",
        choices=["html", "text", "both"],
        help="Формат вывода отчета (по умолчанию: html)",
        default="html"
    )

    parser.add_argument(
        "--output", "-o",
        help="Путь для сохранения текстового отчета (по умолчанию: security_report.txt)",
        default="security_report.txt"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Подробный вывод процесса сканирования"
    )

    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=15,
        help="Таймаут запроса в секундах (по умолчанию: 15)"
    )

    return parser


def main() -> Optional[int]:
    """
    Основная функция CLI интерфейса CORS Scanner.
    Returns:
        Optional[int]: Код возврата (0 - успех, 1 - ошибка)
    Side effects:
        - Создает файлы отчетов
        - Выводит информацию в консоль
        - Может завершить программу с кодом ошибки
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Валидация входных данных
    if not validate_url(args.url):
        return 1
    # Проверка шаблонов (для HTML отчетов)
    if args.format in ["html", "both"]:
        try:
            check_template()
        except SystemExit:
            return 1
    if args.verbose:
        print(f"🔍 Начинаем сканирование: {args.url}")
        print(f"⏰ Таймаут: {args.timeout} секунд")
    try:
        # Выполняем сканирование
        results = scan_headers(args.url)
        if results["error"]:
            print("❌ Ошибка при сканировании:")
            for issue in results["issues"]:
                print(f"   {issue}")
            return 1
        # Генерация отчетов в выбранном формате
        if args.format in ["html", "both"]:
            if args.verbose:
                print(f"💾 Генерируем HTML отчет: {args.html}")
            generate_html_report_jinja(results, output_path=args.html)
        if args.format in ["text", "both"]:
            if args.verbose:
                print(f"💾 Генерируем текстовый отчет: {args.output}")
            success = save_report_to_file(
                results["headers"],
                results["issues"],
                results["target"],
                results["security_score"],
                args.output
            )
            if not success:
                return 1

        # Вывод сводки
        print_summary(results, args.format, args.html if args.format == "html" else args.output)

        # Дополнительная информация при наличии проблем
        if results["security_score"] < 60 and len(results["issues"]) > 0:
            print("\n🚨 РЕКОМЕНДАЦИИ ПО УЛУЧШЕНИЮ БЕЗОПАСНОСТИ:")
            for issue in results["issues"][:5]:  # Показываем первые 5 проблем
                if issue.startswith(("❌", "⚠️")):
                    print(f"   {issue}")

        return 0

    except KeyboardInterrupt:
        print("\n⏹️  Сканирование прервано пользователем")
        return 1

    except Exception as e:
        print(f"❌ Неожиданная ошибка: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    """
    Точка входа при запуске скрипта напрямую.
    Обрабатывает аргументы командной строки и запускает сканирование.
    """
    exit_code = main()
    sys.exit(exit_code)
