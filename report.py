from colorama import Fore, Style
from typing import Dict, Any
from datetime import datetime


def print_report(scan_results: Dict[str, Any]) -> None:
    """
    Выводит красивый консольный отчет о результатах сканирования безопасности.

    Args:
        scan_results (Dict): Результаты сканирования из scanner.py
    """
    print(Fore.CYAN + "\n🔐 ОТЧЕТ БЕЗОПАСНОСТИ ЗАГОЛОВКОВ" + Style.RESET_ALL)
    print("=" * 60)

    # Основная информация
    print(f"{Fore.YELLOW}🎯 Цель:{Style.RESET_ALL} {scan_results['target']}")
    print(f"{Fore.YELLOW}📅 Дата:{Style.RESET_ALL} {scan_results['date']}")
    print(f"{Fore.YELLOW}⏱️  Длительность:{Style.RESET_ALL} {scan_results['scan_duration']}с")
    print(f"{Fore.YELLOW}📊 Статус:{Style.RESET_ALL} {scan_results['http_status']}")

    # Оценка безопасности
    score = scan_results['security_score']
    if score >= 80:
        score_color = Fore.GREEN
        level = "ОТЛИЧНО"
    elif score >= 60:
        score_color = Fore.YELLOW
        level = "УДОВЛЕТВОРИТЕЛЬНО"
    else:
        score_color = Fore.RED
        level = "НИЗКИЙ УРОВЕНЬ"

    print(f"{score_color}🛡️  Оценка безопасности: {score}% - {level}{Style.RESET_ALL}")

    # Статистика заголовков
    print(f"{Fore.CYAN}📋 Заголовки:{Style.RESET_ALL} {scan_results['present_headers']}/{scan_results['total_headers']} "
          f"({scan_results['critical_headers_present']} критических)")

    # Детализация заголовков
    print(Fore.CYAN + "\n🔍 ЗАГОЛОВКИ БЕЗОПАСНОСТИ:" + Style.RESET_ALL)
    print("-" * 50)

    for header in scan_results['headers']:
        status = "✅ ПРИСУТСТВУЕТ" if header['present'] else "❌ ОТСУТСТВУЕТ"

        if header['present']:
            # Зеленый для присутствующих
            print(f"{Fore.GREEN}{status}{Style.RESET_ALL} {header['name']}")
            print(
                f"   {Fore.WHITE}Значение: {header['value'][:100]}{'...' if len(header['value']) > 100 else ''}{Style.RESET_ALL}")
            print(f"   {Fore.BLUE}Риск: {header['risk']}{Style.RESET_ALL}")

            # Предупреждения
            for warning in header['warnings']:
                if '🚨' in warning or 'КРИТИЧЕСКО' in warning:
                    print(f"   {Fore.RED}{warning}{Style.RESET_ALL}")
                elif '⚠️' in warning:
                    print(f"   {Fore.YELLOW}{warning}{Style.RESET_ALL}")
                else:
                    print(f"   {Fore.WHITE}{warning}{Style.RESET_ALL}")

            # Рекомендации
            for recommendation in header['recommendations']:
                if recommendation.startswith('✅'):
                    print(f"   {Fore.GREEN}{recommendation}{Style.RESET_ALL}")
        else:
            # Красный для отсутствующих
            print(f"{Fore.RED}{status}{Style.RESET_ALL} {header['name']}")
            print(f"   {Fore.RED}Риск: {header['risk']}{Style.RESET_ALL}")

        print()

    # Выявленные проблемы
    print(Fore.CYAN + "⚠️  ВЫЯВЛЕННЫЕ ПРОБЛЕМЫ:" + Style.RESET_ALL)
    print("-" * 50)

    if scan_results['issues']:
        for i, issue in enumerate(scan_results['issues'], 1):
            if issue.startswith('🚨') or 'КРИТИЧЕСКО' in issue:
                print(f"{Fore.RED}{i}. {issue}{Style.RESET_ALL}")
            elif issue.startswith('❌'):
                print(f"{Fore.RED}{i}. {issue}{Style.RESET_ALL}")
            elif issue.startswith('⚠️'):
                print(f"{Fore.YELLOW}{i}. {issue}{Style.RESET_ALL}")
            else:
                print(f"{Fore.WHITE}{i}. {issue}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}✅ Проблем не обнаружено! Отличная безопасность!{Style.RESET_ALL}")

    # Информация о сервере
    if scan_results['server_info']:
        print(Fore.CYAN + "\n🖥️  ИНФОРМАЦИЯ О СЕРВЕРЕ:" + Style.RESET_ALL)
        print("-" * 30)
        for key, value in scan_results['server_info'].items():
            if value:
                print(f"{Fore.WHITE}{key}: {value}{Style.RESET_ALL}")


def generate_text_report(scan_results: Dict[str, Any]) -> str:
    """
    Генерирует текстовый отчет в виде строки.

    Args:
        scan_results (Dict): Результаты сканирования

    Returns:
        str: Форматированный текстовый отчет
    """
    report_lines = [
        "=" * 70,
        "ОТЧЕТ БЕЗОПАСНОСТИ HTTP-ЗАГОЛОВКОВ",
        "=" * 70,
        f"Цель: {scan_results['target']}",
        f"Финальный URL: {scan_results.get('final_url', scan_results['target'])}",
        f"Дата сканирования: {scan_results['date']}",
        f"Длительность сканирования: {scan_results['scan_duration']}с",
        f"HTTP статус: {scan_results['http_status']}",
        f"Было редиректов: {'Да' if scan_results.get('redirected', False) else 'Нет'}",
        "",
        f"ОЦЕНКА БЕЗОПАСНОСТИ: {scan_results['security_score']}%",
        f"Заголовков обнаружено: {scan_results['present_headers']}/{scan_results['total_headers']}",
        f"Критических заголовков: {scan_results['critical_headers_present']}",
        "",
        "ЗАГОЛОВКИ БЕЗОПАСНОСТИ:",
        "-" * 50
    ]

    # Добавляем информацию о каждом заголовке
    for header in scan_results['headers']:
        status = "ПРИСУТСТВУЕТ" if header['present'] else "ОТСУТСТВУЕТ"
        symbol = "✅" if header['present'] else "❌"

        report_lines.append(f"{symbol} {header['name']}: {status}")
        report_lines.append(f"   Описание: {header['description']}")
        report_lines.append(f"   Риск: {header['risk']}")
        report_lines.append(f"   Критичность: {'Да' if header['critical'] else 'Нет'}")

        if header['present']:
            report_lines.append(f"   Значение: {header['value']}")

            if header['warnings']:
                report_lines.append("   Предупреждения:")
                for warning in header['warnings']:
                    report_lines.append(f"     - {warning}")

            if header['recommendations']:
                report_lines.append("   Рекомендации:")
                for rec in header['recommendations']:
                    report_lines.append(f"     - {rec}")
        else:
            report_lines.append("   Рекомендация: Необходимо добавить этот заголовок")

        report_lines.append("")

    # Выявленные проблемы
    report_lines.extend([
        "ВЫЯВЛЕННЫЕ ПРОБЛЕМЫ:",
        "-" * 50
    ])

    if scan_results['issues']:
        for i, issue in enumerate(scan_results['issues'], 1):
            report_lines.append(f"{i}. {issue}")
    else:
        report_lines.append("✅ Критических проблем не обнаружено!")

    # Информация о сервере
    if scan_results.get('server_info'):
        server_info = scan_results['server_info']
        if any(server_info.values()):
            report_lines.extend([
                "",
                "ИНФОРМАЦИЯ О СЕРВЕРЕ:",
                "-" * 30
            ])
            for key, value in server_info.items():
                if value:
                    report_lines.append(f"{key}: {value}")

    report_lines.extend([
        "",
        "=" * 70,
        f"Отчет сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "Конец отчета"
    ])

    return "\n".join(report_lines)


def save_report_to_file(scan_results: Dict[str, Any],
                        filename: str = "security_report.txt") -> bool:
    """
    Сохраняет текстовый отчет в файл.

    Args:
        scan_results (Dict): Результаты сканирования
        filename (str): Имя файла для сохранения

    Returns:
        bool: True если сохранение успешно, False в случае ошибки
    """
    try:
        report_text = generate_text_report(scan_results)

        with open(filename, 'w', encoding='utf-8') as file:
            file.write(report_text)

        print(f"{Fore.GREEN}✅ Отчет сохранен в файл: {filename}{Style.RESET_ALL}")
        return True

    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка при сохранении отчета: {str(e)}{Style.RESET_ALL}")
        return False


def print_security_score(score: int) -> None:
    """
    Выводит цветную оценку безопасности в консоль.

    Args:
        score (int): Оценка безопасности от 0 до 100
    """
    print(Fore.CYAN + "\n📊 ОБЩАЯ ОЦЕНКА БЕЗОПАСНОСТИ" + Style.RESET_ALL)

    if score >= 80:
        color = Fore.GREEN
        level = "ОТЛИЧНО"
        emoji = "🎉"
    elif score >= 60:
        color = Fore.YELLOW
        level = "УДОВЛЕТВОРИТЕЛЬНО"
        emoji = "⚠️"
    else:
        color = Fore.RED
        level = "НИЗКИЙ УРОВЕНЬ"
        emoji = "🚨"

    print(f"{color}{emoji} Оценка: {score}% - {level}{Style.RESET_ALL}")


def generate_short_summary(scan_results: Dict[str, Any]) -> str:
    """
    Генерирует краткую сводку для быстрого просмотра.

    Args:
        scan_results (Dict): Результаты сканирования

    Returns:
        str: Краткая сводка
    """
    score = scan_results['security_score']

    if score >= 80:
        status = "🟢 БЕЗОПАСНО"
    elif score >= 60:
        status = "🟡 ТРЕБУЕТ ВНИМАНИЯ"
    else:
        status = "🔴 ОПАСНО"

    critical_issues = sum(1 for issue in scan_results['issues']
                          if '🚨' in issue or 'КРИТИЧЕСКО' in issue)

    return (f"{status} | Оценка: {score}% | "
            f"Заголовки: {scan_results['present_headers']}/{scan_results['total_headers']} | "
            f"Критические проблемы: {critical_issues}")


# Пример использования
if __name__ == "__main__":
    # Тестовые данные для демонстрации
    sample_results = {
        'target': 'https://example.com',
        'date': '2024-01-15 14:30:00',
        'security_score': 75,
        'scan_duration': 2.5,
        'http_status': 200,
        'final_url': 'https://example.com',
        'redirected': False,
        'present_headers': 8,
        'total_headers': 11,
        'critical_headers_present': 3,
        'headers': [
            {
                'name': 'Content-Security-Policy',
                'present': True,
                'value': "default-src 'self'",
                'risk': 'Низкий',
                'description': 'Защита от XSS и внедрения кода',
                'critical': True,
                'warnings': [],
                'recommendations': ['✅ CSP настроен']
            },
            {
                'name': 'Strict-Transport-Security',
                'present': False,
                'value': None,
                'risk': 'Высокий',
                'description': 'Принудительное использование HTTPS',
                'critical': True,
                'warnings': [],
                'recommendations': []
            }
        ],
        'issues': [
            "❌ HSTS отсутствует — возможны downgrade атаки на HTTPS",
            "⚠️ CORS открыт для всех доменов (Access-Control-Allow-Origin: *)"
        ],
        'server_info': {
            'server': 'nginx/1.18.0',
            'x_powered_by': None,
            'content_type': 'text/html'
        },
        'error': None
    }

    # Демонстрация работы
    print_report(sample_results)
    print("\n" + "=" * 60)
    print("Краткая сводка:", generate_short_summary(sample_results))