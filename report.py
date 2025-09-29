from colorama import Fore, Style
from typing import Dict, List, Optional, Any


def print_report(headers: Dict[str, Optional[str]], issues: List[str]) -> None:
    """
    Выводит красивый консольный отчет о результатах сканирования безопасности.
    """
    print(Fore.CYAN + "\n🔐 Заголовки безопасности:" + Style.RESET_ALL)

    for header_name, header_value in headers.items():
        status = header_value if header_value else "❌ Отсутствует"

        # Цветовое выделение для CORS заголовков
        if header_name.startswith("Access-Control-"):
            if header_value == "*" and header_name == "Access-Control-Allow-Origin":
                print(f"{Fore.RED}{header_name}: {status}{Style.RESET_ALL}")
            else:
                print(f"{Fore.BLUE}{header_name}: {status}{Style.RESET_ALL}")
        elif header_value:
            print(f"{Fore.GREEN}{header_name}: {status}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}{header_name}: {status}{Style.RESET_ALL}")

    print(Fore.YELLOW + "\n⚠️ Выявленные проблемы:" + Style.RESET_ALL)

    for issue in issues:
        if issue.startswith("🚨"):
            print(f"{Fore.RED}{issue}{Style.RESET_ALL}")
        elif issue.startswith("❌"):
            print(f"{Fore.RED}{issue}{Style.RESET_ALL}")
        elif issue.startswith("⚠️"):
            print(f"{Fore.YELLOW}{issue}{Style.RESET_ALL}")
        elif issue.startswith("✅"):
            print(f"{Fore.GREEN}{issue}{Style.RESET_ALL}")
        else:
            print(issue)


def generate_text_report(headers: List[Dict[str, Any]], issues: List[str],
                         target: str, security_score: int) -> str:
    """
    Генерирует текстовый отчет в виде строки (альтернатива консольному выводу).
    Полезен для сохранения отчетов в файлы, отправки по email
    или интеграции с другими системами.
    Args:
        headers (List[Dict[str, Any]]): Список заголовков в формате сканера
            Каждый заголовок имеет поля: 'name', 'present', 'value', 'risk'
        issues (List[str]): Список выявленных проблем
        target (str): Целевой URL который сканировался
        security_score (int): Общая оценка безопасности в процентах
    Returns:
        str: Форматированный текстовый отчет
    Example:
        >>> report_text = generate_text_report(headers, issues, "https://example.com", 75)
        >>> print(report_text)
    """
    report_lines = [
        "=" * 60,
        "ОТЧЕТ БЕЗОПАСНОСТИ ЗАГОЛОВКОВ",
        "=" * 60,
        f"Цель: {target}",
        f"Оценка безопасности: {security_score}%",
        f"Дата генерации: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "ЗАГОЛОВКИ БЕЗОПАСНОСТИ:",
        "-" * 40
    ]

    # Добавляем информацию о каждом заголовке
    for header in headers:
        status = "✅ ПРИСУТСТВУЕТ" if header['present'] else "❌ ОТСУТСТВУЕТ"
        value = header['value'] or "Не установлен"
        report_lines.append(f"{header['name']}: {status}")
        if header['present']:
            report_lines.append(f"  Значение: {value}")
        report_lines.append(f"  Риск: {header['risk']}")
        report_lines.append("")

    # Добавляем выявленные проблемы
    report_lines.extend([
        "ВЫЯВЛЕННЫЕ ПРОБЛЕМЫ:",
        "-" * 40
    ])

    if issues:
        for i, issue in enumerate(issues, 1):
            report_lines.append(f"{i}. {issue}")
    else:
        report_lines.append("✅ Проблем не обнаружено!")

    report_lines.extend([
        "",
        "=" * 60,
        "Конец отчета"
    ])

    return "\n".join(report_lines)


def save_report_to_file(headers: List[Dict[str, Any]], issues: List[str],
                        target: str, security_score: int,
                        filename: str = "security_report.txt") -> bool:
    """
    Сохраняет текстовый отчет в файл.
    Args:
        headers (List[Dict[str, Any]]): Список заголовков
        issues (List[str]): Список проблем
        target (str): Целевой URL
        security_score (int): Оценка безопасности
        filename (str): Имя файла для сохранения (по умолчанию "security_report.txt")
    Returns:
        bool: True если сохранение успешно, False в случае ошибки
    Example:
    """
    try:
        report_text = generate_text_report(headers, issues, target, security_score)

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
    Returns:
        None
    """
    print(Fore.CYAN + "\n📊 ОБЩАЯ ОЦЕНКА БЕЗОПАСНОСТИ" + Style.RESET_ALL)
    if score >= 80:
        color = Fore.GREEN
        level = "ОТЛИЧНО"
    elif score >= 60:
        color = Fore.YELLOW
        level = "УДОВЛЕТВОРИТЕЛЬНО"
    else:
        color = Fore.RED
        level = "НИЗКИЙ УРОВЕНЬ"

    print(f"{color}Оценка: {score}% - {level}{Style.RESET_ALL}")


# Пример использования всех функций
if __name__ == "__main__":
    # Тестовые данные для демонстрации
    sample_headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": None,
        "X-Content-Type-Options": "nosniff"
    }
    sample_issues = [
        "❌ X-Frame-Options отсутствует — Clickjacking",
        "⚠️ Content-Security-Policy содержит 'unsafe-inline' - снижает безопасность",
        "✅ Strict-Transport-Security правильно настроен"
    ]
    # Демонстрация работы
    print_report(sample_headers, sample_issues)
    print_security_score(75)
    # Пример сохранения в файл
    headers_list = [
        {"name": "CSP", "present": True, "value": "default-src 'self'", "risk": "XSS"},
        {"name": "HSTS", "present": False, "value": None, "risk": "SSL stripping"}
    ]
    save_report_to_file(headers_list, sample_issues, "https://example.com", 75)
