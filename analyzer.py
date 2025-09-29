from typing import Dict, List, Optional, Any
from ethic import ethical_explain


def analyze(headers: Dict[str, Optional[str]]) -> List[str]:
    """
    Анализирует HTTP-заголовки безопасности и выявляет потенциальные уязвимости.

    Args:
        headers (Dict[str, Optional[str]]): Словарь HTTP-заголовков

    Returns:
        List[str]: Список выявленных проблем с иконками и описаниями
    """
    issues: List[str] = []

    # Проверка Content-Security-Policy
    csp_value = headers.get("Content-Security-Policy")
    if not csp_value:
        issues.append("❌ CSP отсутствует — сайт уязвим к XSS.")
    else:
        csp_issues = _analyze_csp(csp_value)
        issues.extend(csp_issues)

    # Проверка CORS политики
    cors_value = headers.get("Access-Control-Allow-Origin")
    if cors_value == "*":
        issues.append("🚨 CORS открыт для всех доменов — возможна утечка данных!")
    elif not cors_value:
        issues.append("ℹ️ CORS политика не настроена")

    # Проверка CORS credentials
    cors_creds = headers.get("Access-Control-Allow-Credentials")
    if cors_creds and cors_creds.lower() == "true" and cors_value == "*":
        issues.append("🚨 Опасное сочетание: CORS credentials=true с открытым origin=*!")

    # Проверка HSTS
    hsts_value = headers.get("Strict-Transport-Security")
    if not hsts_value:
        issues.append("❌ Нет HSTS — возможны атаки через downgrade.")
    else:
        hsts_issues = _analyze_hsts(hsts_value)
        issues.extend(hsts_issues)

    # Проверка защиты от clickjacking
    xfo_value = headers.get("X-Frame-Options")
    if not xfo_value:
        issues.append("❌ X-Frame-Options отсутствует — риск clickjacking атак.")
    else:
        xfo_issues = _analyze_x_frame_options(xfo_value)
        issues.extend(xfo_issues)

    # Проверка других CORS заголовков
    if not headers.get("Access-Control-Allow-Methods"):
        issues.append("⚠️ Access-Control-Allow-Methods отсутствует")

    if not headers.get("Access-Control-Allow-Headers"):
        issues.append("⚠️ Access-Control-Allow-Headers отсутствует")

    # Остальные проверки остаются без изменений...
    return issues


def _analyze_cors_policy(headers: Dict[str, Optional[str]]) -> List[str]:
    """Анализ CORS политики"""
    issues = []
    origin = headers.get("Access-Control-Allow-Origin")
    credentials = headers.get("Access-Control-Allow-Credentials")

    if origin == "*":
        issues.append("🚨 CORS: открыт для всех доменов")
        if credentials and credentials.lower() == "true":
            issues.append("🚨 CORS: credentials=true несовместимо с origin=*")

    return issues