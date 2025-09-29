from typing import Dict, List, Optional, Any
from ethic import ethical_explain


def analyze(headers: Dict[str, Optional[str]]) -> List[str]:
    """
    Анализирует HTTP-заголовки безопасности и выявляет потенциальные уязвимости.
    Проверяет наличие критически важных security-заголовков и анализирует 
    их значения на предмет опасных настроек.
    Args:
        headers (Dict[str, Optional[str]]): Словарь HTTP-заголовков, 
            где ключ - название заголовка, значение - его содержимое или None
    Returns:
        List[str]: Список выявленных проблем с иконками и описаниями
    Example:
        ['⚠️ CORS открыт для всех — возможна утечка данных.']
    """
    issues: List[str] = []
    # Проверка Content-Security-Policy
    csp_value = headers.get("Content-Security-Policy")
    if not csp_value:
        issues.append("❌ CSP отсутствует — сайт уязвим к XSS.")
    else:
        # Глубокий анализ CSP политики
        csp_issues = _analyze_csp(csp_value)
        issues.extend(csp_issues)
    # Проверка CORS политики
    cors_value = headers.get("Access-Control-Allow-Origin")
    if cors_value == "*":
        issues.append("⚠️ CORS открыт для всех — возможна утечка данных.")
    elif not cors_value:
        issues.append("ℹ️ CORS политика не настроена — могут быть проблемы с кросс-доменными запросами.")
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
    # Проверка MIME-sniffing защиты
    xcto_value = headers.get("X-Content-Type-Options")
    if not xcto_value:
        issues.append("❌ X-Content-Type-Options отсутствует — риск MIME-sniffing атак.")
    elif xcto_value.lower() != "nosniff":
        issues.append(f"⚠️ X-Content-Type-Options имеет нестандартное значение: {xcto_value}")
    # Проверка политики реферера
    referrer_value = headers.get("Referrer-Policy")
    if not referrer_value:
        issues.append("❌ Referrer-Policy отсутствует — возможна утечка данных реферера.")
    else:
        referrer_issues = _analyze_referrer_policy(referrer_value)
        issues.extend(referrer_issues)
    # Проверка политики разрешений
    permissions_value = headers.get("Permissions-Policy")
    if not permissions_value:
        issues.append("⚠️ Permissions-Policy отсутствует — ограничен контроль над API устройств.")
    # Проверка защиты от XSS (устаревшая, но все еще полезная)
    xss_value = headers.get("X-XSS-Protection")
    if not xss_value:
        issues.append("ℹ️ X-XSS-Protection отсутствует — современные браузеры имеют встроенную защиту.")
    elif xss_value == "0":
        issues.append("⚠️ X-XSS-Protection отключен — рекомендуется '1; mode=block'")
    return issues


def _analyze_csp(csp_value: str) -> List[str]:
    """
    Анализирует политику безопасности контента (CSP) на наличие опасных директив.
    Args:
        csp_value (str): Значение Content-Security-Policy заголовка
    Returns:
        List[str]: Список проблем, связанных с CSP
    """
    issues = []
    csp_lower = csp_value.lower()
    # Проверка опасных директив
    if "'unsafe-inline'" in csp_lower:
        issues.append("⚠️ CSP содержит 'unsafe-inline' — снижает защиту от XSS.")
    if "'unsafe-eval'" in csp_lower:
        issues.append("⚠️ CSP содержит 'unsafe-eval' — разрешает выполнение eval().")
    if "default-src *" in csp_lower or "default-src 'none'" not in csp_lower:
        # Проверяем наличие default-src (рекомендуется)
        if "default-src" not in csp_lower:
            issues.append("ℹ️ CSP не содержит default-src директиву — рекомендуется явное указание.")
    # Проверка слишком разрешительных политик
    if "script-src *" in csp_lower:
        issues.append("🚨 CSP: script-src * — крайне опасно, разрешает скрипты с любых источников!")
    if "style-src *" in csp_lower:
        issues.append("🚨 CSP: style-src * — разрешает стили с любых источников!")
    return issues


def _analyze_hsts(hsts_value: str) -> List[str]:
    """
    Анализирует настройки Strict-Transport-Security.
    Args:
        hsts_value (str): Значение HSTS заголовка
    Returns:
        List[str]: Список проблем, связанных с HSTS
    """
    issues = []
    hsts_lower = hsts_value.lower()
    # Проверка отключенного HSTS
    if "max-age=0" in hsts_lower:
        issues.append("🚨 HSTS отключен (max-age=0) — HTTPS downgrade атаки возможны!")
    # Проверка слишком короткого max-age
    if "max-age=" in hsts_lower:
        try:
            # Извлекаем значение max-age
            max_age_str = hsts_value.split("max-age=")[1].split(";")[0].strip()
            max_age = int(max_age_str)

            if max_age < 31536000:  # 1 год в секундах
                issues.append(f"⚠️ HSTS max-age={max_age} — рекомендуется минимум 31536000 (1 год)")
        except (ValueError, IndexError):
            issues.append("⚠️ HSTS имеет некорректный max-age параметр")
    # Проверка включения includeSubDomains
    if "includesubdomains" not in hsts_lower:
        issues.append("ℹ️ HSTS не включает includeSubDomains — поддомены не защищены")
    # Проверка preload директивы
    if "preload" not in hsts_lower:
        issues.append("ℹ️ HSTS не включает preload — не защищен от первой атаки")
    return issues


def _analyze_x_frame_options(xfo_value: str) -> List[str]:
    """
    Анализирует настройки X-Frame-Options.
    Args:
        xfo_value (str): Значение X-Frame-Options заголовка
    Returns:
        List[str]: Список проблем, связанных с X-Frame-Options
    """
    issues = []
    xfo_upper = xfo_value.upper()
    valid_values = ["DENY", "SAMEORIGIN"]
    if xfo_upper not in valid_values:
        issues.append(f"⚠️ X-Frame-Options имеет нестандартное значение: {xfo_value}")
    if xfo_upper == "SAMEORIGIN":
        issues.append("ℹ️ X-Frame-Options: SAMEORIGIN — фреймы разрешены только с того же origin")
    return issues


def _analyze_referrer_policy(referrer_value: str) -> List[str]:
    """
    Анализирует политику реферера на предмет утечки данных.
    Args:
        referrer_value (str): Значение Referrer-Policy заголовка
    Returns:
        List[str]: Список проблем, связанных с Referrer-Policy
    """
    issues = []
    referrer_lower = referrer_value.lower()

    # Список безопасных политик реферера
    safe_policies = [
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "origin",
        "strict-origin",
        "origin-when-cross-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url"
    ]

    if referrer_lower not in [p.lower() for p in safe_policies]:
        issues.append(f"⚠️ Referrer-Policy имеет неизвестное значение: {referrer_value}")
    # Предупреждения для менее безопасных политик
    if referrer_lower == "unsafe-url":
        issues.append("⚠️ Referrer-Policy: unsafe-url — передает полный URL в реферере")
    if referrer_lower == "no-referrer-when-downgrade":
        issues.append("ℹ️ Referrer-Policy: no-referrer-when-downgrade — стандартное поведение браузеров")
    return issues


def analyze_with_ethical_context(headers: Dict[str, Optional[str]]) -> Dict[str, Any]:
    """
    Расширенный анализ заголовков с этическим контекстом.
    Объединяет технический анализ с этическими аспектами безопасности.
    Args:
        headers (Dict[str, Optional[str]]): Словарь HTTP-заголовков
    Returns:
        Dict[str, Any]: Расширенные результаты анализа с этическим контекстом
    """
    technical_issues = analyze(headers)
    ethical_insights = []
    # Добавляем этический контекст к проблемам
    for header_name, header_value in headers.items():
        ethical_info = ethical_explain(header_name, header_value)

        if isinstance(ethical_info, dict) and 'ethical_impact' in ethical_info:
            ethical_insights.append({
                'header': header_name,
                'value': header_value,
                'ethical_impact': ethical_info['ethical_impact'],
                'privacy_risk': ethical_info.get('privacy_risk', 'Неизвестно'),
                'user_trust': ethical_info.get('user_trust', 'Неизвестно')
            })

    return {
        'technical_issues': technical_issues,
        'ethical_insights': ethical_insights,
        'headers_analyzed': len(headers),
        'issues_count': len(technical_issues)
    }


# Пример использования
if __name__ == "__main__":
    # Тестовые данные
    test_headers = {
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
        "Strict-Transport-Security": "max-age=3600",
        "X-Frame-Options": "DENY",
        "Access-Control-Allow-Origin": "*"
    }

    # Базовый анализ
    issues = analyze(test_headers)
    print("=== БАЗОВЫЙ АНАЛИЗ ===")
    for issue in issues:
        print(issue)

    # Расширенный анализ с этическим контекстом
    print("\n=== РАСШИРЕННЫЙ АНАЛИЗ ===")
    extended_results = analyze_with_ethical_context(test_headers)
    print(f"Проанализировано заголовков: {extended_results['headers_analyzed']}")
    print(f"Найдено проблем: {extended_results['issues_count']}")

    for insight in extended_results['ethical_insights']:
        print(f"\n{insight['header']}:")
        print(f"  Этический аспект: {insight['ethical_impact']}")
        print(f"  Риск приватности: {insight['privacy_risk']}")
