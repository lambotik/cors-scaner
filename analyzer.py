from typing import Dict, List, Optional, Tuple
import re


def analyze_security_headers(headers: Dict[str, Optional[str]]) -> Tuple[List[Dict[str, any]], List[str], int]:
    """
    Комплексный анализ HTTP-заголовков безопасности.

    Args:
        headers (Dict[str, Optional[str]]): Словарь HTTP-заголовков

    Returns:
        Tuple[List[Dict], List[str], int]:
            - Список заголовков с анализом
            - Список проблем
            - Оценка безопасности (0-100)
    """

    # Определяем проверяемые заголовки с правильной категоризацией
    security_headers = [
        {
            'name': 'Content-Security-Policy',
            'description': 'Защита от XSS и внедрения кода',
            'critical': True,
            'category': 'security',
            'analyzer': _analyze_csp
        },
        {
            'name': 'Strict-Transport-Security',
            'description': 'Принудительное использование HTTPS',
            'critical': True,
            'category': 'security',
            'analyzer': _analyze_hsts
        },
        {
            'name': 'X-Frame-Options',
            'description': 'Защита от clickjacking',
            'critical': True,
            'category': 'security',
            'analyzer': _analyze_x_frame_options
        },
        {
            'name': 'X-Content-Type-Options',
            'description': 'Блокировка MIME-sniffing',
            'critical': False,
            'category': 'privacy',
            'analyzer': _analyze_content_type_options
        },
        {
            'name': 'Referrer-Policy',
            'description': 'Контроль утечки referrer данных',
            'critical': False,
            'category': 'privacy',
            'analyzer': _analyze_referrer_policy
        },
        {
            'name': 'Permissions-Policy',
            'description': 'Управление доступом к API браузера',
            'critical': False,
            'category': 'privacy',
            'analyzer': _analyze_permissions_policy
        },
        {
            'name': 'Access-Control-Allow-Origin',
            'description': 'CORS политика - разрешенные домены',
            'critical': False,
            'category': 'cors',
            'analyzer': _analyze_cors_origin
        },
        {
            'name': 'Access-Control-Allow-Methods',
            'description': 'CORS разрешенные методы',
            'critical': False,
            'category': 'cors',
            'analyzer': _analyze_cors_methods
        },
        {
            'name': 'Access-Control-Allow-Headers',
            'description': 'CORS разрешенные заголовки',
            'critical': False,
            'category': 'cors',
            'analyzer': _analyze_cors_headers
        },
        {
            'name': 'Access-Control-Allow-Credentials',
            'description': 'CORS передача учетных данных',
            'critical': True,  # Изменено на критический
            'category': 'cors',
            'analyzer': _analyze_cors_credentials
        },
        {
            'name': 'X-XSS-Protection',
            'description': 'Защита от XSS (устаревшая)',
            'critical': False,
            'category': 'privacy',
            'analyzer': _analyze_xss_protection
        }
    ]

    analyzed_headers = []
    all_issues = []

    # Анализируем каждый заголовок
    for header_def in security_headers:
        header_name = header_def['name']
        header_value = headers.get(header_name)

        # Анализ конкретного заголовка
        analysis = header_def['analyzer'](header_value, headers)

        analyzed_headers.append({
            'name': header_name,
            'present': header_value is not None,
            'value': header_value,
            'risk': analysis['risk'],
            'description': header_def['description'],
            'critical': header_def['critical'],
            'category': header_def['category'],
            'warnings': analysis['warnings'],
            'recommendations': analysis['recommendations']
        })

        # Добавляем проблемы в общий список
        all_issues.extend(analysis['issues'])

    # Комплексный анализ CORS политики
    cors_issues = _analyze_cors_comprehensive(headers)
    all_issues.extend(cors_issues)

    # Добавляем общие проблемы на основе отсутствующих критических заголовков
    missing_critical = [h for h in analyzed_headers if h['critical'] and not h['present']]
    if missing_critical:
        critical_names = [h['name'] for h in missing_critical]
        if len(missing_critical) >= 2:
            all_issues.append(f"🚨 КРИТИЧЕСКО: Отсутствуют важные заголовки безопасности: {', '.join(critical_names)}")
        else:
            for header in missing_critical:
                all_issues.append(f"❌ КРИТИЧЕСКИЙ: Отсутствует {header['name']} - {header['description']}")

    # Добавляем предупреждение если оценка низкая
    security_score = _calculate_security_score(analyzed_headers)
    if security_score < 60:
        present_count = sum(1 for h in analyzed_headers if h['present'])
        all_issues.append(f"⚠️ НИЗКАЯ ОЦЕНКА: Настроено только {present_count}/{len(analyzed_headers)} заголовков")

    return analyzed_headers, all_issues, security_score


def _analyze_csp(value: Optional[str], all_headers: Dict) -> Dict:
    """Анализ Content-Security-Policy"""
    issues = []
    warnings = []
    recommendations = []
    risk = "Низкий"

    if not value:
        issues.append("❌ CSP отсутствует — сайт уязвим к XSS атакам")
        risk = "Высокий"
        return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}

    # Проверка опасных директив
    if "'unsafe-inline'" in value:
        warnings.append("⚠️ CSP содержит 'unsafe-inline' - снижает безопасность")
        risk = "Средний"

    if "'unsafe-eval'" in value:
        warnings.append("⚠️ CSP содержит 'unsafe-eval' - потенциально опасно")
        risk = "Средний"

    if "default-src *" in value or "default-src 'none'" not in value:
        if "default-src 'self'" not in value and "default-src https:" not in value:
            warnings.append("⚠️ CSP default-src слишком разрешительный")

    # Проверка отсутствия важных директив
    if "script-src" not in value:
        warnings.append("ℹ️ CSP не определяет script-src политику")

    if "style-src" not in value:
        warnings.append("ℹ️ CSP не определяет style-src политику")

    recommendations.append("✅ CSP настроен правильно")

    return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}


def _analyze_hsts(value: Optional[str], all_headers: Dict) -> Dict:
    """Анализ Strict-Transport-Security"""
    issues = []
    warnings = []
    recommendations = []
    risk = "Низкий"

    if not value:
        issues.append("❌ HSTS отсутствует — возможны downgrade атаки на HTTPS")
        risk = "Высокий"
        return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}

    # Парсим значение HSTS
    max_age_match = re.search(r'max-age=(\d+)', value)
    includes_subdomains = 'includeSubDomains' in value
    preload = 'preload' in value

    if not max_age_match:
        issues.append("❌ HSTS имеет неверный формат - отсутствует max-age")
        risk = "Высокий"
        return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}

    max_age = int(max_age_match.group(1))

    if max_age < 300:  # 5 минут
        issues.append("❌ HSTS max-age слишком мал (меньше 5 минут)")
        risk = "Высокий"
    elif max_age < 31536000:  # 1 год
        warnings.append("⚠️ HSTS max-age менее года - рекомендуется 31536000")
        risk = "Средний"

    if preload and not includes_subdomains:
        issues.append("❌ HSTS preload требует includeSubDomains директиву")
        risk = "Высокий"

    if includes_subdomains:
        recommendations.append("✅ HSTS включает поддомены")

    if preload:
        recommendations.append("✅ HSTS настроен для preload списка")

    recommendations.append("✅ HSTS правильно настроен")

    return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}


def _analyze_x_frame_options(value: Optional[str], all_headers: Dict) -> Dict:
    """Анализ X-Frame-Options"""
    issues = []
    warnings = []
    recommendations = []
    risk = "Низкий"

    if not value:
        issues.append("❌ X-Frame-Options отсутствует — риск clickjacking атак")
        risk = "Высокий"
        return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}

    valid_values = ['DENY', 'SAMEORIGIN']
    if value.upper() not in valid_values:
        issues.append(f"❌ X-Frame-Options имеет недопустимое значение: {value}")
        risk = "Высокий"
    else:
        recommendations.append(f"✅ X-Frame-Options правильно настроен: {value}")

    return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}


def _analyze_content_type_options(value: Optional[str], all_headers: Dict) -> Dict:
    """Анализ X-Content-Type-Options"""
    issues = []
    warnings = []
    recommendations = []
    risk = "Низкий"

    if not value:
        issues.append("❌ X-Content-Type-Options отсутствует — возможен MIME-sniffing")
        risk = "Средний"
        return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}

    if value.lower() != 'nosniff':
        issues.append(f"❌ X-Content-Type-Options имеет неверное значение: {value}")
        risk = "Средний"
    else:
        recommendations.append("✅ X-Content-Type-Options правильно настроен")

    return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}


def _analyze_referrer_policy(value: Optional[str], all_headers: Dict) -> Dict:
    """Анализ Referrer-Policy"""
    issues = []
    warnings = []
    recommendations = []
    risk = "Низкий"

    if not value:
        warnings.append("⚠️ Referrer-Policy отсутствует — возможна утечка referrer данных")
        risk = "Низкий"
        return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}

    valid_policies = [
        'no-referrer', 'no-referrer-when-downgrade', 'origin',
        'origin-when-cross-origin', 'same-origin', 'strict-origin',
        'strict-origin-when-cross-origin', 'unsafe-url'
    ]

    if value not in valid_policies:
        warnings.append(f"⚠️ Referrer-Policy имеет нестандартное значение: {value}")
    else:
        recommendations.append(f"✅ Referrer-Policy настроен: {value}")

    return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}


def _analyze_permissions_policy(value: Optional[str], all_headers: Dict) -> Dict:
    """Анализ Permissions-Policy"""
    issues = []
    warnings = []
    recommendations = []
    risk = "Низкий"

    if not value:
        warnings.append("⚠️ Permissions-Policy отсутствует — ограничение доступа к API устройств не настроено")
        return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}

    # Проверяем наличие ограничений для опасных features
    dangerous_features = ['camera', 'microphone', 'geolocation', 'payment']
    for feature in dangerous_features:
        if f"{feature}=*" in value or f"{feature}=()" not in value:
            warnings.append(f"⚠️ Permissions-Policy: {feature} может быть доступен всем сайтам")

    recommendations.append("✅ Permissions-Policy настроен")

    return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}


def _analyze_cors_origin(value: Optional[str], all_headers: Dict) -> Dict:
    """Анализ Access-Control-Allow-Origin"""
    issues = []
    warnings = []
    recommendations = []
    risk = "Низкий"

    if not value:
        # Проверяем, есть ли другие CORS заголовки
        cors_headers_present = any(
            h for h in ['Access-Control-Allow-Methods', 'Access-Control-Allow-Headers',
                        'Access-Control-Allow-Credentials']
            if h in all_headers
        )
        if cors_headers_present:
            warnings.append("⚠️ Настроены CORS заголовки, но отсутствует Access-Control-Allow-Origin")
        return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}

    if value == "*":
        warnings.append("⚠️ CORS открыт для всех доменов (Access-Control-Allow-Origin: *)")
        risk = "Средний"
    else:
        recommendations.append(f"✅ CORS ограничен конкретным доменом: {value}")

    return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}


def _analyze_cors_methods(value: Optional[str], all_headers: Dict) -> Dict:
    """Анализ Access-Control-Allow-Methods"""
    issues = []
    warnings = []
    recommendations = []
    risk = "Низкий"

    if not value:
        # Не критично, если нет CORS запросов
        return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}

    dangerous_methods = ['DELETE', 'PUT', 'PATCH']
    origin = all_headers.get('Access-Control-Allow-Origin')

    if origin == "*":
        for method in dangerous_methods:
            if method in value:
                warnings.append(f"⚠️ Опасный метод {method} доступен для всех доменов")
                risk = "Средний"

    if value:
        recommendations.append(f"✅ CORS методы настроены: {value}")

    return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}


def _analyze_cors_headers(value: Optional[str], all_headers: Dict) -> Dict:
    """Анализ Access-Control-Allow-Headers"""
    issues = []
    warnings = []
    recommendations = []
    risk = "Низкий"

    if not value:
        return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}

    sensitive_headers = ['authorization', 'cookie', 'proxy-authorization']
    origin = all_headers.get('Access-Control-Allow-Origin')

    if origin == "*":
        for header in sensitive_headers:
            if header in value.lower():
                warnings.append(f"⚠️ Чувствительный заголовок {header} разрешен для всех доменов")
                risk = "Средний"

    if value:
        recommendations.append(f"✅ CORS заголовки настроены: {value}")

    return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}


def _analyze_cors_credentials(value: Optional[str], all_headers: Dict) -> Dict:
    """Анализ Access-Control-Allow-Credentials"""
    issues = []
    warnings = []
    recommendations = []
    risk = "Низкий"

    if not value:
        return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}

    origin = all_headers.get('Access-Control-Allow-Origin')

    if value.lower() == "true" and origin == "*":
        issues.append("🚨 КРИТИЧЕСКО: CORS credentials=true несовместимо с origin=* - браузер заблокирует запрос!")
        risk = "Высокий"
    elif value.lower() == "true":
        warnings.append("⚠️ CORS разрешена передача учетных данных")
        risk = "Средний"
    else:
        recommendations.append("✅ CORS credentials правильно настроен")

    return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}


def _analyze_xss_protection(value: Optional[str], all_headers: Dict) -> Dict:
    """Анализ X-XSS-Protection"""
    issues = []
    warnings = []
    recommendations = []
    risk = "Низкий"

    if not value:
        warnings.append("ℹ️ X-XSS-Protection отсутствует (устаревший заголовок)")
        return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}

    if "1; mode=block" not in value:
        warnings.append("⚠️ X-XSS-Protection не включает mode=block")

    recommendations.append("✅ X-XSS-Protection настроен (используйте CSP для современной защиты)")

    return {'risk': risk, 'issues': issues, 'warnings': warnings, 'recommendations': recommendations}


def _analyze_cors_comprehensive(headers: Dict[str, Optional[str]]) -> List[str]:
    """Комплексный анализ CORS политики"""
    issues = []

    origin = headers.get('Access-Control-Allow-Origin')
    credentials = headers.get('Access-Control-Allow-Credentials')
    methods = headers.get('Access-Control-Allow-Methods')

    # Проверка опасных комбинаций
    if origin == "*" and credentials and credentials.lower() == "true":
        issues.append("🚨 КРИТИЧЕСКО: Несовместимая CORS политика - credentials=true с origin=*")

    # Проверка избыточных разрешений
    if origin == "*" and methods and any(method in methods for method in ['DELETE', 'PUT', 'PATCH']):
        issues.append("⚠️ Опасные HTTP методы (DELETE/PUT/PATCH) доступны для всех доменов")

    # Проверка отсутствия CORS при наличии других CORS заголовков
    cors_headers = [h for h in headers if h.startswith('Access-Control-')]
    if len(cors_headers) > 0 and not origin:
        issues.append("⚠️ Настроены CORS заголовки, но отсутствует Access-Control-Allow-Origin")

    return issues


def _calculate_security_score(analyzed_headers: List[Dict]) -> int:
    """Рассчитывает общую оценку безопасности (0-100)"""

    if not analyzed_headers:
        return 0

    total_weight = 0
    weighted_score = 0.0  # Используем float для точных расчетов

    for header in analyzed_headers:
        # Вес заголовка: критические = 3, обычные = 1
        weight = 3 if header['critical'] else 1

        # Очки за заголовок: присутствует = 1, отсутствует = 0
        header_score = 1.0 if header['present'] else 0.0

        if header['present']:
            # Штраф за предупреждения: -0.5 за каждое (макс -0.5)
            warning_penalty = min(0.5 * len(header['warnings']), 0.5)
            # Штраф за проблемы: -1 за каждую (макс -1.0)
            issue_penalty = min(1.0 * len([i for i in header['issues'] if not i.startswith('✅')]), 1.0)

            header_score = max(0.0, header_score - warning_penalty - issue_penalty)

        total_weight += weight
        weighted_score += header_score * weight

    if total_weight == 0:
        return 0

    final_score = int((weighted_score / total_weight) * 100)
    return min(100, max(0, final_score))


# Функции для обратной совместимости

def analyze(headers: Dict[str, Optional[str]]) -> List[str]:
    """
    Старая функция для обратной совместимости.
    Возвращает только список проблем.
    """
    _, issues, _ = analyze_security_headers(headers)
    return issues


def get_security_headers_analysis(headers: Dict[str, Optional[str]]) -> Dict[str, any]:
    """
    Расширенный анализ для использования в новых компонентах.

    Returns:
        Dict с полным анализом безопасности
    """
    analyzed_headers, issues, score = analyze_security_headers(headers)

    # Подготовка данных для шаблонов
    critical_missing = []
    cors_missing = []
    privacy_missing = []
    present_headers_names = []

    for header in analyzed_headers:
        if header['present']:
            present_headers_names.append(header['name'])
        else:
            if header['critical'] and 'CORS' not in header['name'] and 'Access-Control' not in header['name']:
                critical_missing.append(header['name'])
            elif 'CORS' in header['name'] or 'Access-Control' in header['name']:
                cors_missing.append(header['name'])
            else:
                privacy_missing.append(header['name'])

    # Подсчитываем заголовки по категориям
    security_headers = [h for h in analyzed_headers if h['category'] == 'security']
    cors_headers = [h for h in analyzed_headers if h['category'] == 'cors']
    privacy_headers = [h for h in analyzed_headers if h['category'] == 'privacy']

    return {
        'headers': analyzed_headers,
        'issues': issues,
        'security_score': score,
        'total_headers': len(analyzed_headers),
        'present_headers': sum(1 for h in analyzed_headers if h['present']),
        'critical_headers_present': sum(1 for h in analyzed_headers if h['critical'] and h['present']),
        'template_data': {
            'critical_missing': critical_missing,
            'cors_missing': cors_missing,
            'privacy_missing': privacy_missing,
            'present_headers_names': present_headers_names
        },
        'categories': {
            'security': {
                'total': len(security_headers),
                'present': sum(1 for h in security_headers if h['present'])
            },
            'cors': {
                'total': len(cors_headers),
                'present': sum(1 for h in cors_headers if h['present'])
            },
            'privacy': {
                'total': len(privacy_headers),
                'present': sum(1 for h in privacy_headers if h['present'])
            }
        }
    }


# Пример использования
if __name__ == "__main__":
    # Тестовые заголовки для демонстрации
    test_headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true"
    }

    # Полный анализ
    full_analysis = get_security_headers_analysis(test_headers)

    print(f"Оценка безопасности: {full_analysis['security_score']}%")
    print(f"Заголовков: {full_analysis['present_headers']}/{full_analysis['total_headers']}")
    print("\nПроблемы:")
    for issue in full_analysis['issues']:
        print(f"  {issue}")

    print("\nДетальный анализ заголовков:")
    for header in full_analysis['headers']:
        status = "✅" if header['present'] else "❌"
        print(f"  {status} {header['name']}: {header['risk']} ({header['category']})")
        for warning in header['warnings']:
            print(f"    {warning}")
