import requests
import time
from urllib.parse import urlparse
from typing import Dict, List, Any


def scan_headers(url: str) -> Dict[str, Any]:
    """
    Улучшенное сканирование заголовков безопасности с детальным анализом
    """
    start_time = time.time()

    try:
        results = {
            'target': url,
            'final_url': url,
            'security_score': 0,
            'scan_duration': 0,
            'http_status': 0,
            'present_headers': 0,
            'total_headers': 11,
            'headers': [],
            'issues': [],
            'recommendations': [],
            'risk_level': 'Низкий',
            'cors_analysis': {},
            'redirects': False,
            'server_info': '',
            'scan_details': {}
        }

        # 1. Базовый запрос с анализом редиректов и сервера
        print(f"🔍 Сканирование: {url}")
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={'User-Agent': 'Security-Scanner/2.0'}
        )

        results['final_url'] = response.url
        results['http_status'] = response.status_code
        results['redirects'] = (url != response.url)
        results['server_info'] = response.headers.get('Server', 'Не указан')

        # 2. Детальный анализ security headers
        security_analysis = analyze_security_headers(response)
        results['headers'] = security_analysis['headers']
        results['issues'] = security_analysis['issues']
        results['recommendations'] = security_analysis['recommendations']
        results['present_headers'] = security_analysis['present_headers']

        # 3. Углубленный CORS анализ
        cors_results = analyze_cors_policy(url, response)
        results['cors_analysis'] = cors_results
        results['issues'].extend(cors_results.get('issues', []))
        results['recommendations'].extend(cors_results.get('recommendations', []))

        # 4. Расчет итоговых показателей
        final_scores = calculate_security_metrics(results)
        results['security_score'] = final_scores['score']
        results['risk_level'] = final_scores['risk_level']
        results['scan_duration'] = round(time.time() - start_time, 2)
        results['scan_details'] = final_scores['details']

        return results

    except requests.exceptions.RequestException as e:
        return create_error_response(url, start_time, f"Ошибка подключения: {str(e)}")
    except Exception as e:
        return create_error_response(url, start_time, f"Ошибка сканирования: {str(e)}")


def analyze_security_headers(response) -> Dict[str, Any]:
    """
    Детальный анализ каждого заголовка безопасности
    """
    headers = []
    global_issues = []
    global_recommendations = []
    present_headers = 0

    # Конфигурация заголовков ТОЛЬКО с описаниями
    headers_config = [
        {
            'name': 'Content-Security-Policy',
            'critical': True,
            'description': 'Защита от XSS и внедрения кода',
            'risk_description': 'Без CSP сайт уязвим к внедрению вредоносных скриптов и XSS атакам'
        },
        {
            'name': 'Strict-Transport-Security',
            'critical': True,
            'description': 'Принудительное использование HTTPS',
            'risk_description': 'Без HSTS возможны downgrade атаки и перехват трафика'
        },
        {
            'name': 'X-Frame-Options',
            'critical': True,
            'description': 'Защита от clickjacking',
            'risk_description': 'Без защиты сайт можно встроить в iframe для обманных действий'
        },
        {
            'name': 'X-Content-Type-Options',
            'critical': True,
            'description': 'Блокировка MIME-sniffing',
            'risk_description': 'Браузер может неправильно определить тип контента, что приведет к уязвимостям'
        },
        {
            'name': 'Referrer-Policy',
            'critical': False,
            'description': 'Контроль утечки referrer данных',
            'risk_description': 'Может привести к утечке чувствительных данных в URL'
        },
        {
            'name': 'Permissions-Policy',
            'critical': False,
            'description': 'Управление доступом к API браузера',
            'risk_description': 'Сайт может получить доступ к камере, микрофону без согласия пользователя'
        },
        {
            'name': 'Access-Control-Allow-Origin',
            'critical': False,
            'description': 'CORS политика - разрешенные домены',
            'risk_description': 'Неправильная настройка может открыть API для любых доменов'
        },
        {
            'name': 'Access-Control-Allow-Methods',
            'critical': False,
            'description': 'CORS разрешенные методы',
            'risk_description': 'Разрешение опасных методов (PUT, DELETE) может привести к уязвимостям'
        },
        {
            'name': 'Access-Control-Allow-Headers',
            'critical': False,
            'description': 'CORS разрешенные заголовки',
            'risk_description': 'Избыточные разрешения могут обойти защиту'
        },
        {
            'name': 'Access-Control-Allow-Credentials',
            'critical': False,
            'description': 'CORS передача учетных данных',
            'risk_description': 'В сочетании с ACAO: * создает критическую уязвимость'
        },
        {
            'name': 'X-XSS-Protection',
            'critical': False,
            'description': 'Защита от XSS (устаревшая)',
            'risk_description': 'Устаревшая защита, не эффективна в современных браузерах'
        }
    ]

    for config in headers_config:
        header_name = config['name']
        header_value = response.headers.get(header_name)
        is_present = header_value is not None

        # Анализ качества настройки (ТОЛЬКО анализ, без рекомендаций)
        analysis = analyze_header_quality(header_name, header_value, is_present)

        # Формируем данные заголовка
        header_data = {
            'name': header_name,
            'present': is_present,
            'value': header_value,
            'critical': config['critical'],
            'description': config['description'],
            'risk_description': config['risk_description'],
            'risk_level': analysis['risk_level'],
            'quality_score': analysis['quality_score'],
            'notes': analysis['notes']  # Только заметки, без рекомендаций
        }

        headers.append(header_data)

        # Глобальные проблемы и рекомендации (только если заголовок отсутствует)
        if not is_present:
            if config['critical']:
                global_issues.append(f"❌ {header_name} отсутствует — {config['risk_description']}")
                global_recommendations.append(generate_header_recommendation(header_name))
            else:
                global_issues.append(f"⚠️ {header_name} отсутствует — {config['risk_description']}")

    return {
        'headers': headers,
        'issues': global_issues,
        'recommendations': global_recommendations,
        'present_headers': present_headers
    }


def analyze_header_quality(header_name: str, value: str, is_present: bool) -> Dict[str, Any]:
    """
    Анализ качества настройки заголовка (ТОЛЬКО анализ, без рекомендаций)
    """
    analysis = {
        'risk_level': 'Низкий',
        'quality_score': 100 if is_present else 0,
        'notes': []
    }

    if not is_present:
        analysis['risk_level'] = 'Высокий' if header_name in ['Content-Security-Policy', 'Strict-Transport-Security',
                                                              'X-Frame-Options'] else 'Средний'
        return analysis

    # Анализ качества для присутствующих заголовков
    if header_name == 'Content-Security-Policy':
        if 'unsafe-inline' in value:
            analysis['risk_level'] = 'Средний'
            analysis['quality_score'] = 60
            analysis['notes'].append('CSP содержит unsafe-inline - снижает безопасность')
        if 'unsafe-eval' in value:
            analysis['risk_level'] = 'Средний'
            analysis['quality_score'] = max(analysis['quality_score'] - 20, 0)
            analysis['notes'].append('CSP содержит unsafe-eval - потенциально опасно')
        if "'self'" in value and not any(x in value for x in ['unsafe-inline', 'unsafe-eval', '*']):
            analysis['notes'].append('CSP правильно ограничивает источники')

    elif header_name == 'Strict-Transport-Security':
        if 'max-age=31536000' in value:
            analysis['notes'].append('HSTS настроен на год - отлично')
        if 'includeSubDomains' in value:
            analysis['notes'].append('HSTS включает поддомены - правильно')
        else:
            analysis['risk_level'] = 'Средний'
            analysis['notes'].append('HSTS не включает поддомены')

    elif header_name == 'X-Frame-Options':
        if value == 'DENY':
            analysis['notes'].append('Полная защита от clickjacking')
        elif value == 'SAMEORIGIN':
            analysis['risk_level'] = 'Низкий'
            analysis['notes'].append('Частичная защита - разрешено встраивание с того же origin')

    elif header_name == 'Access-Control-Allow-Origin':
        if value == '*':
            analysis['risk_level'] = 'Высокий'
            analysis['quality_score'] = 30
            analysis['notes'].append('CORS открыт для всех доменов - критическая уязвимость')
        elif value and value != '*':
            analysis['notes'].append('CORS ограничен конкретными доменами - безопасно')

    elif header_name == 'Access-Control-Allow-Credentials':
        if value == 'true':
            analysis['risk_level'] = 'Высокий'
            analysis['notes'].append('CORS разрешает передачу учетных данных')

    elif header_name == 'Permissions-Policy':
        if not any(feature in value for feature in ['camera', 'microphone', 'geolocation']):
            analysis['notes'].append('Базовые ограничения настроены')
        elif 'camera=()' in value and 'microphone=()' in value and 'geolocation=()' in value:
            analysis['notes'].append('Доступ к чувствительным API правильно ограничен')
        else:
            analysis['risk_level'] = 'Средний'
            analysis['notes'].append('Рекомендуется ограничить доступ к чувствительным API')

    return analysis


def generate_header_recommendation(header_name: str) -> str:
    """
    Генерация рекомендаций ТОЛЬКО для отсутствующих заголовков
    """
    recommendations = {
        'Content-Security-Policy': 'Настройте Content-Security-Policy для защиты от XSS атак',
        'Strict-Transport-Security': 'Добавьте HSTS для принудительного использования HTTPS',
        'X-Frame-Options': 'Настройте X-Frame-Options: DENY для защиты от clickjacking',
        'X-Content-Type-Options': 'Добавьте X-Content-Type-Options: nosniff',
        'Referrer-Policy': 'Настройте Referrer-Policy для контроля утечки данных',
        'Permissions-Policy': 'Ограничьте доступ к API: camera=(), microphone=(), geolocation=()',
        'Access-Control-Allow-Origin': 'Настройте CORS политику для API если необходимо',
        'Access-Control-Allow-Methods': 'Ограничьте разрешенные CORS методы',
        'Access-Control-Allow-Headers': 'Ограничьте разрешенные CORS заголовки',
        'Access-Control-Allow-Credentials': 'Настройте CORS credentials если необходимо',
        'X-XSS-Protection': 'Замените на Content-Security-Policy для современной защиты'
    }

    return f"💡 {recommendations.get(header_name, f'Настройте {header_name}')}"


def analyze_cors_policy(target_url: str, base_response) -> Dict[str, Any]:
    """
    Расширенный анализ CORS политики
    """
    cors_results = {
        'simple_request': {},
        'preflight_request': {},
        'with_credentials': {},
        'security_level': 'Высокий',
        'issues': [],
        'recommendations': []
    }

    # Анализ базовых CORS заголовков
    acao = base_response.headers.get('Access-Control-Allow-Origin')
    acac = base_response.headers.get('Access-Control-Allow-Credentials')

    if acao == '*':
        cors_results['security_level'] = 'Критический'
        cors_results['issues'].append('🚨 CORS открыт для всех доменов (*)')
        cors_results['recommendations'].append('🔒 Немедленно ограничьте CORS конкретными доменами')
    elif acao and acac == 'true':
        cors_results['security_level'] = 'Высокий'
        cors_results['issues'].append('⚠️ CORS с учетными данными разрешен')
        cors_results['recommendations'].append('🔐 Убедитесь в строгой проверке Origin на сервере')
    elif acao:
        cors_results['security_level'] = 'Низкий'
        cors_results['recommendations'].append('✅ CORS правильно настроен')

    return cors_results


def calculate_security_metrics(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Расчет комплексных метрик безопасности
    """
    total_score = 0
    max_score = 100

    # 1. Базовые заголовки (50%)
    present_headers = results.get('present_headers', 0)
    total_headers = results.get('total_headers', 11)
    base_score = (present_headers / total_headers) * 50

    # 2. Качество настройки (30%)
    quality_score = 0
    for header in results.get('headers', []):
        quality_score += header.get('quality_score', 0)
    quality_score = (quality_score / len(results.get('headers', [1]))) * 0.3

    # 3. Критические заголовки (20%)
    critical_headers = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options']
    critical_present = sum(1 for h in results.get('headers', []) if h['name'] in critical_headers and h['present'])
    critical_score = (critical_present / 3) * 20

    total_score = base_score + quality_score + critical_score

    # Определение уровня риска
    if total_score >= 80:
        risk_level = 'Низкий'
    elif total_score >= 60:
        risk_level = 'Средний'
    elif total_score >= 40:
        risk_level = 'Высокий'
    else:
        risk_level = 'Критический'

    return {
        'score': min(100, int(total_score)),
        'risk_level': risk_level,
        'details': {
            'base_headers_score': int(base_score),
            'quality_score': int(quality_score),
            'critical_headers_score': int(critical_score),
            'critical_headers_present': f"{critical_present}/3"
        }
    }


def create_error_response(url: str, start_time: float, error_msg: str) -> Dict[str, Any]:
    """Создание ответа при ошибке"""
    return {
        'target': url,
        'error': error_msg,
        'security_score': 0,
        'risk_level': 'Неизвестен',
        'scan_duration': round(time.time() - start_time, 2),
        'headers': [],
        'issues': [f"❌ {error_msg}"],
        'recommendations': ['🔧 Проверьте доступность сайта и повторите сканирование']
    }