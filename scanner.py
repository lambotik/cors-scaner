import requests
import time
from urllib.parse import urlparse
from typing import Dict, List, Any


def scan_headers(url: str) -> Dict[str, Any]:
    """
    Расширенное сканирование заголовков безопасности с улучшенной CORS проверкой
    """
    start_time = time.time()

    try:
        # Базовая информация
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
            'cors_analysis': {},  # Новый раздел для детального CORS анализа
            'redirects': False
        }

        # 1. Базовый GET запрос для основных заголовков
        print(f"🔍 Базовое сканирование: {url}")
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={'User-Agent': 'Security-Scanner/1.0'}
        )

        results['final_url'] = response.url
        results['http_status'] = response.status_code
        results['redirects'] = (url != response.url)

        # Анализ основных security headers
        security_headers = analyze_security_headers(response)
        results['headers'] = security_headers['headers']
        results['issues'] = security_headers['issues']
        results['present_headers'] = security_headers['present_headers']

        # 2. Детальный CORS анализ
        print(f"🌐 Расширенный CORS анализ: {url}")
        cors_results = analyze_cors_policy(url, response)
        results['cors_analysis'] = cors_results
        results['issues'].extend(cors_results.get('issues', []))

        # 3. Расчет итоговой оценки
        results['security_score'] = calculate_security_score(results)
        results['scan_duration'] = round(time.time() - start_time, 2)

        return results

    except requests.exceptions.RequestException as e:
        return {
            'target': url,
            'error': f"Ошибка запроса: {str(e)}",
            'security_score': 0,
            'scan_duration': round(time.time() - start_time, 2),
            'headers': [],
            'issues': [f"❌ Не удалось подключиться к сайту: {str(e)}"]
        }
    except Exception as e:
        return {
            'target': url,
            'error': f"Неожиданная ошибка: {str(e)}",
            'security_score': 0,
            'scan_duration': round(time.time() - start_time, 2),
            'headers': [],
            'issues': [f"❌ Ошибка сканирования: {str(e)}"]
        }


def analyze_cors_policy(target_url: str, base_response) -> Dict[str, Any]:
    """
    Расширенный анализ CORS политики
    """
    cors_results = {
        'simple_request': {},
        'preflight_request': {},
        'with_credentials': {},
        'wildcard_test': {},
        'issues': []
    }

    parsed_url = urlparse(target_url)
    domain = f"{parsed_url.scheme}://{parsed_url.netloc}"

    # Тестовые Origin для проверки CORS
    test_origins = [
        'https://example.com',
        'https://malicious-site.com',
        'http://localhost:3000',
        'null'
    ]

    # 1. Проверка простого CORS запроса
    print("  📤 Тестирование простого CORS запроса...")
    try:
        for origin in test_origins:
            test_response = requests.get(
                target_url,
                timeout=5,
                headers={'Origin': origin}
            )

            cors_headers = {
                'acao': test_response.headers.get('Access-Control-Allow-Origin'),
                'acam': test_response.headers.get('Access-Control-Allow-Methods'),
                'acah': test_response.headers.get('Access-Control-Allow-Headers'),
                'acac': test_response.headers.get('Access-Control-Allow-Credentials')
            }

            if any(cors_headers.values()):
                cors_results['simple_request'][origin] = cors_headers

                # Анализ безопасности
                if cors_headers['acao'] == '*':
                    cors_results['issues'].append(
                        f"⚠️ CORS открыт для всех доменов (*) с Origin: {origin}"
                    )
                elif cors_headers['acao'] == origin:
                    cors_results['issues'].append(
                        f"✅ CORS правильно настроен для Origin: {origin}"
                    )

    except Exception as e:
        cors_results['issues'].append(f"❌ Ошибка тестирования CORS: {str(e)}")

    # 2. Проверка Preflight запроса (OPTIONS)
    print("  📥 Тестирование Preflight запроса...")
    try:
        options_response = requests.options(
            target_url,
            timeout=5,
            headers={
                'Origin': 'https://example.com',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'X-Custom-Header'
            }
        )

        if options_response.status_code != 405:  # Method Not Allowed - нормально
            cors_results['preflight_request'] = {
                'status': options_response.status_code,
                'acao': options_response.headers.get('Access-Control-Allow-Origin'),
                'acam': options_response.headers.get('Access-Control-Allow-Methods'),
                'acah': options_response.headers.get('Access-Control-Allow-Headers'),
                'acac': options_response.headers.get('Access-Control-Allow-Credentials'),
                'acam_age': options_response.headers.get('Access-Control-Max-Age')
            }

            if options_response.headers.get('Access-Control-Allow-Methods'):
                cors_results['issues'].append(
                    f"✅ Preflight запрос поддерживается"
                )

    except Exception as e:
        cors_results['issues'].append(f"❌ Ошибка preflight запроса: {str(e)}")

    # 3. Проверка CORS с credentials
    print("  🔐 Тестирование CORS с учетными данными...")
    try:
        creds_response = requests.get(
            target_url,
            timeout=5,
            headers={'Origin': 'https://example.com'},
            cookies={'test': 'value'}
        )

        acac = creds_response.headers.get('Access-Control-Allow-Credentials')
        acao = creds_response.headers.get('Access-Control-Allow-Origin')

        cors_results['with_credentials'] = {
            'allow_credentials': acac,
            'allow_origin': acao
        }

        if acac == 'true' and acao == '*':
            cors_results['issues'].append(
                "🚨 ОПАСНО: CORS с credentials разрешен для всех доменов (*)"
            )
        elif acac == 'true':
            cors_results['issues'].append(
                "⚠️ CORS с credentials разрешен (проверьте настройки Origin)"
            )

    except Exception as e:
        cors_results['issues'].append(f"❌ Ошибка тестирования credentials: {str(e)}")

    # 4. Проверка на отсутствие CORS заголовков
    base_cors_headers = [
        'Access-Control-Allow-Origin',
        'Access-Control-Allow-Methods',
        'Access-Control-Allow-Headers',
        'Access-Control-Allow-Credentials'
    ]

    missing_cors = []
    for header in base_cors_headers:
        if header not in base_response.headers:
            missing_cors.append(header)

    if missing_cors:
        cors_results['issues'].append(
            f"ℹ️ Отсутствуют CORS заголовки: {', '.join(missing_cors)}"
        )

    return cors_results


def analyze_security_headers(response) -> Dict[str, Any]:
    """
    Анализ основных заголовков безопасности (существующая логика)
    """
    headers = []
    issues = []
    present_headers = 0

    security_headers_config = [
        {
            'name': 'Content-Security-Policy',
            'critical': True,
            'description': 'Защита от XSS и внедрения кода'
        },
        {
            'name': 'Strict-Transport-Security',
            'critical': True,
            'description': 'Принудительное использование HTTPS'
        },
        {
            'name': 'X-Frame-Options',
            'critical': True,
            'description': 'Защита от clickjacking'
        },
        {
            'name': 'X-Content-Type-Options',
            'critical': False,
            'description': 'Блокировка MIME-sniffing'
        },
        {
            'name': 'X-XSS-Protection',
            'critical': False,
            'description': 'Защита от XSS (устаревшая)'
        },
        {
            'name': 'Referrer-Policy',
            'critical': False,
            'description': 'Контроль утечки referrer данных'
        },
        {
            'name': 'Permissions-Policy',
            'critical': False,
            'description': 'Управление доступом к API браузера'
        },
        # CORS headers
        {
            'name': 'Access-Control-Allow-Origin',
            'critical': False,
            'description': 'CORS политика - разрешенные домены'
        },
        {
            'name': 'Access-Control-Allow-Methods',
            'critical': False,
            'description': 'CORS разрешенные методы'
        },
        {
            'name': 'Access-Control-Allow-Headers',
            'critical': False,
            'description': 'CORS разрешенные заголовки'
        },
        {
            'name': 'Access-Control-Allow-Credentials',
            'critical': False,
            'description': 'CORS передача учетных данных'
        }
    ]

    for config in security_headers_config:
        header_name = config['name']
        header_value = response.headers.get(header_name)
        is_present = header_value is not None

        if is_present:
            present_headers += 1

            # Анализ значений заголовков
            if header_name == 'Access-Control-Allow-Origin' and header_value == '*':
                issues.append("⚠️ CORS открыт для всех доменов (Access-Control-Allow-Origin: *)")
            elif header_name == 'Access-Control-Allow-Credentials' and header_value == 'true':
                issues.append("⚠️ CORS разрешает передачу учетных данных")
            elif header_name == 'Strict-Transport-Security' and 'max-age=0' in header_value:
                issues.append("⚠️ HSTS отключен (max-age=0)")

        elif config['critical']:
            issues.append(f"❌ {header_name} отсутствует — критическая уязвимость безопасности")
        else:
            issues.append(f"⚠️ {header_name} отсутствует — может потребоваться для API")

        headers.append({
            'name': header_name,
            'present': is_present,
            'value': header_value,
            'critical': config['critical'],
            'risk': 'Высокий' if config['critical'] and not is_present else 'Низкий'
        })

    return {
        'headers': headers,
        'issues': issues,
        'present_headers': present_headers
    }


def calculate_security_score(results: Dict[str, Any]) -> int:
    """
    Расчет оценки безопасности с учетом CORS анализа
    """
    base_score = 0
    max_score = 100

    # Базовые заголовки (70% оценки)
    present_headers = results.get('present_headers', 0)
    total_headers = results.get('total_headers', 11)
    base_score += (present_headers / total_headers) * 70

    # CORS безопасность (30% оценки)
    cors_issues = results.get('cors_analysis', {}).get('issues', [])
    dangerous_cors = sum(1 for issue in cors_issues if 'ОПАСНО' in issue or 'открыт для всех' in issue)

    if dangerous_cors == 0:
        base_score += 30
    elif dangerous_cors == 1:
        base_score += 15
    elif dangerous_cors == 2:
        base_score += 5

    return min(100, int(base_score))