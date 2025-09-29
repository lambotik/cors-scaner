import requests
import time
from typing import Dict, List, Tuple, Any
from urllib.parse import urlparse
from analyzer import get_security_headers_analysis


class SecurityScanner:
    """
    Сканер безопасности HTTP-заголовков с расширенными возможностями.
    """

    def __init__(self, timeout: int = 15, user_agent: str = None):
        """
        Инициализация сканера.

        Args:
            timeout (int): Таймаут запросов в секундах
            user_agent (str): Кастомный User-Agent
        """
        self.timeout = timeout
        self.user_agent = user_agent or "CORS-Security-Scanner/2.0"
        self.session = requests.Session()

        # Настройка сессии
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

    def scan_url(self, target_url: str) -> Dict[str, Any]:
        """
        Основная функция сканирования URL.

        Args:
            target_url (str): URL для сканирования

        Returns:
            Dict с результатами сканирования
        """
        start_time = time.time()

        try:
            # Нормализация URL
            normalized_url = self._normalize_url(target_url)

            # Выполняем основные запросы
            main_response = self._make_main_request(normalized_url)
            cors_response = self._make_cors_requests(normalized_url)

            # Собираем все заголовки
            all_headers = self._collect_all_headers(main_response, cors_response)

            # Анализируем заголовки
            analysis = get_security_headers_analysis(all_headers)

            # Формируем полный результат
            scan_result = self._build_result(
                normalized_url, analysis, all_headers,
                main_response, start_time
            )

            return scan_result

        except Exception as e:
            return self._build_error_result(target_url, str(e), start_time)

    def _normalize_url(self, input_url: str) -> str:
        """
        Нормализует URL, добавляя протокол если нужно.

        Args:
            input_url (str): Исходный URL

        Returns:
            str: Нормализованный URL
        """
        if not input_url.startswith(('http://', 'https://')):
            # Пробуем HTTPS сначала, потом HTTP
            try:
                test_url = f"https://{input_url}"
                response = self.session.head(test_url, timeout=5, allow_redirects=True)
                return response.url
            except (requests.RequestException, ValueError):
                try:
                    test_url = f"http://{input_url}"
                    response = self.session.head(test_url, timeout=5, allow_redirects=True)
                    return response.url
                except (requests.RequestException, ValueError):
                    return f"https://{input_url}"

        return input_url

    def _make_main_request(self, scan_url: str) -> requests.Response:
        """
        Выполняет основной GET запрос.

        Args:
            scan_url (str): URL для запроса

        Returns:
            requests.Response: Ответ сервера
        """
        try:
            response = self.session.get(
                scan_url,
                timeout=self.timeout,
                allow_redirects=True,
                stream=True  # Не загружаем тело ответа сразу
            )
            return response
        except requests.exceptions.SSLError:
            # Пробуем HTTP если HTTPS не работает
            if scan_url.startswith('https://'):
                http_url = scan_url.replace('https://', 'http://')
                return self.session.get(http_url, timeout=self.timeout, allow_redirects=True)
            raise

    def _make_cors_requests(self, cors_url: str) -> Dict[str, Any]:
        """
        Выполняет CORS-related запросы для полного анализа.

        Args:
            cors_url (str): URL для тестирования

        Returns:
            Dict с результатами CORS запросов
        """
        cors_results = {
            'options': None,
            'cors_request': None,
            'preflight': None
        }

        try:
            # OPTIONS запрос (preflight)
            options_response = self.session.options(
                cors_url,
                timeout=10,
                headers={
                    'Origin': 'https://example.com',
                    'Access-Control-Request-Method': 'GET',
                    'Access-Control-Request-Headers': 'X-Requested-With'
                }
            )
            cors_results['options'] = options_response
        except requests.RequestException:
            pass  # OPTIONS может не поддерживаться

        try:
            # CORS запрос с Origin
            cors_response = self.session.get(
                cors_url,
                timeout=10,
                headers={'Origin': 'https://example.com'}
            )
            cors_results['cors_request'] = cors_response
        except requests.RequestException:
            pass

        return cors_results

    def _collect_all_headers(self, main_response: requests.Response,
                             cors_results: Dict[str, Any]) -> Dict[str, str]:
        """
        Собирает все заголовки из различных запросов.

        Args:
            main_response: Основной GET ответ
            cors_results: Результаты CORS запросов

        Returns:
            Dict со всеми заголовками
        """
        headers = {}

        # Заголовки из основного запроса
        for key, value in main_response.headers.items():
            headers[key] = value

        # Заголовки из OPTIONS запроса (CORS preflight)
        if cors_results['options']:
            for key, value in cors_results['options'].headers.items():
                if key.startswith('Access-Control-'):
                    headers[key] = value

        # Заголовки из CORS запроса
        if cors_results['cors_request']:
            for key, value in cors_results['cors_request'].headers.items():
                if key.startswith('Access-Control-'):
                    headers[key] = value

        # Нормализуем названия заголовков (регистронезависимые)
        normalized_headers = {}
        for key, value in headers.items():
            normalized_headers[key.lower()] = value

        return self._denormalize_headers(normalized_headers)

    @staticmethod
    def _denormalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
        """
        Преобразует заголовки обратно в стандартный вид.

        Args:
            headers: Заголовки в нижнем регистре

        Returns:
            Dict с заголовками в стандартном формате
        """
        standard_headers = {}

        # Стандартные названия security headers
        header_mapping = {
            'content-security-policy': 'Content-Security-Policy',
            'strict-transport-security': 'Strict-Transport-Security',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'referrer-policy': 'Referrer-Policy',
            'permissions-policy': 'Permissions-Policy',
            'access-control-allow-origin': 'Access-Control-Allow-Origin',
            'access-control-allow-methods': 'Access-Control-Allow-Methods',
            'access-control-allow-headers': 'Access-Control-Allow-Headers',
            'access-control-allow-credentials': 'Access-Control-Allow-Credentials',
            'x-xss-protection': 'X-XSS-Protection',
            'cache-control': 'Cache-Control',
            'server': 'Server',
            'x-powered-by': 'X-Powered-By'
        }

        for lower_key, value in headers.items():
            if lower_key in header_mapping:
                standard_headers[header_mapping[lower_key]] = value
            else:
                # Для нестандартных заголовков оставляем как есть
                standard_headers[lower_key] = value

        return standard_headers

    @staticmethod
    def _build_result(scanned_url: str, analysis: Dict[str, Any],
                      collected_headers: Dict[str, str], response: requests.Response,
                      start_time: float) -> Dict[str, Any]:
        """
        Формирует полный результат сканирования.

        Args:
            scanned_url: Сканируемый URL
            analysis: Результаты анализа
            collected_headers: Собранные заголовки
            response: HTTP ответ
            start_time: Время начала сканирования

        Returns:
            Dict с полными результатами
        """
        scan_duration = round(time.time() - start_time, 2)

        final_result = {
            'target': scanned_url,
            'date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'security_score': analysis['security_score'],
            'headers': analysis['headers'],
            'issues': analysis['issues'],
            'total_headers': analysis['total_headers'],
            'present_headers': analysis['present_headers'],
            'critical_headers_present': analysis['critical_headers_present'],
            'scan_duration': scan_duration,
            'http_status': response.status_code,
            'final_url': response.url,
            'redirected': response.history != [],
            'server_info': {
                'server': response.headers.get('Server'),
                'x_powered_by': response.headers.get('X-Powered-By'),
                'content_type': response.headers.get('Content-Type')
            },
            'raw_headers': dict(response.headers),
            'error': None
        }

        return final_result

    @staticmethod
    def _build_error_result(error_url: str, error_msg: str,
                            start_time: float) -> Dict[str, Any]:
        """
        Формирует результат при ошибке сканирования.

        Args:
            error_url: Сканируемый URL
            error_msg: Сообщение об ошибке
            start_time: Время начала сканирования

        Returns:
            Dict с информацией об ошибке
        """
        scan_duration = round(time.time() - start_time, 2)

        return {
            'target': error_url,
            'date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'security_score': 0,
            'headers': [],
            'issues': [f"❌ Ошибка сканирования: {error_msg}"],
            'total_headers': 0,
            'present_headers': 0,
            'critical_headers_present': 0,
            'scan_duration': scan_duration,
            'http_status': None,
            'final_url': error_url,
            'redirected': False,
            'server_info': {},
            'raw_headers': {},
            'error': error_msg
        }

    def scan_multiple_urls(self, url_list: List[str]) -> Dict[str, Any]:
        """
        Сканирует несколько URL одновременно.

        Args:
            url_list: Список URL для сканирования

        Returns:
            Dict с результатами всех сканирований
        """
        results = {}

        for single_url in url_list:
            try:
                results[single_url] = self.scan_url(single_url)
            except Exception as e:
                results[single_url] = self._build_error_result(single_url, str(e), time.time())

        return {
            'batch_scan': True,
            'total_urls': len(url_list),
            'successful_scans': sum(1 for r in results.values() if not r['error']),
            'failed_scans': sum(1 for r in results.values() if r['error']),
            'average_score': self._calculate_average_score(results),
            'results': results
        }

    @staticmethod
    def _calculate_average_score(scan_results: Dict[str, Any]) -> float:
        """
        Рассчитывает среднюю оценку безопасности для batch сканирования.

        Args:
            scan_results: Результаты сканирования

        Returns:
            float: Средняя оценка
        """
        successful_results = [r for r in scan_results.values() if not r['error']]
        if not successful_results:
            return 0.0

        total_score = sum(r['security_score'] for r in successful_results)
        return round(total_score / len(successful_results), 1)

    def get_scan_statistics(self) -> Dict[str, Any]:
        """
        Возвращает статистику использования сканера.

        Returns:
            Dict со статистикой
        """
        return {
            'user_agent': self.user_agent,
            'timeout': self.timeout,
            'session_headers': dict(self.session.headers)
        }

    def close(self):
        """
        Закрывает сессию requests.
        """
        self.session.close()


# Функции для обратной совместимости

def scan_headers(input_url: str, timeout: int = 15) -> Dict[str, Any]:
    """
    Основная функция сканирования для обратной совместимости.

    Args:
        input_url (str): URL для сканирования
        timeout (int): Таймаут запроса

    Returns:
        Dict с результатами сканирования
    """
    scanner_instance = SecurityScanner(timeout=timeout)
    try:
        return scanner_instance.scan_url(input_url)
    finally:
        scanner_instance.close()


def quick_scan(quick_url: str) -> Dict[str, Any]:
    """
    Быстрое сканирование с минимальным таймаутом.

    Args:
        quick_url (str): URL для сканирования

    Returns:
        Dict с базовыми результатами
    """
    quick_scanner = SecurityScanner(timeout=5)
    try:
        return quick_scanner.scan_url(quick_url)
    finally:
        quick_scanner.close()


def scan_with_details(detailed_url: str, include_body: bool = False) -> Dict[str, Any]:
    """
    Расширенное сканирование с дополнительной информацией.

    Args:
        detailed_url (str): URL для сканирования
        include_body (bool): Включать ли тело ответа

    Returns:
        Dict с детальными результатами
    """
    detailed_scanner = SecurityScanner(timeout=20)
    try:
        detailed_result = detailed_scanner.scan_url(detailed_url)

        if include_body and not detailed_result['error']:
            try:
                response = detailed_scanner.session.get(detailed_url, timeout=10)
                detailed_result['content_length'] = len(response.content)
                detailed_result['encoding'] = response.encoding
                # Не сохраняем полное тело из соображений производительности
            except requests.RequestException:
                pass

        return detailed_result
    finally:
        detailed_scanner.close()


# Вспомогательные функции

def validate_url(check_url: str) -> Tuple[bool, str]:
    """
    Валидирует URL и возвращает результат с сообщением.

    Args:
        check_url (str): URL для валидации

    Returns:
        Tuple[bool, str]: (валиден, сообщение)
    """
    if not check_url or not isinstance(check_url, str):
        return False, "URL должен быть строкой"

    if len(check_url) > 2000:
        return False, "URL слишком длинный"

    try:
        parsed = urlparse(check_url)
        if not parsed.scheme or parsed.scheme not in ['http', 'https']:
            return False, "URL должен использовать http или https протокол"

        if not parsed.netloc:
            return False, "URL должен содержать домен"

        return True, "URL валиден"
    except Exception as e:
        return False, f"Ошибка парсинга URL: {str(e)}"


def get_supported_headers() -> List[Dict[str, str]]:
    """
    Возвращает список поддерживаемых security headers.

    Returns:
        List с информацией о заголовках
    """
    return [
        {
            'name': 'Content-Security-Policy',
            'description': 'Защита от XSS и внедрения кода',
            'critical': True,
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
        },
        {
            'name': 'Strict-Transport-Security',
            'description': 'Принудительное использование HTTPS',
            'critical': True,
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
        },
        {
            'name': 'X-Frame-Options',
            'description': 'Защита от clickjacking',
            'critical': True,
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
        },
        {
            'name': 'X-Content-Type-Options',
            'description': 'Блокировка MIME-sniffing',
            'critical': False,
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'
        },
        {
            'name': 'Referrer-Policy',
            'description': 'Контроль утечки referrer данных',
            'critical': False,
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'
        },
        {
            'name': 'Permissions-Policy',
            'description': 'Управление доступом к API браузера',
            'critical': False,
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'
        },
        {
            'name': 'Access-Control-Allow-Origin',
            'description': 'CORS политика - разрешенные домены',
            'critical': True,
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin'
        },
        {
            'name': 'Access-Control-Allow-Methods',
            'description': 'CORS разрешенные методы',
            'critical': False,
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods'
        },
        {
            'name': 'Access-Control-Allow-Headers',
            'description': 'CORS разрешенные заголовки',
            'critical': False,
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers'
        },
        {
            'name': 'Access-Control-Allow-Credentials',
            'description': 'CORS передача учетных данных',
            'critical': True,
            'reference': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials'
        }
    ]


# Пример использования
if __name__ == "__main__":
    # Демонстрация работы сканера
    test_urls = [
        "https://google.com",
        "https://github.com"
    ]

    print("🔍 Демонстрация работы CORS Security Scanner")
    print("=" * 50)

    demo_scanner = SecurityScanner(timeout=10)

    try:
        for test_url in test_urls:
            print(f"\nСканируем: {test_url}")
            demo_result = demo_scanner.scan_url(test_url)

            if demo_result['error']:
                print(f"❌ Ошибка: {demo_result['error']}")
            else:
                print(f"✅ Статус: {demo_result['http_status']}")
                print(f"🛡️  Оценка безопасности: {demo_result['security_score']}%")
                print(f"📊 Заголовков: {demo_result['present_headers']}/{demo_result['total_headers']}")
                print(f"⏱️  Время сканирования: {demo_result['scan_duration']}с")

                if demo_result['issues']:
                    print("\n⚠️  Обнаруженные проблемы:")
                    for issue in demo_result['issues'][:3]:  # Показываем первые 3
                        print(f"   {issue}")
                else:
                    print("🎉 Проблем не обнаружено!")

    finally:
        demo_scanner.close()

    print("\n" + "=" * 50)
    print("📋 Поддерживаемые заголовки безопасности:")
    headers_info = get_supported_headers()
    for header in headers_info:
        critical = "🔴" if header['critical'] else "🟡"
        print(f"   {critical} {header['name']}: {header['description']}")