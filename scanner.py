import requests
from datetime import datetime
from requests.structures import CaseInsensitiveDict
from typing import Dict, Any, Optional


def scan_headers(url: str) -> Dict[str, Any]:
    """
    Выполняет сканирование HTTP-заголовков безопасности целевого URL.
    Проверяет наличие критически важных security-заголовков, анализирует их значения
    и вычисляет общий показатель безопасности веб-приложения.
    Args:
        url (str): URL веб-сайта для сканирования. Может быть с http/https или без.
    Returns:
        Dict[str, Any]: Результаты сканирования со следующей структурой:
            - target (str): Исходный URL
            - date (str): Дата и время сканирования
            - headers (List[Dict]): Список проверенных заголовков
            - issues (List[str]): Список выявленных проблем
            - security_score (int): Оценка безопасности в процентах (0-100)
            - total_headers (int): Общее количество проверяемых заголовков
            - error (bool): Флаг наличия ошибки при сканировании
    Raises:
        Не выбрасывает исключения напрямую - все ошибки обрабатываются внутри функции
        и возвращаются в поле 'error' результата.
    Example:
        >>> results = scan_headers("https://example.com")
        >>> print(results["security_score"])
        75
        >>> print(results["issues"])
        ["❌ X-Frame-Options отсутствует — Clickjacking"]
    """
    print(f"🎯 Начинаем сканирование: {url}")

    # Инициализация структуры результатов
    result: Dict[str, Any] = {
        "target": url,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "headers": [],
        "issues": [],
        "security_score": 0,
        "total_headers": 8,
        "error": False
    }

    try:
        print("🔗 Выполняем HTTP запрос...")

        # Эмулируем заголовки реального браузера для обхода базовой защиты
        headers: Dict[str, str] = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }

        # Выполняем HTTP GET запрос с настройками для production использования
        response: requests.Response = requests.get(
            url,
            timeout=15,  # Таймаут для избежания зависаний
            headers=headers,  # Реалистичные заголовки браузера
            allow_redirects=True,  # Следовать перенаправлениям
            verify=True  # Проверять SSL сертификаты
        )

        # Используем case-insensitive словарь для корректной обработки регистра заголовков
        response_headers: CaseInsensitiveDict = CaseInsensitiveDict(response.headers)

        print(f"✅ Ответ получен, статус: {response.status_code}")
        print(f"📨 Полученные заголовки: {list(response_headers.keys())}")

        # Словарь проверяемых security-заголовков и связанных с ними рисков
        headers_to_check: Dict[str, str] = {
            "Content-Security-Policy": "Уязвимость к XSS",
            "Strict-Transport-Security": "Downgrade-атаки через HTTP",
            "X-Frame-Options": "Clickjacking",
            "X-Content-Type-Options": "MIME-sniffing",
            "Referrer-Policy": "Утечка реферера",
            "Permissions-Policy": "Доступ к функциям браузera",
            "X-XSS-Protection": "Защита от XSS",
            "Cache-Control": "Кеширование чувствительных данных"
        }

        found_count: int = 0
        # Проверяем каждый security-заголовок из нашего списка
        for header, risk in headers_to_check.items():
            present: bool = header in response_headers
            header_value: Optional[str] = response_headers.get(header)
            # Добавляем информацию о заголовке в результаты
            result["headers"].append({
                "name": header,
                "present": present,
                "value": header_value,
                "risk": risk
            })
            if present:
                found_count += 1
                print(f"✅ Найден заголовок: {header} = {header_value[:100] if header_value else 'None'}...")

                # Глубокий анализ значений конкретных заголовков
                if header == "Content-Security-Policy":
                    # Проверяем наличие опасных директив в CSP
                    if "'unsafe-inline'" in header_value:
                        result["issues"].append(f"⚠️ {header} содержит 'unsafe-inline' - снижает безопасность")
                    if "'unsafe-eval'" in header_value:
                        result["issues"].append(f"⚠️ {header} содержит 'unsafe-eval' - снижает безопасность")
                elif header == "Strict-Transport-Security":
                    # Проверяем корректность настройки HSTS
                    if "max-age=0" in header_value:
                        result["issues"].append(f"⚠️ {header} имеет max-age=0 - HSTS отключен")
                elif header == "X-Frame-Options":
                    # Проверяем безопасные значения X-Frame-Options
                    if header_value.upper() not in ["DENY", "SAMEORIGIN"]:
                        result["issues"].append(f"⚠️ {header} имеет небезопасное значение: {header_value}")
            else:
                # Заголовок отсутствует - добавляем в список проблем
                result["issues"].append(f"❌ {header} отсутствует — {risk}")
                print(f"❌ Отсутствует заголовок: {header}")
        # Вычисляем общий показатель безопасности в процентах
        result["security_score"] = int((found_count / len(headers_to_check)) * 100)
        print(f"📊 Сканирование завершено. Score: {result['security_score']}%")
        print(f"🔍 Найдено заголовков: {found_count}/{len(headers_to_check)}")
        # Добавляем общую текстовую оценку на основе score
        if result["security_score"] >= 80:
            result["issues"].insert(0, "✅ Отличная безопасность заголовков!")
        elif result["security_score"] >= 60:
            result["issues"].insert(0, "⚠️ Средний уровень безопасности")
        else:
            result["issues"].insert(0, "🚨 Низкий уровень безопасности")
    except requests.exceptions.Timeout:
        # Обработка таймаута запроса
        error_msg = "⏰ Таймаут запроса (более 15 секунд)"
        print(error_msg)
        result["error"] = True
        result["issues"].append(error_msg)
    except requests.exceptions.ConnectionError:
        # Обработка ошибок подключения (DNS, недоступный хост и т.д.)
        error_msg = "🔌 Ошибка подключения к сайту"
        print(error_msg)
        result["error"] = True
        result["issues"].append(error_msg)
    except requests.exceptions.RequestException as e:
        # Общая обработка ошибок requests
        error_msg = f"🌐 Ошибка сети: {str(e)}"
        print(error_msg)
        result["error"] = True
        result["issues"].append(error_msg)
    except Exception as e:
        # Перехват любых непредвиденных ошибок
        error_msg = f"⚙️ Неожиданная ошибка: {str(e)}"
        print(error_msg)
        result["error"] = True
        result["issues"].append(error_msg)
    return result
