import requests
from datetime import datetime
from requests.structures import CaseInsensitiveDict


def scan_headers(url):
    print(f"🎯 Начинаем сканирование: {url}")

    result = {
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

        # Добавляем реалистичные заголовки браузера
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }

        response = requests.get(
            url,
            timeout=15,
            headers=headers,
            allow_redirects=True,
            verify=True
        )

        response_headers = CaseInsensitiveDict(response.headers)

        print(f"✅ Ответ получен, статус: {response.status_code}")
        print(f"📨 Полученные заголовки: {list(response_headers.keys())}")

        # Проверяем основные заголовки безопасности
        headers_to_check = {
            "Content-Security-Policy": "Уязвимость к XSS",
            "Strict-Transport-Security": "Downgrade-атаки через HTTP",
            "X-Frame-Options": "Clickjacking",
            "X-Content-Type-Options": "MIME-sniffing",
            "Referrer-Policy": "Утечка реферера",
            "Permissions-Policy": "Доступ к функциям браузера",
            "X-XSS-Protection": "Защита от XSS",
            "Cache-Control": "Кеширование чувствительных данных"
        }

        found_count = 0

        for header, risk in headers_to_check.items():
            present = header in response_headers
            header_value = response_headers.get(header)

            result["headers"].append({
                "name": header,
                "present": present,
                "value": header_value,
                "risk": risk
            })

            if present:
                found_count += 1
                print(f"✅ Найден заголовок: {header} = {header_value[:100] if header_value else 'None'}...")

                # Анализ значений
                if header == "Content-Security-Policy":
                    if "'unsafe-inline'" in header_value:
                        result["issues"].append(f"⚠️ {header} содержит 'unsafe-inline' - снижает безопасность")
                    if "'unsafe-eval'" in header_value:
                        result["issues"].append(f"⚠️ {header} содержит 'unsafe-eval' - снижает безопасность")

                elif header == "Strict-Transport-Security":
                    if "max-age=0" in header_value:
                        result["issues"].append(f"⚠️ {header} имеет max-age=0 - HSTS отключен")

                elif header == "X-Frame-Options":
                    if header_value.upper() not in ["DENY", "SAMEORIGIN"]:
                        result["issues"].append(f"⚠️ {header} имеет небезопасное значение: {header_value}")

            else:
                result["issues"].append(f"❌ {header} отсутствует — {risk}")
                print(f"❌ Отсутствует заголовок: {header}")

        # Считаем score
        result["security_score"] = int((found_count / len(headers_to_check)) * 100)

        print(f"📊 Сканирование завершено. Score: {result['security_score']}%")
        print(f"🔍 Найдено заголовков: {found_count}/{len(headers_to_check)}")

        # Добавляем общую оценку
        if result["security_score"] >= 80:
            result["issues"].insert(0, "✅ Отличная безопасность заголовков!")
        elif result["security_score"] >= 60:
            result["issues"].insert(0, "⚠️ Средний уровень безопасности")
        else:
            result["issues"].insert(0, "🚨 Низкий уровень безопасности")

    except requests.exceptions.Timeout:
        error_msg = "⏰ Таймаут запроса (более 15 секунд)"
        print(error_msg)
        result["error"] = True
        result["issues"].append(error_msg)

    except requests.exceptions.ConnectionError:
        error_msg = "🔌 Ошибка подключения к сайту"
        print(error_msg)
        result["error"] = True
        result["issues"].append(error_msg)

    except requests.exceptions.RequestException as e:
        error_msg = f"🌐 Ошибка сети: {str(e)}"
        print(error_msg)
        result["error"] = True
        result["issues"].append(error_msg)

    except Exception as e:
        error_msg = f"⚙️ Неожиданная ошибка: {str(e)}"
        print(error_msg)
        result["error"] = True
        result["issues"].append(error_msg)

    return result