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
        "total_headers": 7,
        "error": False
    }

    try:
        print("🔗 Выполняем HTTP запрос...")
        response = requests.get(url, timeout=10)
        headers = CaseInsensitiveDict(response.headers)  # Регистронезависимый словарь

        print(f"✅ Ответ получен, статус: {response.status_code}")

        # Проверяем основные заголовки
        headers_to_check = {
            "Content-Security-Policy": "Уязвимость к XSS",
            "Strict-Transport-Security": "Downgrade-атаки через HTTP",
            "X-Frame-Options": "Clickjacking",
            "X-Content-Type-Options": "MIME-sniffing",
            "Referrer-Policy": "Утечка реферера",
            "Permissions-Policy": "Доступ к функциям браузера"
        }

        for header, risk in headers_to_check.items():
            present = header in headers
            header_value = headers.get(header)

            result["headers"].append({
                "name": header,
                "present": present,
                "value": header_value,
                "risk": risk
            })

            if present:
                print(f"✅ Найден заголовок: {header} = {header_value[:50]}...")
            else:
                result["issues"].append(f"{header} отсутствует — {risk}")

        # Считаем score
        found = sum(1 for h in result["headers"] if h["present"])
        result["security_score"] = int((found / len(headers_to_check)) * 100)

        print(f"📊 Сканирование завершено. Score: {result['security_score']}%")
        print(f"🔍 Найдено заголовков: {found}/{len(headers_to_check)}")

    except Exception as e:
        print(f"❌ Ошибка при сканировании: {e}")
        result["error"] = True
        result["issues"].append(f"Ошибка: {str(e)}")

    return result