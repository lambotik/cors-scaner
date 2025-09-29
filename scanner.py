import requests
from datetime import datetime


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
        print(f"✅ Ответ получен, статус: {response.status_code}")

        # Проверяем основные заголовки
        headers_to_check = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

        for header in headers_to_check:
            present = header in response.headers
            result["headers"].append({
                "name": header,
                "present": present,
                "value": response.headers.get(header),
                "risk": "Риск безопасности"
            })
            if not present:
                result["issues"].append(f"{header} отсутствует")

        # Считаем score
        found = sum(1 for h in result["headers"] if h["present"])
        result["security_score"] = int((found / len(headers_to_check)) * 100)

        print(f"📊 Сканирование завершено. Score: {result['security_score']}%")

    except Exception as e:
        print(f"❌ Ошибка при сканировании: {e}")
        result["error"] = True
        result["issues"].append(f"Ошибка: {str(e)}")

    return result