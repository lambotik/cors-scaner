import requests
from datetime import datetime
from urllib.parse import urlparse
import re

SECURITY_HEADERS = {
    "Content-Security-Policy": "Уязвимость к XSS",
    "Access-Control-Allow-Origin": "CORS-запросы будут заблокированы",
    "Strict-Transport-Security": "Downgrade-атаки через HTTP",
    "X-Frame-Options": "Clickjacking",
    "X-Content-Type-Options": "MIME-sniffing",
    "Referrer-Policy": "Утечка реферера",
    "Permissions-Policy": "Доступ к функциям браузера",
    "X-XSS-Protection": "Защита от XSS (устарело, но проверяем)",
}


def analyze_csp(csp_header):
    """Анализ качества CSP заголовка"""
    warnings = []

    if not csp_header:
        return ["❌ CSP отсутствует"]

    # Проверяем unsafe-inline в script-src
    if "'unsafe-inline'" in csp_header and "script-src" in csp_header:
        warnings.append("⚠️ CSP: unsafe-inline в script-src снижает безопасность")

    # Проверяем unsafe-eval в script-src
    if "'unsafe-eval'" in csp_header and "script-src" in csp_header:
        warnings.append("⚠️ CSP: unsafe-eval в script-src снижает безопасность")

    # Проверяем отсутствие default-src
    if "default-src" not in csp_header:
        warnings.append("⚠️ CSP: отсутствует default-src")

    return warnings


def validate_url(url):
    """Проверка и нормализация URL"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)
    if not parsed.netloc:  # Если нет домена
        return None
    return url


def scan_headers(url):
    # Нормализуем URL
    normalized_url = validate_url(url)
    if not normalized_url:
        return {
            "target": url,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "headers": [],
            "issues": ["❌ Неверный URL формат"],
            "error": True
        }

    result = {
        "target": normalized_url,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "headers": [],
        "issues": [],
        "security_score": 0,
        "total_headers": len(SECURITY_HEADERS),
        "error": False,
        "csp_warnings": []
    }

    try:
        # Добавляем User-Agent чтобы избежать блокировки
        headers = {
            'User-Agent': 'Mozilla/5.0 (CORS Security Scanner)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }

        response = requests.get(normalized_url, timeout=15, headers=headers, allow_redirects=True)
        response_headers = response.headers

        found_headers = 0

        for header, risk in SECURITY_HEADERS.items():
            header_value = response_headers.get(header)
            present = header_value is not None

            # Специальный анализ для CSP
            csp_warnings = []
            if header == "Content-Security-Policy" and present:
                csp_warnings = analyze_csp(header_value)
                result["csp_warnings"] = csp_warnings

            result["headers"].append({
                "name": header,
                "present": present,
                "value": header_value if present else None,
                "risk": risk,
                "warnings": csp_warnings if header == "Content-Security-Policy" else []
            })

            if present:
                found_headers += 1
                # Проверяем опасные значения
                if header == "Access-Control-Allow-Origin" and header_value == "*":
                    result["issues"].append(f"⚠️ {header} = * — открыт для всех доменов")
                elif header == "X-XSS-Protection" and header_value == "0":
                    result["issues"].append(f"⚠️ {header} = 0 — защита от XSS отключена")
                elif header == "Content-Security-Policy" and csp_warnings:
                    result["issues"].extend(csp_warnings)
            else:
                result["issues"].append(f"❌ {header} отсутствует — {risk}")

        # Рассчитываем security score
        result["security_score"] = int((found_headers / len(SECURITY_HEADERS)) * 100)

        # Добавляем общую оценку
        if result["security_score"] >= 80:
            result["issues"].insert(0, "✅ Отличная безопасность заголовков!")
        elif result["security_score"] >= 60:
            result["issues"].insert(0, "⚠️ Средний уровень безопасности")
        else:
            result["issues"].insert(0, "🚨 Низкий уровень безопасности")

    except requests.exceptions.Timeout:
        result["issues"].append("⏰ Таймаут запроса (более 15 секунд)")
        result["error"] = True
    except requests.exceptions.ConnectionError:
        result["issues"].append("🔌 Ошибка подключения к сайту")
        result["error"] = True
    except requests.exceptions.RequestException as e:
        result["issues"].append(f"🌐 Ошибка сети: {str(e)}")
        result["error"] = True
    except Exception as e:
        result["issues"].append(f"⚙️ Неожиданная ошибка: {str(e)}")
        result["error"] = True

    return result