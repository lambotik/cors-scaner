def analyze(headers):
    issues = []
    if not headers.get("Content-Security-Policy"):
        issues.append("❌ CSP отсутствует — сайт уязвим к XSS.")
    if headers.get("Access-Control-Allow-Origin") == "*":
        issues.append("⚠️ CORS открыт для всех — возможна утечка данных.")
    if not headers.get("Strict-Transport-Security"):
        issues.append("❌ Нет HSTS — возможны атаки через downgrade.")
    # Добавь другие проверки по желанию
    return issues
