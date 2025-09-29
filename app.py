import os
from flask import Flask, request, render_template

# Диагностика импорта
try:
    from scanner import scan_headers
    print("✅ scanner.py успешно импортирован")
except ImportError as e:
    print(f"❌ Ошибка импорта scanner.py: {e}")
    # Заглушка для теста
    def scan_headers(url):
        return {
            "target": url,
            "date": "2025-09-29",
            "headers": [
                {"name": "Content-Security-Policy", "present": True, "risk": "XSS", "value": "test"},
                {"name": "Strict-Transport-Security", "present": True, "risk": "HSTS", "value": "max-age=31536000"},
                {"name": "X-Frame-Options", "present": False, "risk": "Clickjacking", "value": None},
            ],
            "issues": ["Тестовый режим - сканирование отключено"],
            "security_score": 50,
            "total_headers": 7,
            "error": False
        }

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    try:
        if request.method == "POST":
            url = request.form.get("url")
            if not url:
                return "Ошибка: URL не указан", 400
            print(f"🔍 Сканируем URL: {url}")
            results = scan_headers(url)
            print(f"📊 Результаты: {results}")
            return render_template("report.html", **results)
        return render_template("index.html")
    except Exception as e:
        return f"Ошибка: {str(e)}", 500

@app.route("/test-scan")
def test_scan():
    """Тест сканирования"""
    results = scan_headers("https://google.com")
    return results  # Возвращаем сырые данные для диагностики

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)