import os
from flask import Flask, request, render_template, jsonify, send_from_directory
from flask_cors import CORS
from scanner import scan_headers

app = Flask(__name__, static_folder='static', template_folder='templates')
# Включаем CORS для всех маршрутов, чтобы разрешить кросс-доменные запросы
CORS(app)


# Маршрут для favicon
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/x-icon')


@app.route("/", methods=["GET", "POST"])
def index():
    """
    Главная страница приложения.
    """
    try:
        if request.method == "POST":
            url = request.form.get("url")
            if not url:
                return render_template("index.html", error="Ошибка: URL не указан")
            print(f"🔍 Сканируем URL: {url}")
            results = scan_headers(url)
            print(f"📊 Результаты получены, оценка: {results.get('security_score', 0)}%")

            # Передаем данные в шаблон правильно
            return render_template("report.html", **results)
        return render_template("index.html")
    except Exception as e:
        return render_template("index.html", error=f"Ошибка: {str(e)}")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    REST API endpoint для программного сканирования заголовков.
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "JSON данные не предоставлены"}), 400

    url = data.get('url')

    if not url:
        return jsonify({"error": "URL не указан"}), 400

    try:
        results = scan_headers(url)
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/test-scan")
def test_scan():
    """
    Тестовый маршрут для проверки работы сканера.
    """
    try:
        results = scan_headers("https://google.com")
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Убираем информацию о лимитах из шаблона report.html
@app.route("/report-template-fix")
def report_template_fix():
    """
    Временный маршрут для проверки шаблона без лимитов
    """
    # Тестовые данные для проверки
    test_results = {
        'target': 'https://example.com',
        'date': '2024-01-15 14:30:00',
        'security_score': 75,
        'scan_duration': 2.5,
        'http_status': 200,
        'present_headers': 8,
        'total_headers': 11,
        'headers': [
            {
                'name': 'Content-Security-Policy',
                'present': True,
                'value': "default-src 'self'",
                'risk': 'Низкий',
                'critical': True
            },
            {
                'name': 'Strict-Transport-Security',
                'present': False,
                'value': None,
                'risk': 'Высокий',
                'critical': True
            }
        ],
        'issues': [
            "❌ HSTS отсутствует — возможны downgrade атаки на HTTPS",
            "⚠️ CORS открыт для всех доменов (Access-Control-Allow-Origin: *)"
        ]
    }
    return render_template("report.html", **test_results)


if __name__ == "__main__":
    # Создаем папку templates если её нет
    if not os.path.exists('templates'):
        os.makedirs('templates')

    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Запуск CORS Scanner на порту {port}")
    print("📊 Лимиты запросов отключены")
    app.run(host="0.0.0.0", port=port, debug=True)