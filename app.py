import os
from flask import Flask, request, render_template, jsonify, send_from_directory
from flask_cors import CORS
from scanner import scan_headers
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__, static_folder='static')
# Включаем CORS для всех маршрутов, чтобы разрешить кросс-доменные запросы
CORS(app)

# Правильная инициализация Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour"]
)


# Маршрут для favicon
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/x-icon')


@app.route("/", methods=["GET", "POST"])
@limiter.limit("1 per minute")
def index():
    """
    Главная страница приложения.
    """
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


@app.route("/api/scan", methods=["POST"])
@limiter.limit("1 per minute")
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
@limiter.limit("1 per minute")
def test_scan():
    """
    Тестовый маршрут для проверки работы сканера.
    """
    try:
        results = scan_headers("https://google.com")
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Слишком много запросов",
        "message": "Пожалуйста, подождите перед следующим сканированием",
        "limits": {
            "form": "1 запросов в минуту",
            "api": "1 запросов в минуту",
            "test": "1 запроса в минуту"
        }
    }), 429


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
