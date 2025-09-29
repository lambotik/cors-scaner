import os
from flask import Flask, request, render_template, jsonify
from flask_cors import CORS
from scanner import scan_headers
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
# Включаем CORS для всех маршрутов, чтобы разрешить кросс-доменные запросы
CORS(app)

# Правильная инициализация Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)


@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # Более разумный лимит для формы
def index():
    """
    Главная страница приложения.
    GET: Отображает форму для ввода URL
    POST: Обрабатывает отправку формы, сканирует заголовки и показывает отчёт
    Returns:
        render_template: HTML страница с формой или результатами сканирования
    """
    try:
        if request.method == "POST":
            # Получаем URL из формы
            url = request.form.get("url")
            if not url:
                return "Ошибка: URL не указан", 400
            print(f"🔍 Сканируем URL: {url}")
            # Вызываем функцию сканирования заголовков
            results = scan_headers(url)
            print(f"📊 Результаты: {results}")
            # Рендерим шаблон отчёта с полученными данными
            return render_template("report.html", **results)
        # GET запрос - показываем главную страницу с формой
        return render_template("index.html")
    except Exception as e:
        # Обработка непредвиденных ошибок
        return f"Ошибка: {str(e)}", 500


@app.route("/api/scan", methods=["POST"])
@limiter.limit("5 per minute")  # Отдельный лимит для API
def api_scan():
    """
    REST API endpoint для программного сканирования заголовков.
    Expected JSON:
        {"url": "https://example.com"}
    Returns:
        jsonify: JSON объект с результатами сканирования или ошибкой
    Example response:
        {
            "target": "https://example.com",
            "security_score": 75,
            "headers": [...],
            "issues": [...]
        }
    """
    # Получаем JSON данные из запроса
    data = request.get_json()

    if not data:
        return jsonify({"error": "JSON данные не предоставлены"}), 400

    url = data.get('url')

    if not url:
        return jsonify({"error": "URL не указан"}), 400

    try:
        # Выполняем сканирование и возвращаем JSON результат
        results = scan_headers(url)
        return jsonify(results)
    except Exception as e:
        # Возвращаем ошибку в JSON формате
        return jsonify({"error": str(e)}), 500


@app.route("/test-scan")
@limiter.limit("2 per minute")  # Лимит для тестового маршрута
def test_scan():
    """
    Тестовый маршрут для проверки работы сканера.
    Сканирует google.com и возвращает сырые JSON данные.
    Полезен для диагностики и отладки.
    Returns:
        jsonify: Результаты сканирования google.com
    """
    try:
        results = scan_headers("https://google.com")
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.errorhandler(429)
def ratelimit_handler(e):
    """
    Обработчик превышения лимита запросов.
    """
    return jsonify({
        "error": "Слишком много запросов",
        "message": "Пожалуйста, подождите перед следующим сканированием",
        "limits": {
            "form": "10 запросов в минуту",
            "api": "5 запросов в минуту",
            "test": "2 запроса в минуту"
        }
    }), 429


# Добавим также обработчик для HTML страниц при 429 ошибке
@app.errorhandler(429)
def handle_ratelimit_html(e):
    if request.accept_mimetypes.accept_html:
        return render_template('rate_limit.html'), 429
    return ratelimit_handler(e)


if __name__ == "__main__":
    # Получаем порт из переменных окружения (для Render) или используем 5000 по умолчанию
    port = int(os.environ.get("PORT", 5000))

    # Запускаем приложение на всех интерфейсах с указанным портом
    # debug=False для production окружения
    app.run(host="0.0.0.0", port=port, debug=False)