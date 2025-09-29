import os
import requests
from flask import Flask, request, render_template, jsonify
from flask_cors import CORS
from scanner import scan_headers

app = Flask(__name__)
CORS(app)  # Разрешаем CORS для API


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


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """API endpoint для сканирования"""
    data = request.get_json()
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
    """Тест сканирования"""
    results = scan_headers("https://google.com")
    return jsonify(results)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)