import os
from flask import Flask, request, render_template
from scanner import scan_headers

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    try:
        if request.method == "POST":
            url = request.form.get("url")
            if not url:
                return "Ошибка: URL не указан", 400
            results = scan_headers(url)
            return render_template("report.html", **results)
        return render_template("index.html")
    except Exception as e:
        # Временно показываем ошибку для диагностики
        return f"""
        <h1>Ошибка приложения</h1>
        <p><strong>Тип ошибки:</strong> {type(e).__name__}</p>
        <p><strong>Сообщение:</strong> {str(e)}</p>
        <pre>{e}</pre>
        """, 500

@app.route("/test")
def test():
    """Тестовая страница для проверки шаблонов"""
    try:
        return render_template("index.html")
    except Exception as e:
        return f"Ошибка шаблона: {str(e)}", 500

@app.route("/test-scan")
def test_scan():
    """Тест сканирования без формы"""
    try:
        results = scan_headers("https://google.com")
        return render_template("report.html", **results)
    except Exception as e:
        return f"Ошибка сканирования: {str(e)}", 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # ← ВАЖНО для Render
    app.run(host="0.0.0.0", port=port, debug=False)