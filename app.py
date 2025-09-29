from flask import Flask, request, render_template
from scanner import scan_headers

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        results = scan_headers(url)  # ← сохраняем результаты сканирования
        return render_template("report.html", **results)  # ← используем Jinja2 шаблон
    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)