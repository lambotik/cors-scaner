from flask import Flask, request, render_template
from scanner import scan_headers
from report_generator import generate_html_report_jinja
import os

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        results = scan_headers(url)
        generate_html_report_jinja(results, output_path="templates/report.html")
        return render_template("report.html", **results)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
