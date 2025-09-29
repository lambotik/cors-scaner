from jinja2 import Environment, FileSystemLoader

def generate_html_report_jinja(scan_results, output_path="report.html"):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report.html.j2")

    rendered = template.render(
        target=scan_results["target"],
        date=scan_results["date"],
        headers=scan_results["headers"],
        issues=scan_results["issues"]
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)
