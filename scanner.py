import requests
from datetime import datetime

SECURITY_HEADERS = {
    "Content-Security-Policy": "Уязвимость к XSS",
    "Access-Control-Allow-Origin": "CORS-запросы будут заблокированы",
    "Strict-Transport-Security": "Downgrade-атаки через HTTP",
    "X-Frame-Options": "Clickjacking",
    "Referrer-Policy": "Утечка реферера",
}

def scan_headers(url):
    result = {
        "target": url,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "headers": [],
        "issues": []
    }

    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        for header, risk in SECURITY_HEADERS.items():
            present = header in headers
            result["headers"].append({
                "name": header,
                "present": present,
                "risk": risk
            })
            if not present:
                result["issues"].append(f"{header} отсутствует — {risk}")

    except requests.RequestException as e:
        result["issues"].append(f"Ошибка запроса: {str(e)}")

    return result
