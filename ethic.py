def ethical_explain(header):
    explanations = {
        "Content-Security-Policy": "CSP защищает пользователей от внедрения вредоносного кода.",
        "Access-Control-Allow-Origin": "Открытый CORS может нарушить приватность.",
        "Strict-Transport-Security": "HSTS предотвращает атаки через подмену протокола.",
    }
    return explanations.get(header, "Нет этического комментария.")
