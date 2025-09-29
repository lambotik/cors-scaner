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

            # Преобразуем результаты в новую структуру
            formatted_results = format_results_for_template(results)

            # Передаем данные в шаблон правильно
            return render_template("report.html", **formatted_results)
        return render_template("index.html")
    except Exception as e:
        return render_template("index.html", error=f"Ошибка: {str(e)}")


def format_results_for_template(results):
    """
    Преобразует результаты сканирования в структуру для нового шаблона
    """
    # Базовая структура
    formatted = {
        'security_score': results.get('security_score', 0),
        'total_headers': results.get('total_headers', 0),
        'target_url': results.get('target', ''),
        'final_url': results.get('final_url', results.get('target', '')),
        'configured_headers': results.get('present_headers', 0),
        'problems_count': len(results.get('issues', [])),
        'scan_duration': f"{results.get('scan_duration', 0):.2f}s",
        'problems': results.get('issues', []),
        'final_recommendation': {
            'title': '🚨 Требуется внимание к настройкам безопасности!' if results.get('security_score',
                                                                                      0) < 70 else '✅ Безопасность на хорошем уровне',
            'description': 'Рекомендуется настроить отсутствующие заголовки безопасности.'
        }
    }

    # Группируем заголовки по разделам
    headers_data = {
        'cors': [],
        'security': [],
        'privacy': [],
        'other': []
    }

    # Определяем к какой категории относится каждый заголовок
    cors_headers = ['Access-Control-Allow-Origin', 'Access-Control-Allow-Methods',
                    'Access-Control-Allow-Headers', 'Access-Control-Allow-Credentials']

    security_headers = ['Content-Security-Policy', 'Strict-Transport-Security',
                        'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']

    privacy_headers = ['Referrer-Policy', 'Permissions-Policy']

    # Обрабатываем каждый заголовок из результатов
    for header_info in results.get('headers', []):
        header_name = header_info.get('name', '')
        is_present = header_info.get('present', False)
        header_value = header_info.get('value', '')

        # Определяем статус и риск
        status = 'present' if is_present else 'missing'
        risk_level = 'low'
        risk_text = 'Низкий риск'

        if header_info.get('critical', False):
            risk_level = 'medium' if is_present else 'high'
            risk_text = 'Средний риск' if is_present else 'Высокий риск'

        # Формируем описание заголовка
        descriptions = {
            'Content-Security-Policy': 'Защита от XSS и внедрения кода',
            'Strict-Transport-Security': 'Принудительное использование HTTPS',
            'X-Frame-Options': 'Защита от clickjacking',
            'X-Content-Type-Options': 'Блокировка MIME-sniffing',
            'X-XSS-Protection': 'Защита от XSS (устаревшая)',
            'Referrer-Policy': 'Контроль утечки referrer данных',
            'Permissions-Policy': 'Управление доступом к API браузера',
            'Access-Control-Allow-Origin': 'CORS политика - разрешенные домены',
            'Access-Control-Allow-Methods': 'CORS разрешенные методы',
            'Access-Control-Allow-Headers': 'CORS разрешенные заголовки',
            'Access-Control-Allow-Credentials': 'CORS передача учетных данных'
        }

        description = descriptions.get(header_name, 'Security header')

        # Формируем заметки
        notes = []
        if is_present:
            notes.append({'type': 'success', 'text': '✅ Заголовок настроен'})
            if header_value and '*' in header_value and 'Access-Control-Allow-Origin' in header_name:
                notes.append({'type': 'warning', 'text': '⚠️ CORS открыт для всех доменов'})
        else:
            if header_info.get('critical', False):
                notes.append({'type': 'warning', 'text': '⚠️ Критический заголовок отсутствует'})
            notes.append({'type': 'info', 'text': '💡 Рекомендация: Необходимо добавить этот заголовок'})

        header_data = {
            'name': header_name,
            'status': status,
            'risk_level': risk_level,
            'risk_text': risk_text,
            'description': description,
            'value': header_value,
            'notes': notes
        }

        # Распределяем по категориям
        if header_name in cors_headers:
            headers_data['cors'].append(header_data)
        elif header_name in security_headers:
            headers_data['security'].append(header_data)
        elif header_name in privacy_headers:
            headers_data['privacy'].append(header_data)
        else:
            headers_data['other'].append(header_data)

    formatted['headers'] = headers_data
    return formatted


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

    formatted_results = format_results_for_template(test_results)
    return render_template("report.html", **formatted_results)


if __name__ == "__main__":
    # Создаем папку templates если её нет
    if not os.path.exists('templates'):
        os.makedirs('templates')

    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Запуск CORS Scanner на порту {port}")
    print("📊 Лимиты запросов отключены")
    app.run(host="0.0.0.0", port=port, debug=True)