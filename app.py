import os
from flask import Flask, request, render_template, jsonify, send_from_directory
from flask_cors import CORS
from scanner import scan_headers

app = Flask(__name__, static_folder='static', template_folder='templates')
# Включаем CORS для всех маршрутов, чтобы разрешить кросс-доменные запросы
CORS(app)


def format_results_for_template(results):
    """
    Преобразует результаты сканирования в структуру для нового шаблона
    """
    # Очищаем проблемы и рекомендации
    cleaned_problems = []
    for problem in results.get('issues', []):
        cleaned = problem.replace("X-", "").replace("A.", "").strip()
        cleaned = ' '.join(cleaned.split())
        cleaned_problems.append(cleaned)

    cleaned_recommendations = []
    for rec in results.get('recommendations', []):
        cleaned_rec = rec.strip()
        # Убираем дубликаты рекомендаций
        if cleaned_rec not in cleaned_recommendations:
            cleaned_recommendations.append(cleaned_rec)

    # Базовая структура
    formatted = {
        'security_score': results.get('security_score', 0),
        'total_headers': results.get('total_headers', 0),
        'target_url': results.get('target', ''),
        'final_url': results.get('final_url', results.get('target', '')),
        'configured_headers': results.get('present_headers', 0),
        'problems_count': len(cleaned_problems),
        'scan_duration': f"{results.get('scan_duration', 0):.2f}s",
        'risk_level': results.get('risk_level', 'Неизвестен'),
        'server_info': results.get('server_info', 'Не указан'),
        'redirects': results.get('redirects', False),
        'http_status': results.get('http_status', 0),
        'problems': cleaned_problems,
        'recommendations': cleaned_recommendations,  # Только уникальные рекомендации
        'cors_analysis': results.get('cors_analysis', {}),
        'scan_details': results.get('scan_details', {}),
        'final_recommendation': generate_final_recommendation(results)
    }

    # Группируем заголовки по разделам
    headers_data = {
        'cors': [],
        'security': [],
        'privacy': [],
        'other': []
    }

    cors_headers = ['Access-Control-Allow-Origin', 'Access-Control-Allow-Methods',
                    'Access-Control-Allow-Headers', 'Access-Control-Allow-Credentials']

    security_headers = ['Content-Security-Policy', 'Strict-Transport-Security',
                        'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']

    privacy_headers = ['Referrer-Policy', 'Permissions-Policy']

    # Обрабатываем каждый заголовок
    for header_info in results.get('headers', []):
        header_name = header_info.get('name', '')
        status = 'present' if header_info.get('present', False) else 'missing'

        header_data = {
            'name': header_name,
            'status': status,
            'risk_level': header_info.get('risk_level', 'low').lower(),
            'risk_text': header_info.get('risk_level', 'Низкий риск'),
            'description': header_info.get('description', ''),
            'risk_description': header_info.get('risk_description', ''),
            'value': header_info.get('value', ''),
            'quality_score': header_info.get('quality_score', 0),
            'critical': header_info.get('critical', False),
            'notes': []
        }

        # Добавляем ТОЛЬКО заметки из анализа (без рекомендаций)
        for note in header_info.get('notes', []):
            header_data['notes'].append(
                {'type': 'success' if 'правильно' in note or 'отлично' in note else 'warning', 'text': note})

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


def generate_final_recommendation(results):
    """
    Генерирует итоговую рекомендацию на основе результатов сканирования
    """
    score = results.get('security_score', 0)
    risk_level = results.get('risk_level', 'Неизвестен')

    if score >= 90:
        return {
            'title': '✅ Отличная безопасность!',
            'description': 'Все критически важные заголовки настроены правильно. Рекомендуется регулярный мониторинг.',
            'level': 'success'
        }
    elif score >= 70:
        return {
            'title': '🟡 Хорошая безопасность',
            'description': 'Основные заголовки настроены. Рекомендуется улучшить настройки второстепенных заголовков.',
            'level': 'warning'
        }
    elif score >= 50:
        return {
            'title': '🟠 Требует улучшений',
            'description': 'Отсутствуют некоторые важные заголовки. Рекомендуется срочно настроить недостающие заголовки безопасности.',
            'level': 'warning'
        }
    elif score >= 30:
        return {
            'title': '🔴 Высокий риск',
            'description': 'Отсутствуют критические заголовки безопасности. Немедленно настройте CSP, HSTS и X-Frame-Options.',
            'level': 'danger'
        }
    else:
        return {
            'title': '🚨 Критический риск!',
            'description': 'Сайт крайне уязвим. Требуется немедленная настройка всех заголовков безопасности.',
            'level': 'critical'
        }


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
