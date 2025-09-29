def ethical_explain(header, value=None):
    """
    Возвращает этическое объяснение для security-заголовков.

    Объясняет не только технические аспекты, но и этические последствия
    для приватности пользователей и безопасности данных.

    Args:
        header (str): Название HTTP-заголовка
        value (str, optional): Значение заголовка для контекстного анализа

    Returns:
        dict: Словарь с этическим объяснением и дополнительной информацией
    """

    explanations = {
        "Content-Security-Policy": {
            "description": "CSP защищает пользователей от внедрения вредоносного кода.",
            "ethical_impact": "✅ Защищает данные пользователей от краж через XSS атаки",
            "privacy_risk": "Высокий - без CSP возможен перехват вводимых данных",
            "user_trust": "Критически важный для доверия к веб-приложению",
            "simple_description": "CSP защищает пользователей от внедрения вредоносного кода."
        },
        "Access-Control-Allow-Origin": {
            "description": "Контролирует доступ к ресурсам с других доменов.",
            "ethical_impact": "🔒 Предотвращает несанкционированный доступ к данным",
            "privacy_risk": "Средний - неправильная настройка может раскрыть API",
            "user_trust": "Важен для защиты конфиденциальных операций",
            "simple_description": "Открытый CORS может нарушить приватность."
        },
        "Strict-Transport-Security": {
            "description": "HSTS предотвращает атаки через подмену протокола.",
            "ethical_impact": "🛡️ Гарантирует безопасное HTTPS-соединение",
            "privacy_risk": "Высокий - без HSTS возможен перехват трафика",
            "user_trust": "Фундаментальный для электронной коммерции и банкинга",
            "simple_description": "HSTS предотвращает атаки через подмену протокола."
        },
        "X-Frame-Options": {
            "description": "Защищает от атак clickjacking.",
            "ethical_impact": "🚫 Предотвращает мошеннические действия от имени пользователя",
            "privacy_risk": "Средний - возможен кликджекинг конфиденциальных действий",
            "user_trust": "Критически важен для финансовых операций",
            "simple_description": "Защищает от атак clickjacking."
        },
        "X-Content-Type-Options": {
            "description": "Блокирует MIME-sniffing атаки.",
            "ethical_impact": "📁 Защищает от подмены типа контента",
            "privacy_risk": "Низкий - но предотвращает скрытые уязвимости",
            "user_trust": "Повышает общую надежность приложения",
            "simple_description": "Блокирует MIME-sniffing атаки."
        },
        "Referrer-Policy": {
            "description": "Контролирует передачу referrer-данных.",
            "ethical_impact": "🔍 Ограничивает утечку информации о поведении пользователя",
            "privacy_risk": "Высокий - раскрывает историю переходов и личные данные",
            "user_trust": "Демонстрирует уважение к приватности пользователей",
            "simple_description": "Контролирует передачу referrer-данных."
        },
        "Permissions-Policy": {
            "description": "Управляет доступом к функциям браузера.",
            "ethical_impact": "🎛️ Дает пользователям контроль над доступом к камере, микрофону и т.д.",
            "privacy_risk": "Высокий - без политики возможен несанкционированный доступ к устройствам",
            "user_trust": "Критически важен для приложений с доступом к hardware",
            "simple_description": "Управляет доступом к функциям браузера."
        },
        "X-XSS-Protection": {
            "description": "Включает встроенную защиту от XSS в браузерах.",
            "ethical_impact": "🛡️ Добавляет дополнительный уровень защиты",
            "privacy_risk": "Средний - современные браузеры имеют встроенную защиту",
            "user_trust": "Рекомендуется для обратной совместимости",
            "simple_description": "Включает встроенную защиту от XSS в браузерах."
        }
    }

    # Получаем базовое объяснение
    header_info = explanations.get(header)

    if not header_info:
        return {
            "description": "Нет этического комментария для этого заголовка.",
            "ethical_impact": "Неизвестно",
            "privacy_risk": "Неизвестно",
            "user_trust": "Неизвестно",
            "simple_description": "Нет этического комментария.",
            "contextual_warnings": []
        }

    # Добавляем контекстные предупреждения на основе значения
    contextual_warnings = []

    if header == "Access-Control-Allow-Origin" and value == "*":
        contextual_warnings.append("⚠️ ОПАСНО: CORS открыт для всех доменов - возможна утечка данных")

    if header == "Content-Security-Policy" and value:
        if "'unsafe-inline'" in value:
            contextual_warnings.append("⚠️ ВНИМАНИЕ: CSP содержит unsafe-inline - снижает безопасность")
        if "'unsafe-eval'" in value:
            contextual_warnings.append("⚠️ ВНИМАНИЕ: CSP содержит unsafe-eval - потенциально опасно")

    if header == "Strict-Transport-Security" and value and "max-age=0" in value:
        contextual_warnings.append("⚠️ ПРЕДУПРЕЖДЕНИЕ: HSTS отключен (max-age=0)")

    # Формируем полный ответ
    result = header_info.copy()
    result["contextual_warnings"] = contextual_warnings

    return result


def get_ethical_rating(headers_data):
    """
    Рассчитывает общий этический рейтинг безопасности на основе заголовков.

    Args:
        headers_data (list): Список заголовков с полями 'name' и 'present'

    Returns:
        dict: Этический рейтинг с пояснениями
    """
    # Определяем категории заголовков внутри функции
    critical_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options"
    ]

    important_headers = [
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    # Подсчитываем присутствующие заголовки
    present_critical = sum(1 for h in headers_data
                           if h['name'] in critical_headers and h['present'])
    present_important = sum(1 for h in headers_data
                            if h['name'] in important_headers and h['present'])

    total_headers = len(critical_headers) + len(important_headers)
    present_total = present_critical + present_important

    # Рассчитываем оценку
    score = (present_total / total_headers) * 100 if total_headers > 0 else 0

    # Определяем уровень
    if score >= 80:
        rating = "🟢 Отлично"
        description = "Высокий уровень этической ответственности"
    elif score >= 60:
        rating = "🟡 Удовлетворительно"
        description = "Средний уровень, есть возможности для улучшения"
    else:
        rating = "🔴 Неудовлетворительно"
        description = "Низкий уровень защиты приватности пользователей"

    return {
        "rating": rating,
        "score": round(score),
        "description": description,
        "critical_present": present_critical,
        "critical_total": len(critical_headers),
        "important_present": present_important,
        "important_total": len(important_headers)
    }


def generate_ethical_summary(headers_data):
    """
    Генерирует краткое этическое резюме на основе всех заголовков.

    Args:
        headers_data (list): Данные всех проверенных заголовков

    Returns:
        str: Текстовое резюме этических аспектов безопасности
    """
    rating = get_ethical_rating(headers_data)

    # Определяем категории заголовков для использования в этой функции
    critical_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options"
    ]

    summary_parts = [
        f"## Этическая оценка безопасности: {rating['rating']}",
        f"**Общий балл: {rating['score']}%**",
        f"{rating['description']}",
        "",
        "### Детали:",
        f"- Критические заголовки: {rating['critical_present']}/{rating['critical_total']}",
        f"- Важные заголовки: {rating['important_present']}/{rating['important_total']}",
        "",
        "### Рекомендации:"
    ]

    # Добавляем рекомендации на основе отсутствующих заголовков
    missing_critical = [h['name'] for h in headers_data
                        if h['name'] in critical_headers and not h['present']]

    for header in missing_critical:
        explanation = ethical_explain(header)
        # Теперь explanation всегда словарь
        if 'ethical_impact' in explanation:
            summary_parts.append(f"🔴 **Добавьте {header}** - {explanation['ethical_impact']}")
        else:
            summary_parts.append(f"🔴 **Добавьте {header}** - критически важный заголовок безопасности")

    return "\n".join(summary_parts)


# Дополнительная функция для простого использования (обратная совместимость)
def ethical_explain_simple(header):
    """
    Упрощенная версия функции для обратной совместимости.

    Args:
        header (str): Название HTTP-заголовка

    Returns:
        str: Простое текстовое объяснение
    """
    result = ethical_explain(header)
    return result.get("simple_description", "Нет этического комментария.")