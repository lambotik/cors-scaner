# 🔐 CORS Scanner

**Профессиональный инструмент для анализа безопасности HTTP-заголовков**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

CORS Scanner — это веб-приложение и CLI инструмент для комплексной проверки security-заголовков веб-сайтов. Помогает разработчикам, DevOps инженерам и пентестерам оценить уровень защищённости веб-приложений.

## 🌟 Возможности

### 🔍 Анализ безопасности
- **Проверка 8+ критических security-заголовков**
- **Content-Security-Policy (CSP)** - защита от XSS атак
- **Strict-Transport-Security (HSTS)** - принудительное использование HTTPS
- **X-Frame-Options** - защита от clickjacking
- **X-Content-Type-Options** - предотвращение MIME-sniffing
- **Referrer-Policy** - контроль утечки данных реферера
- **Permissions-Policy** - управление доступом к API браузера
- **Глубокий анализ значений** - проверка опасных настроек

### 📊 Отчетность
- **Веб-интерфейс** - интуитивный UI для ручной проверки
- **HTML отчеты** - красивые визуализированные отчеты
- **Текстовые отчеты** - для интеграции и автоматизации
- **Консольный вывод** - быстрая проверка через CLI
- **Security Score** - общая оценка безопасности (0-100%)

### ⚡ Интерфейсы
- **Web UI** - Flask веб-приложение
- **REST API** - для интеграции с другими системами
- **CLI интерфейс** - для скриптов и автоматизации

## 🚀 Быстрый старт

### Онлайн версия
Посетите [https://cors-scanner.onrender.com](https://cors-scanner.onrender.com) для мгновенного использования.

### Локальная установка

```bash
# Клонирование репозитория
git clone https://github.com/lambotik/cors-scaner.git
cd cors-scaner

# Установка зависимостей
pip install -r requirements.txt

# Запуск веб-приложения
python app.py
```
CLI интерфейс
```bash
# Базовая проверка с HTML отчетом
python main.py https://example.com
```
# Текстовый отчет
```bash
python main.py https://google.com --format text --output report.txt
```
# Оба формата с подробным выводом
```bash
python main.py https://github.com --format both --verbose
```
# Кастомный таймаут
```bash
python main.py https://slow-site.com --timeout 30
```
## 📋 Проверяемые заголовки

| Заголовок | Назначение | Критичность | Пример значения |
|-----------|------------|-------------|-----------------|
| `Content-Security-Policy` | Защита от XSS атак и внедрения скриптов | 🔴 Критический | `default-src 'self'; script-src 'self'` |
| `Strict-Transport-Security` | Принудительное использование HTTPS, защита от downgrade атак | 🔴 Критический | `max-age=31536000; includeSubDomains` |
| `X-Frame-Options` | Защита от clickjacking атак | 🔴 Критический | `DENY` или `SAMEORIGIN` |
| `X-Content-Type-Options` | Блокировка MIME-sniffing, предотвращение подмены типа контента | 🟡 Важный | `nosniff` |
| `Referrer-Policy` | Контроль утечки данных реферера, защита приватности | 🟡 Важный | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | Управление доступом к API устройств (камера, микрофон и т.д.) | 🟡 Важный | `camera=(), microphone=()` |
| `Access-Control-Allow-Origin` | Контроль CORS политики, определяет разрешенные домены для кросс-доменных запросов | 🔴 Критический | `https://trusted-domain.com` или `*` |
| `Access-Control-Allow-Methods` | Разрешенные HTTP методы для CORS запросов | 🟡 Важный | `GET, POST, OPTIONS` |
| `Access-Control-Allow-Headers` | Разрешенные заголовки для CORS запросов | 🟡 Важный | `Content-Type, Authorization` |
| `Access-Control-Allow-Credentials` | Разрешение передавать credentials (cookies, auth) в CORS запросах | 🔴 Критический | `true` |
| `Origin` | Указывает источник запроса (браузер автоматически добавляет) | 🔵 Информационный | `https://example.com` |
| `X-XSS-Protection` | Защита от XSS (устаревшая, но поддерживается) | 🔵 Информационный | `1; mode=block` |
| `Cache-Control` | Управление кешированием чувствительных данных | 🔵 Информационный | `no-store, no-cache` |

### 🔒 Особенности CORS заголовков

**`Access-Control-Allow-Origin`**
- `*` - открыт для всех доменов (опасно для конфиденциальных данных)
- `https://specific-domain.com` - разрешен только конкретный домен
- Отсутствие заголовка - CORS запросы будут блокироваться браузером

**`Access-Control-Allow-Credentials`**
- `true` - разрешает передачу cookies и авторизационных данных
- Требует явного указания домена в `Access-Control-Allow-Origin` (не `*`)

**`Origin`**
- Автоматически добавляется браузером в CORS запросы
- Показывает, с какого домена пришел запрос

## 🏗️ Архитектура
```plaintext
cors-scanner/
├── app.py                 # Flask веб-приложение (основной entry point)
├── scanner.py            # Ядро сканирования заголовков
├── analyzer.py           # Анализ и выявление проблем
├── ethic.py              # Этический анализ безопасности
├── report_generator.py   # Генерация HTML отчетов
├── report.py             # Консольные и текстовые отчеты
├── main.py               # CLI интерфейс
├── requirements.txt      # Зависимости Python
├── templates/            # HTML шаблоны
│   ├── index.html       # Главная страница с формой ввода
│   └── report.html      # Шаблон отчета с результатами
└── static/              # Статические файлы
    └── favicon.ico      # Иконка приложения
```


### 📁 Описание модулей

- **`app.py`** - Основное Flask приложение, обработка HTTP запросов, маршрутизация
- **`scanner.py`** - Выполняет HTTP запросы и собирает заголовки безопасности
- **`analyzer.py`** - Анализирует заголовки на наличие уязвимостей и проблем
- **`ethic.py`** - Оценивает этические аспекты безопасности и приватности
- **`report_generator.py`** - Генерирует HTML отчеты с использованием Jinja2 шаблонов
- **`report.py`** - Создает текстовые и консольные отчеты
- **`main.py`** - Командный интерфейс для использования из терминала
- 
