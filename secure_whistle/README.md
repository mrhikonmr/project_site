# SecureWhistle: портал анонимных обращений

Flask + SQLite. Роли: **user** (сотрудник), **manager** (compliance), **admin**.

## Запуск
```
pip install -r requirements.txt
flask --app app init        # создаст БД и admin, пароль покажет один раз
python app.py               # https://... за прокси; для локальной проверки по http:
INSECURE_DEV=1 python app.py   # (Windows: set INSECURE_DEV=1)
```
Регистрация даёт только роль user. Manager и admin создаются из админки.

## Соответствие заданию и OWASP Top-10
| Критерий | Реализация | OWASP |
|---|---|---|
| Пароли | Argon2id, политика пароля (от 10, буквы+цифры) | A02, A07 |
| Сессия | HttpOnly, Secure, SameSite=Lax, срок 30 мин, `session.clear()` при входе | A07 |
| Rate limiting | Flask-Limiter: вход 5/мин, регистрация 5/час, обращения 10/час | A07 |
| Access control | `roles_required` + `get_report_or_404` (автор или manager), иначе 404 | A01 |
| IDOR | Публичный ID это `token_urlsafe(16)`; файлы проверяются через владельца обращения | A01 |
| Разделение обязанностей | Admin не читает обращения; manager не видит автора | A01, A04 |
| SQLi | Только SQLAlchemy ORM | A03 |
| XSS | Jinja2 autoescape + CSP `default-src 'self'` без inline-скриптов | A03 |
| CSRF | Flask-WTF CSRFProtect, токен во всех POST-формах (включая logout) | A01 |
| Файлы | Белый список расширений, magic bytes, совпадение типа, случайное имя, хранение вне `static`, шифрование на диске, отдача как attachment + nosniff | A04, A08 |
| Шифрование | Fernet (AES + HMAC) для тем, текстов, сообщений и файлов | A02 |
| Ошибки | Свои страницы 400/403/404/413/429/500, `debug=False` | A05 |
| Заголовки | CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, no-store | A05 |
| Аудит | Таблица Audit: вход, неудачный вход, просмотр, скачивание, смена статуса | A09 |

## Ограничения (честно сказать на защите)
- Rate limiter хранит счётчики в памяти (для продакшена нужен Redis).
- Ключи лежат в `instance/*.key` (в продакшене: менеджер секретов).
- Анонимность на уровне приложения, IP логируется только в аудите.
- Нет 2FA: можно добавить TOTP для manager/admin как улучшение.
