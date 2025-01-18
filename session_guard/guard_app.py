import os
import sqlite3
import uuid
from datetime import datetime, timedelta

import requests
import itsdangerous  # <--- нужно для декодирования Flask-сессии

from flask import (
    Flask, request, redirect, make_response, Response, url_for, 
    render_template, session as admin_session
)
from config import (
    TARGET_SERVICE_URL, GUARD_HOST, GUARD_PORT, GUARD_SECRET_KEY,
    VULNERABLE_SECRET_KEY,
    ADMIN_USERS, DEFAULT_SETTINGS
)

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_ADMIN_SESSION"

DB_NAME = os.path.join(os.path.dirname(__file__), 'protection.db')

# --------------------------------------------------------------------------------
# Вспомогательные функции
# --------------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        schema_path = os.path.join(os.path.dirname(__file__), 'protection_schema.sql')
        with open(schema_path, 'r', encoding='utf-8') as f:
            db.executescript(f.read())
        db.commit()
        # инициализируем настройки
        for k, v in DEFAULT_SETTINGS.items():
            db.execute(
                "INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)",
                (k, str(v))
            )
        db.commit()

def log_event(event_type, event_data):
    db = get_db()
    db.execute(
        "INSERT INTO logs (event_type, event_data) VALUES (?, ?)",
        (event_type, event_data)
    )
    db.commit()

def get_setting(key):
    db = get_db()
    row = db.execute(
        "SELECT setting_value FROM settings WHERE setting_key = ?",
        (key,)
    ).fetchone()
    if row is None:
        return None
    return row['setting_value']

def set_setting(key, value):
    db = get_db()
    db.execute(
        "UPDATE settings SET setting_value = ? WHERE setting_key = ?",
        (str(value), key)
    )
    db.commit()

def find_session(session_cookie_value):
    db = get_db()
    row = db.execute(
        "SELECT * FROM sessions WHERE session_cookie = ? LIMIT 1",
        (session_cookie_value,)
    ).fetchone()
    return row

def create_session_record(session_cookie_value, ip, user_agent):
    db = get_db()
    db.execute(
        """
        INSERT INTO sessions (session_cookie, user_ip, user_agent)
        VALUES (?, ?, ?)
        """,
        (session_cookie_value, ip, user_agent)
    )
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.commit()
    return new_id

def deactivate_session(session_id):
    db = get_db()
    db.execute(
        "UPDATE sessions SET is_active = 0, updated_at = ? WHERE id = ?",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), session_id)
    )
    db.commit()

def set_blocked_until(session_id, dt):
    db = get_db()
    db.execute(
        "UPDATE sessions SET blocked_until = ? WHERE id = ?",
        (dt.strftime("%Y-%m-%d %H:%M:%S"), session_id)
    )
    db.commit()

def decode_flask_session(cookie_value):
    """
    Раскодировать Flask-сессию уязвимого приложения.
    Предполагается, что VULNERABLE_SECRET_KEY совпадает с app.secret_key уязвимого сервиса.

    Возвращаем dict, где могут быть поля session['username'] и др.
    Если не удаётся декодировать — возвращаем пустой dict.
    """
    s = itsdangerous.URLSafeTimedSerializer(VULNERABLE_SECRET_KEY, salt='cookie-session')
    try:
        data = s.loads(cookie_value)
        # data - dict с содержимым сессии
        return data
    except Exception:
        return {}

def update_session_username_and_color_flags(session_cookie_value):
    """
    Вместо того чтобы брать username из формы /login,
    теперь берём его прямо из декодированной Flask-сессии, если там есть 'username'.
    Потом выставляем color_flags (red/yellow/orange).
    """
    db = get_db()
    row = db.execute(
        "SELECT * FROM sessions WHERE session_cookie = ? LIMIT 1",
        (session_cookie_value,)
    ).fetchone()
    if not row:
        return

    # Парсим cookie_value как Flask-сессию
    # Если в уязвимом приложении session['username'] есть, берём его
    session_data = decode_flask_session(session_cookie_value)
    username = session_data.get('username', 'anonymous')

    # Определяем флаги
    color_flags = []
    # Первая сессия для этого username?
    c_username = db.execute(
        "SELECT COUNT(*) as cnt FROM sessions WHERE username = ? AND id != ?",
        (username, row['id'])
    ).fetchone()
    if c_username['cnt'] == 0:
        color_flags.append("red")

    # Первый IP?
    c_ip = db.execute(
        "SELECT COUNT(*) as cnt FROM sessions WHERE user_ip = ? AND id != ?",
        (row['user_ip'], row['id'])
    ).fetchone()
    if c_ip['cnt'] == 0:
        color_flags.append("yellow")

    # Первый User-Agent?
    c_ua = db.execute(
        "SELECT COUNT(*) as cnt FROM sessions WHERE user_agent = ? AND id != ?",
        (row['user_agent'], row['id'])
    ).fetchone()
    if c_ua['cnt'] == 0:
        color_flags.append("orange")

    flags_str = "|".join(color_flags)

    db.execute(
        "UPDATE sessions SET username = ?, color_flags = ?, updated_at = ? WHERE id = ?",
        (username, flags_str, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), row['id'])
    )
    db.commit()

def block_user_with_message(session_cookie_value, message):
    """
    Возвращаем пользователю страницу с информацией (5 секунд), 
    при этом сбрасываем ему cookie (ставим anon_…).

    После 5 секунд — редирект на /login (уязвимый сервис), 
    чтобы пользователь залогинился по-новой.
    """
    # Генерируем новый anon cookie
    new_cookie = f"anon_{uuid.uuid4().hex}"

    # Формируем HTML с 5-секундным таймером
    html_content = f"""
    <html>
    <head>
        <meta http-equiv="refresh" content="5;url=/login">
    </head>
    <body>
    <h3>{message}</h3>
    <p>Через 5 секунд вы будете перенаправлены на страницу входа.</p>
    </body>
    </html>
    """

    resp = make_response(html_content, 200)
    # Сбрасываем куки у пользователя
    resp.set_cookie('session', new_cookie, expires=0)
    return resp

# --------------------------------------------------------------------------------
# Логика перехвата запросов
# --------------------------------------------------------------------------------

@app.before_request
def intercept_requests():
    # Маршруты /admin* обрабатываем внутри guard_app, не проксируем
    if request.path.startswith("/admin"):
        if request.path != "/admin/login" and not admin_session.get("admin_user"):
            return redirect(url_for("admin_login"))
        return None

    # Для остальных — проксирование
    session_cookie_value = request.cookies.get('session')
    user_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'unknown')

    log_event("REQUEST", f"Path={request.path}, IP={user_ip}, CookieSession={session_cookie_value}")

    if session_cookie_value:
        row = find_session(session_cookie_value)
        if row:
            if row["is_active"] == 0:
                # Сессия уже деактивирована => баним
                if row["blocked_until"]:
                    blocked_until_dt = datetime.strptime(row["blocked_until"], "%Y-%m-%d %H:%M:%S")
                    if datetime.now() < blocked_until_dt:
                        log_event("BLOCK", f"Session still banned: {session_cookie_value}")
                        return block_user_with_message(
                            session_cookie_value,
                            "Сессия заблокирована (временный бан). Если вы не узнаёте данное действие, проверьте систему на вирусы."
                        )
                    else:
                        # бан истёк, но сессия всё равно неактивна => блокируем заново
                        ban_minutes = int(get_setting("ban_minutes_after_blocked") or "5")
                        blocked_until_dt = datetime.now() + timedelta(minutes=ban_minutes)
                        set_blocked_until(row['id'], blocked_until_dt)
                        log_event("BLOCK", f"Session re-used after ban => ban again: {row['id']}")
                        return block_user_with_message(
                            session_cookie_value,
                            "Сессия деактивирована. Вы временно заблокированы."
                        )
                else:
                    # нет blocked_until, значит первое повторное использование 
                    ban_minutes = int(get_setting("ban_minutes_after_blocked") or "5")
                    blocked_until_dt = datetime.now() + timedelta(minutes=ban_minutes)
                    set_blocked_until(row['id'], blocked_until_dt)
                    log_event("BLOCK", f"Session re-used after deactivate => ban: {row['id']}")
                    return block_user_with_message(
                        session_cookie_value,
                        "Сессия была деактивирована. На всякий случай вас заблокировали на время."
                    )
            else:
                # Сессия активна
                block_ip_change = int(get_setting("block_on_ip_change") or "1")
                block_ua_change = int(get_setting("block_on_ua_change") or "1")

                if block_ip_change == 1 and row["user_ip"] != user_ip:
                    # смена IP => блокируем
                    deactivate_session(row['id'])
                    ban_minutes = int(get_setting("ban_minutes_after_blocked") or "5")
                    blocked_until_dt = datetime.now() + timedelta(minutes=ban_minutes)
                    set_blocked_until(row['id'], blocked_until_dt)
                    log_event("BLOCK", f"IP changed from {row['user_ip']} to {user_ip}, session={row['id']}")
                    return block_user_with_message(
                        session_cookie_value,
                        "Сессия заблокирована из-за смены IP. Если это не вы, поменяйте пароль."
                    )

                if block_ua_change == 1 and row["user_agent"] != user_agent:
                    # смена UA => блокируем
                    deactivate_session(row['id'])
                    ban_minutes = int(get_setting("ban_minutes_after_blocked") or "5")
                    blocked_until_dt = datetime.now() + timedelta(minutes=ban_minutes)
                    set_blocked_until(row['id'], blocked_until_dt)
                    log_event("BLOCK", f"User-Agent changed from {row['user_agent']} to {user_agent}, session={row['id']}")
                    return block_user_with_message(
                        session_cookie_value,
                        "Сессия заблокирована из-за смены User-Agent."
                    )

                # Перед проксированием: обновим username/цвета (может быть, пользователь авторизовался)
                update_session_username_and_color_flags(session_cookie_value)
        else:
            # Нет в нашей БД => создаём
            new_id = create_session_record(session_cookie_value, user_ip, user_agent)
            log_event("CREATE_SESSION", f"New session={session_cookie_value}, rowid={new_id}")
    else:
        # Нет cookie => создаём анонимную
        new_cookie = f"anon_{uuid.uuid4().hex}"
        new_id = create_session_record(new_cookie, user_ip, user_agent)
        log_event("CREATE_SESSION", f"New ANON session={new_cookie}, rowid={new_id}")
        resp = make_response(redirect(request.url))
        resp.set_cookie('session', new_cookie)
        return resp

    return proxy_request()

def proxy_request():
    target_url = f"{TARGET_SERVICE_URL}{request.path}"
    if request.query_string:
        target_url += f"?{request.query_string.decode('utf-8')}"

    method = request.method
    headers = dict(request.headers)
    headers.pop('Host', None)

    data_to_send = request.form if request.form else request.data

    proxied_response = requests.request(
        method,
        target_url,
        headers=headers,
        cookies=request.cookies,
        data=data_to_send,
        allow_redirects=False
    )

    log_event("RESPONSE", f"Status={proxied_response.status_code} -> {request.path}")

    flask_response = make_response(proxied_response.content, proxied_response.status_code)
    for key, value in proxied_response.headers.items():
        if key.lower() not in ['content-length', 'transfer-encoding', 'content-encoding', 'connection']:
            flask_response.headers[key] = value

    return flask_response

# --------------------------------------------------------------------------------
# Админ-панель
# --------------------------------------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        if username in ADMIN_USERS and ADMIN_USERS[username] == password:
            admin_session["admin_user"] = username
            return redirect(url_for("admin_index"))
        else:
            return "Неверные учётные данные"
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    admin_session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin")
def admin_index():
    db = get_db()
    rows = db.execute("SELECT * FROM sessions").fetchall()
    return render_template("admin.html", sessions=rows)

@app.route("/admin/deactivate/<int:session_id>", methods=["POST"])
def admin_deactivate_session(session_id):
    deactivate_session(session_id)
    log_event("DEACTIVATE_SESSION", f"SessionID={session_id}")
    return redirect(url_for("admin_index"))

@app.route("/admin/logs")
def admin_logs():
    db = get_db()
    log_rows = db.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
    return render_template("admin_logs.html", logs=log_rows)

@app.route("/admin/manage", methods=["GET", "POST"])
def admin_manage():
    if request.method == "POST":
        block_ip = request.form.get("block_on_ip_change", "0")
        block_ua = request.form.get("block_on_ua_change", "0")
        ban_minutes = request.form.get("ban_minutes_after_blocked", "5")

        set_setting("block_on_ip_change", block_ip)
        set_setting("block_on_ua_change", block_ua)
        set_setting("ban_minutes_after_blocked", ban_minutes)

        log_event("ADMIN_CHANGE_SETTINGS", f"block_ip={block_ip}, block_ua={block_ua}, ban={ban_minutes}")
        return redirect(url_for("admin_manage"))

    current_block_ip = get_setting("block_on_ip_change")
    current_block_ua = get_setting("block_on_ua_change")
    current_ban = get_setting("ban_minutes_after_blocked")

    return render_template(
        "admin_manage.html",
        block_ip=current_block_ip,
        block_ua=current_block_ua,
        ban_minutes=current_ban
    )

@app.route("/admin/clear_db", methods=["POST"])
def admin_clear_db():
    db = get_db()
    db.execute("DROP TABLE IF EXISTS sessions;")
    db.execute("DROP TABLE IF EXISTS logs;")
    db.execute("DROP TABLE IF EXISTS settings;")
    db.commit()
    init_db()
    log_event("ADMIN_CLEAR_DB", "All data cleared and re-init")
    return redirect(url_for("admin_index"))

# --------------------------------------------------------------------------------
# Запуск
# --------------------------------------------------------------------------------

if __name__ == "__main__":
    if not os.path.exists(DB_NAME):
        init_db()
    app.run(host=GUARD_HOST, port=GUARD_PORT, debug=True)
