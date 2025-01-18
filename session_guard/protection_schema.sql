DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS logs;
DROP TABLE IF EXISTS settings;

CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_cookie TEXT NOT NULL,
    user_ip TEXT,
    user_agent TEXT,
    username TEXT DEFAULT 'anonymous',
    color_flags TEXT DEFAULT '',
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    blocked_until DATETIME  -- Время, до которого пользователь банится, если repeatedly пытается юзать заблокированную сессию
);

CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT,
    event_data TEXT
);

CREATE TABLE settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key TEXT UNIQUE,
    setting_value TEXT
);
