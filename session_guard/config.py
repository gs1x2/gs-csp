import os

TARGET_SERVICE_URL = os.environ.get("TARGET_SERVICE_URL", "http://127.0.0.1:5000")
GUARD_HOST = os.environ.get("GUARD_HOST", "127.0.0.1")
GUARD_PORT = int(os.environ.get("GUARD_PORT", "80"))

GUARD_SECRET_KEY = "SUPER_SECRET_GUARD_KEY_123"

# Ключ уязвимого сервиса — тот же, что и в app.secret_key уязвимого приложения
# Если у вас там os.urandom(24), нужно скопировать конкретное значение, 
# иначе декодирование не будет работать.
VULNERABLE_SECRET_KEY = b"SuperSecretSessionKey"

ADMIN_USERS = {
    "aaadmin": "superstrong",
    "security": "aaaadmin"
}

DEFAULT_SETTINGS = {
    "block_on_ip_change": 1,
    "block_on_ua_change": 1,
    "ban_minutes_after_blocked": 1
}
