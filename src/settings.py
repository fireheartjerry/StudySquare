import os
import secrets
import sys

try:
    with open("secret_key.txt", "r") as file:
        secret_key = file.readline().strip()
        SECRET_KEY = secret_key
except Exception as e:
    sys.stderr.write(str(e))
    with open("secret_key.txt", "w+") as file:
        file.write(secrets.token_hex(48))  # 384 bits
        SECRET_KEY = file.readline().strip()

TEMPLATES_AUTO_RELOAD = True
SESSION_PERMANENT = True
PERMANENT_SESSION_LIFETIME = 30 * 24 * 60 * 60
WTF_CSRF_TIME_LIMIT = PERMANENT_SESSION_LIFETIME
SESSION_TYPE = "filesystem"
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_HTTPONLY = True
SESSION_FILE_DIR = "session"
LOGGING_FILE_LOCATION = "logs/application.log"
os.makedirs(SESSION_FILE_DIR, 0o770, True)