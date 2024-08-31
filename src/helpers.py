import logging, re, json, urllib.parse

from functools import wraps
from flask import redirect, request, session, flash, make_response
from werkzeug.security import check_password_hash

def verify_text(text):
    """
    Check if text only contains A-Z, a-z, 0-9, underscores, and dashes
    """
    return bool(re.match(r'^[\w\-]+$', text))

def json_fail(message: str, http_code: int):
    """
    Return the fail message as a JSON response with the specified http code
    """
    resp = make_response((json.dumps({"status": "fail", "message": message}), http_code))
    resp.headers['Content-Type'] = 'application/json; charset=utf-8'
    return resp

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login?next=" + urllib.parse.quote(request.full_path))
        return f(*args, **kwargs)
    return decorated_function

def login_chk(rows):
    """
    Determines if the user is allowed to login
    Used by login() in application.py
    rows is a result of a db query for the user
    """
    logger = logging.getLogger("CTFOJ")
    # Check if username and password match db entry
    if len(rows) != 1 or not check_password_hash(rows[0]["password"],
                                                 request.form.get("password")):
        flash('Incorrect username/password', 'danger')
        logger.info(f"Incorrect login attempt from IP {request.remote_addr}",
                    extra={"section": "auth"})
        return 401

    return 0

def register_chk(username, password, confirmation):
    """
    Determines if the user is allowed to register
    Used by register() in application.py
    """
    if not username or not verify_text(username):
        flash('Invalid username', 'danger')
        return 400

    if not password or len(password) < 8:
        flash('Password must be at least 8 characters', 'danger')
        return 400

    if not confirmation or password != confirmation:
        flash('Passwords do not match', 'danger')
        return 400

    return 0