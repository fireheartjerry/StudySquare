import logging
import os
import requests
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from io import BytesIO
import random
import string
import pytz

UTC = timezone.utc

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 

import jwt
from flask import (abort, Flask, flash, redirect, render_template, request,
                   send_from_directory, send_file, session, url_for)
from flask_mail import Mail
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import HTTPException, InternalServerError, default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import *  # noqa
from db import *
import re
from datetime import datetime, timedelta

#from fuzzywuzzy import fuzz

app = Flask(__name__)
app.config.from_object('settings')

LOG_HANDLER = logging.FileHandler(app.config['LOGGING_FILE_LOCATION'])
LOG_HANDLER.setFormatter(
    logging.Formatter(fmt="[TOPSOJ] [{section}] [{levelname}] [{asctime}] {message}",
                      style='{'))
logger = logging.getLogger("TOPSOJ")
logger.addHandler(LOG_HANDLER)
logger.propagate = False
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(
    filename=app.config['LOGGING_FILE_LOCATION'],
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s',
)
logging.getLogger().addHandler(logging.StreamHandler())
# Configure flask-session
Session(app)

# Configure flask-WTF
csrf = CSRFProtect(app)
csrf.init_app(app)

# Load api
from views.square import api as view_square
app.register_blueprint(view_square, url_prefix="/square")

@app.route("/")
def index():
    hotkey1, hotkey2, hotkey3, hotkey4, hotkey5, hotkey6 = gethotkeys()
    
    popular_squares = db.execute("SELECT * FROM squares ORDER BY members DESC LIMIT 3")
    return render_template("index.html", popular_squares=popular_squares, hotkey1=hotkey1, hotkey2=hotkey2, hotkey3=hotkey3, hotkey4=hotkey4, hotkey5=hotkey5, hotkey6=hotkey6)


@app.route("/profile")
def profile():
    hotkey1, hotkey2, hotkey3, hotkey4, hotkey5, hotkey6 = gethotkeys()
    data = db.execute("SELECT * FROM users WHERE id = :uid", uid=session["user_id"])[0]
    recent_10_squares = db.execute("SELECT * FROM square_join_log WHERE user_id = :uid ORDER BY date DESC LIMIT 10", uid=session["user_id"])
    return render_template("profile.html", data=data, recent_10_squares=recent_10_squares, hotkey1=hotkey1, hotkey2=hotkey2, hotkey3=hotkey3, hotkey4=hotkey4, hotkey5=hotkey5, hotkey6=hotkey6)


@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget user id
    session.clear()
    session.permanent = True  # Have to re-set this after clear

    if request.method == "GET":
        return render_template("auth/login.html")

    # Reached using POST

    # Ensure username and password were submitted
    if not request.form.get("username") or not request.form.get("password"):
        flash('Username and password cannot be blank', 'danger')
        return render_template("auth/login.html"), 400

    # Ensure user is allowed to log in
    rows = db.execute("SELECT * FROM users WHERE username=:username",
                      username=request.form.get("username"))
    code = login_chk(rows)
    if code != 0:
        flash('Invalid username or password', 'danger')
        return render_template("auth/login.html"), code

    # Remember which user has logged in
    session["user_id"] = rows[0]["id"]
    session["username"] = rows[0]["username"]

    flash('Logged in successfully!', 'success')
    logger.info((f"User #{session['user_id']} ({session['username']}) logged in "
                 f"on IP {request.remote_addr}"), extra={"section": "auth"})
    # Redirect user to next page
    next_url = request.form.get("next")
    if next_url and '//' not in next_url and ':' not in next_url:
        return redirect(next_url)
    return redirect('/')


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("auth/register.html")

    # Reached using POST

    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    code = register_chk(username, password, confirmation)
    if code:
        return render_template("auth/register.html"), code

    if password == '12345678':
        flash("Please choose a password better than that.", "danger")
        return render_template("auth/register.html"), 400

    # Create entry & check for duplicate
    try:
        db.execute(("INSERT INTO users(username, password, join_date) "
                    "VALUES(?, ?, datetime('now'))"),
                   username, generate_password_hash(password))
    except ValueError:
        if db.execute("SELECT COUNT(*) AS cnt FROM users WHERE username=?", username)[0]["cnt"] > 0:
            flash('Username already exists', 'danger')
        return render_template("auth/register.html"), 400

    user = db.execute("SELECT * FROM users WHERE username=?", username)[0]
    session["user_id"] = user["id"]
    session["username"] = user["username"]

    flash(('Account successfully created! Don\'t forget your password'), 'success')
    logger.info((f"User {username} has created an account "
                 f"on IP {request.remote_addr}"), extra={"section": "auth"})
    return redirect("/")


@app.route("/squares/create", methods=["GET", "POST"])
@login_required
def create_square():
    hotkey1, hotkey2, hotkey3, hotkey4, hotkey5, hotkey6 = gethotkeys()
    if request.method == "GET":
        return render_template("square/create.html", hotkey1=hotkey1, hotkey2=hotkey2, hotkey3=hotkey3, hotkey4=hotkey4, hotkey5=hotkey5, hotkey6=hotkey6)
    
    # Reached via POST
    id = generate_sq_id()
    square_name = request.form.get("square_name")
    preview = request.form.get("preview")
    description = request.form.get("description")
    privacy = request.form.get("privacy")
    meeting_code = request.form.get("meeting_code")
    image_type = int(request.form.get("image_type"))
    topic = request.form.get("topic")
    
    if not square_name or not description or not preview or not meeting_code:
        flash('Please enter all required fields', 'danger')
        return render_template("square/create.html", hotkey1=hotkey1, hotkey2=hotkey2, hotkey3=hotkey3, hotkey4=hotkey4, hotkey5=hotkey5, hotkey6=hotkey6), 400

    # Ensure a square with this title does not exist already
    if db.execute("SELECT COUNT(*) AS cnt FROM squares WHERE name=?", square_name)[0]["cnt"] > 0:
        flash('Square name already exists', 'danger')
        return render_template("square/create.html", hotkey1=hotkey1, hotkey2=hotkey2, hotkey3=hotkey3, hotkey4=hotkey4, hotkey5=hotkey5, hotkey6=hotkey6), 400
    
    # Add to squares table
    db.execute(("INSERT INTO squares(id, name, creator, create_date, preview, description, public, meeting_code, image_type, topic) "
                "VALUES(?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?)"),
               id, square_name, session['user_id'], preview, description, bool(int(privacy)), meeting_code, image_type, topic)
    
    db.execute("INSERT INTO square_members(square_id, user_id, join_date) VALUES(?, ?, datetime('now'))", id, session["user_id"])
    db.execute("UPDATE users SET squares_created = squares_created + 1 WHERE id = ?", session["user_id"])
    db.execute("INSERT INTO square_join_log(user_id, square_id, square_title, square_creator_username) VALUES(?, ?, ?, ?)", (session["user_id"], id, square_name, session["username"]))
    
    logger.info((f"User #{session['user_id']} ({session['username']}) created "
                    f"square {id}"), extra={"section": "square"})
    flash('Square created successfully!', 'success')
    return redirect("/square/" + id)


@app.route("/squares")
def squares():
    hotkey1, hotkey2, hotkey3, hotkey4, hotkey5, hotkey6 = gethotkeys()
    title = request.args.get("title")
    if not title:
        title = None

    query = """
        SELECT s.*, 
               COUNT(sm.square_id) AS in_square
        FROM squares s
        LEFT JOIN square_members sm ON s.id = sm.square_id AND sm.user_id = ?
        WHERE (s.public = 1 OR s.creator = ? OR sm.user_id = ?)
    """
    args = [session.get("user_id", -1), session.get("user_id", -1), session.get("user_id", -1)]

    if title:
        query += " AND (LOWER(s.name) LIKE ? OR LOWER(s.topic) LIKE ? OR LOWER(s.description) LIKE ? OR LOWER(s.preview) LIKE ?)"
        title_like = '%' + title.lower() + '%'
        args.extend([title_like, title_like, title_like, title_like])

    query += " GROUP BY s.id ORDER BY s.name ASC"

    data = db.execute(query, *args)
    
    if not data:
        flash("No such squares found.", "warning")
        return redirect("/")

    # 'in_square' is already calculated in the query, so no need for another loop
    return render_template("square/squares.html", squares=data, hotkey1=hotkey1, hotkey2=hotkey2, hotkey3=hotkey3, hotkey4=hotkey4, hotkey5=hotkey5, hotkey6=hotkey6)


@app.route("/changepassword", methods=["POST"])
@login_required
def change_password():
    old_password = request.form.get("old_password")
    new_password = request.form.get("new_password")
    confirmation = request.form.get("confirm_new_password")

    current_pwd_hash = db.execute("SELECT password FROM users WHERE id = ?", session["user_id"])[0]["password"]
    if not check_password_hash(current_pwd_hash, old_password):
        flash("Current password is incorrect", "danger")
        return redirect("/profile")
    elif new_password != confirmation:
        flash("Passwords do not match", "danger")
        return redirect("/profile")
    elif not new_password or len(new_password) < 8:
        flash("Password must be at least 8 characters", "danger")
        return redirect("/profile")
    
    db.execute("UPDATE users SET password = ? WHERE id = ?", generate_password_hash(new_password), session["user_id"])
    
    flash("Password changed successfully", "success")
    return redirect("/profile")


@app.route("/edithotkeys", methods=["POST"])
@login_required
def edit_hotkeys():
    hotkey1 = request.form.get("hotkey1")
    hotkey2 = request.form.get("hotkey2")
    hotkey3 = request.form.get("hotkey3")
    hotkey4 = request.form.get("hotkey4")
    hotkey5 = request.form.get("hotkey5")
    hotkey6 = request.form.get("hotkey6")

    existing_hotkeys = db.execute("SELECT * FROM hotkeys WHERE user_id = ?", session["user_id"])
    
    if not existing_hotkeys:
        db.execute("INSERT INTO hotkeys(user_id, hotkey1, hotkey2, hotkey3, hotkey4, hotkey5, hotkey6) VALUES(?, ?, ?, ?, ?, ?, ?)", session["user_id"], hotkey1, hotkey2, hotkey3, hotkey4, hotkey5, hotkey6)
    else:
        db.execute("UPDATE hotkeys SET hotkey1 = ?, hotkey2 = ?, hotkey3 = ?, hotkey4 = ?, hotkey5 = ?, hotkey6 = ? WHERE user_id = ?", (hotkey1, hotkey2, hotkey3, hotkey4, hotkey5, hotkey6, session["user_id"]))
    
    flash("Hotkeys updated successfully", "success")
    return redirect("/profile")

# Error handling
def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    if request.path.startswith('/api/'):
        if e.code == 500:
            return json_fail("Internal Server Error", 500)
        return json_fail(e.description, e.code)
    if e.code == 404:
        return render_template("error/404.html"), 404
    if e.code == 500:
        return render_template("error/500.html"), 500
    return render_template("error/generic.html", e=e), e.code

for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


@app.after_request
def security_policies(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == "__main__":
    app.run(debug=True, port=5000)
    
