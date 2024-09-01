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
    popular_squares = db.execute("SELECT * FROM squares ORDER BY members DESC LIMIT 3")
    return render_template("index.html", popular_squares=popular_squares)

@app.route("/square")
def square():
    return render_template("square.html")

@app.route("/profile")
def profile():
    data = db.execute("SELECT * FROM users WHERE id = :uid", uid=session["user_id"])[0]
    return render_template("profile.html", data=data)

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
    
    db.execute("INSERT INTO activity_log(user_id, action, timestamp) VALUES(?, ?, datetime('now'))", session["user_id"], "Logged in.")

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
    db.execute("INSERT INTO activity_log(user_id, action, timestamp) VALUES(?, ?, datetime('now'))", session["user_id"], "logout")
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
    
    db.execute("INSERT INTO activity_log(user_id, action, timestamp) VALUES(?, ?, datetime('now'))", db.execute("SELECT id FROM users WHERE username=?", username)[0]["id"], "Joined StudySquare")

    flash(('Account successfully created! Don\'t forget your password'), 'success')
    logger.info((f"User {username} has created an account "
                 f"on IP {request.remote_addr}"), extra={"section": "auth"})
    return redirect("/")


@app.route("/squares/create", methods=["GET", "POST"])
@login_required
def create_square():
    if request.method == "GET":
        return render_template("square/create.html")
    
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
        return render_template("square/create.html"), 400

    # Ensure a square with this title does not exist already
    if db.execute("SELECT COUNT(*) AS cnt FROM squares WHERE name=?", square_name)[0]["cnt"] > 0:
        flash('Square name already exists', 'danger')
        return render_template("square/create.html"), 400
    
    # Add to squares table
    db.execute(("INSERT INTO squares(id, name, creator, create_date, preview, description, public, meeting_code, image_type, topic) "
                "VALUES(?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?)"),
               id, square_name, session['user_id'], preview, description, bool(int(privacy)), meeting_code, image_type, topic)
    
    db.execute("INSERT INTO square_members(square_id, user_id, join_date) VALUES(?, ?, datetime('now'))", id, session["user_id"])
    
    db.execute("INSERT INTO activity_log(user_id, action, timestamp) VALUES(?, ?, datetime('now'))", session["user_id"], f"Created square \"{square_name}\" ({id}).")
    
    logger.info((f"User #{session['user_id']} ({session['username']}) created "
                    f"square {id}"), extra={"section": "square"})
    flash('Square created successfully!', 'success')
    return redirect("/square/" + id)


@app.route("/squares")
def squares():
    title = request.args.get("title")
    if not title:
        title = None
    
    query = "SELECT * FROM squares"
    modifier = " WHERE ((public = 1 OR creator = ?)"
    args = [session["user_id"]] if session.get("user_id") else [-1]
    if title:
        modifier += " AND (LOWER(name) LIKE ?)"
        args.append('%' + title.lower() + '%')
        if session.get("user_id"):
            db.execute("INSERT INTO searches(user_id, search) VALUES(?, ?)", session['user_id'], title)
    modifier += ") ORDER BY name ASC"
    query += modifier
    data = db.execute(query, *args)
    
    if not data:
        flash("No such squares found.", "warning")
        return redirect("/")
    
    for row in data:
        row['inside_square'] = db.execute("SELECT COUNT(*) AS cnt FROM square_members WHERE square_id = :sid AND user_id = :uid", sid=row['id'], uid=session.get("user_id", -1))[0]["cnt"]
    
    return render_template("square/squares.html", squares=data)


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
    
