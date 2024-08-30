import logging
import os
import requests
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from io import BytesIO
import random
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
from middlewares import ProxyFix
import re
from datetime import datetime, timedelta

from webui import WebUI

#from fuzzywuzzy import fuzz

app = Flask(__name__)

try:
    app.config.from_object('settings')
except Exception as e:
    sys.stderr.write(str(e))
    app.config.from_object('default_settings')
app.jinja_env.globals.update(check_perm=check_perm)

# Configure logging
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

# Configure flask-mail
mail = Mail(app)

# Configure flask-WTF
csrf = CSRFProtect(app)
csrf.init_app(app)

# Load API
from views.api import api as view_api  # noqa
from views.contest import api as view_contest  # noqa
from views.course import api as view_course # noqa
from views.problem import api as view_problem  # noqa
from views.admin import api as view_admin  # noqa
from views.organization import api as view_organization  # noqa
app.register_blueprint(view_api, url_prefix="/api")
app.register_blueprint(view_contest, url_prefix="/contest")
app.register_blueprint(view_course, url_prefix="/course")
app.register_blueprint(view_problem, url_prefix="/problem")
app.register_blueprint(view_admin, url_prefix="/admin")
app.register_blueprint(view_organization, url_prefix="/organization")

# Validate settings
if not app.config['TESTING']:
    with app.app_context():
        try:
            send_email('TOPSOJ Email Setup', app.config['MAIL_DEFAULT_SENDER'],
                       [app.config['MAIL_DEFAULT_SENDER']],
                       ('This email tests your configured email settings for TOPSOJ. '
                        '<b>Please note that HTML is supported.</b> '
                        'Please ignore this email.'))
        except Exception as error:
            logging.warning("Settings validation: Email credentials invalid.")
            logging.warning(str(error))
        else:
            logging.debug("Settings validation: Email credentials valid.")
        if app.config['USE_CAPTCHA']:
            captcha = requests.post('https://hcaptcha.com/siteverify', data={
                'secret': app.config['HCAPTCHA_SECRET'],
                'response': "placeholder",
                'sitekey': app.config['HCAPTCHA_SITE']
            })
            if len(captcha.json()["error-codes"]) == 1:  # only error is invalid input
                logging.debug("Settings validation: hCaptcha credentials valid.")
            else:
                logging.warning("Settings validation: hCaptcha credentials invalid.")
        if app.config['USE_HOMEPAGE']:
            if os.path.isfile(app.config['HOMEPAGE_FILE']):
                logging.debug("Settings validation: Homepage file exists.")
            else:
                logging.warning("Settings validation: Homepage file nonexistent.")


@app.before_request
def check_for_maintenance():
    # Don't prevent login or getting assets
    if request.path == '/login' or request.path.startswith('/assets/'):
        return

    maintenance_mode = bool(os.path.exists('maintenance_mode'))
    if maintenance_mode:
        if request.path.startswith('/api/'):
            if not check_perm(["ADMIN", "SUPERADMIN", "SITE_TESTER"], api_get_perms()):
                return json_fail("The site is currently undergoing maintenance", 503)
            else:
                return

        # Prevent Internal Server error if session only contains CSRF token
        if not check_perm(["ADMIN", "SUPERADMIN", "SITE_TESTER"]):
            return render_template("error/maintenance.html"), 503
        else:
            flash("Maintenance mode is enabled", "maintenance")

@app.before_request
def check_for_testing():
    if check_perm(["SITE_TESTER"]):
        flash("You are in site testing mode, some features may be broken.", "testing")

@app.before_request
def check_for_team():
    if session.get("username"):
        team_account = db.execute("SELECT team_account AS team FROM users WHERE username=?", session.get("username"))
        if team_account and team_account[0]['team']:
            flash("You are using a team account, most features are disabled.", "team")

@app.route("/")
def index():
    # Redirect to login page if homepage setting disabled
    if not app.config["USE_HOMEPAGE"] and not session.get("username"):
        return redirect("/login")

    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 10

    data = db.execute(
        "SELECT * FROM announcements ORDER BY id DESC LIMIT 10 OFFSET ?", page)
    length = db.execute("SELECT COUNT(*) AS cnt FROM announcements")[0]["cnt"]
    contests_happening_soon = db.execute(
        "SELECT * FROM contests WHERE start > datetime('now') AND start <= datetime('now', '+3 days') ORDER BY start ASC")
    points_all_time = db.execute("SELECT username, rating, admin, total_points FROM users ORDER BY total_points DESC LIMIT 3")
    points_last_week = db.execute("""SELECT u.username, u.rating, SUM(p.point_value) AS total_points
                         FROM users u
                         JOIN (SELECT DISTINCT problem_id, user_id
                             FROM submissions
                             WHERE correct = 1
                             AND date >= datetime('now', '-7 days')) s ON u.id = s.user_id
                         JOIN problems p ON s.problem_id = p.id
                         GROUP BY u.username
                         ORDER BY total_points DESC
                         LIMIT 3;
                         """)
    # select all current ongoing contests
    is_ongoing_contest = False
    if check_perm(["ADMIN", "SUPERADMIN"]):
        is_ongoing_contest = len(db.execute(
            ("SELECT id AS n FROM contests WHERE end > datetime('now') AND "
            "start <= datetime('now') ORDER BY end DESC")))
    else:
        org_ids = [row["org_id"] for row in db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session.get("user_id", 0))]
        is_ongoing_contest = len(db.execute(
            ("SELECT id AS n FROM contests WHERE end > datetime('now') AND "
            "start <= datetime('now') AND (private = 0 OR private_org IN (:orgs)) ORDER BY end DESC"),
            orgs=org_ids))
    recent_contests = db.execute(
        ("SELECT * FROM contests WHERE end < datetime('now') ORDER BY end DESC LIMIT 3"))
    if not session.get("username"):

        template = read_file(app.config['HOMEPAGE_FILE'])
        template_type = int(template[20])
        return render_template(f"homepage.html")
    else:
        return render_template("index.html", data=data, length=-(-length // 10), points_all_time=points_all_time, points_last_week=points_last_week, recent_contests=recent_contests, is_ongoing_contest=is_ongoing_contest, contests_happening_soon=contests_happening_soon)


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/docs")
def docs():
    return redirect(app.config['DOCS_URL'])


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/assets/<path:filename>")
def get_asset(filename):
    resp = send_from_directory("assets/", filename)
    resp.headers['Cache-Control'] = 'max-age=604800, must-revalidate'
    return resp


@app.route("/dl/<problem_id>.zip")
@login_required
def dl_file(problem_id):
    problem = db.execute("SELECT * FROM problems WHERE id=?", problem_id)
    if len(problem) == 0 or (problem[0]["draft"] and not
                             check_perm(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])):
        return abort(404)
    return send_from_directory("dl/", f"{problem_id}.zip", as_attachment=True)


@app.route("/dl/<contest_id>/<problem_id>.zip")
@login_required
def dl_contest(contest_id, problem_id):
    contest = db.execute("SELECT * FROM contests WHERE id=?", contest_id)
    if len(contest) == 0:
        return abort(404)
    # Ensure contest started or user is admin
    start = datetime.strptime(contest[0]["start"], "%Y-%m-%d %H:%M:%S")
    if datetime.now(pytz.UTC) < pytz.utc.localize(start) and not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"]):
        return abort(404)
    problem = db.execute(("SELECT * FROM contest_problems WHERE contest_id=? "
                          "AND problem_id=?"), contest_id, problem_id)
    if len(problem) == 0 or (problem[0]["draft"] and
                             not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])):
        return abort(404)
    return send_from_directory("dl/", f"{contest_id}/{problem_id}.zip",
                               as_attachment=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget user id
    session.clear()
    session.permanent = True  # Have to re-set this after clear

    if request.method == "GET":
        return render_template("auth/login.html", site_key=app.config['HCAPTCHA_SITE'])

    # Reached using POST

    # Ensure username and password were submitted
    if not request.form.get("username") or not request.form.get("password"):
        flash('Username and password cannot be blank', 'danger')
        return render_template("auth/login.html",
                               site_key=app.config['HCAPTCHA_SITE']), 400

    # Ensure captcha is valid
    if app.config['USE_CAPTCHA']:
        if not check_captcha(app.config['HCAPTCHA_SECRET'],
                             request.form.get('h-captcha-response'),
                             app.config['HCAPTCHA_SITE']):
            return render_template("auth/login.html",
                                   site_key=app.config['HCAPTCHA_SITE']), 400

    # Ensure user is allowed to log in
    rows = db.execute("SELECT * FROM users WHERE username=:username",
                      username=request.form.get("username"))
    code = login_chk(rows)
    if code != 0:
        return render_template("auth/login.html",
                               site_key=app.config['HCAPTCHA_SITE']), code

    # implement 2fa verification via email
    if rows[0]["twofa"]:
        email = rows[0]["email"]
        token = create_jwt({'email': email}, app.config['SECRET_KEY'])
        text = render_template('email/confirm_login.html',
                               username=request.form.get('username'), token=token)

        if not app.config['TESTING']:
            send_email('TopsOJ Login Confirmation',
                       app.config['MAIL_DEFAULT_SENDER'], [email], text)

        flash(('A login confirmation email has been sent to the email address you '
               'provided. Be sure to check your spam folder!'), 'success')
        logger.info((f"User #{rows[0]['id']} ({rows[0]['username']}) initiated 2FA "
                     f"on IP {request.remote_addr}"), extra={"section": "auth"})
        return render_template("auth/login.html", site_key=app.config['HCAPTCHA_SITE'])

    perms = db.execute("SELECT perm_id FROM user_perms WHERE user_id=?", rows[0]["id"])

    # Remember which user has logged in
    session["user_id"] = rows[0]["id"]
    session["username"] = rows[0]["username"]
    session["perms"] = set([x["perm_id"] for x in perms])

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
        return render_template("auth/register.html", site_key=app.config['HCAPTCHA_SITE'])

    # Reached using POST

    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    email = request.form.get("email")

    code = register_chk(username, password, confirmation, email)
    if code:
        return render_template("auth/register.html",
                               site_key=app.config['HCAPTCHA_SITE']), code
    email = email.lower()

    if password == '12345678':
        flash("Please choose a password better than that.", "danger")
        return render_template("auth/register.html",
                               site_key=app.config['HCAPTCHA_SITE']), 400
  
    # Ensure captcha is valid
    if app.config['USE_CAPTCHA']:
        if not check_captcha(app.config['HCAPTCHA_SECRET'],
                             request.form.get('h-captcha-response'),
                             app.config['HCAPTCHA_SITE']):
            return render_template("auth/register.html",
                                   site_key=app.config['HCAPTCHA_SITE']), 400

    # Create entry & check for duplicate
    try:
        db.execute(("INSERT INTO users(username, password, email, join_date) "
                    "VALUES(?, ?, ?, datetime('now'))"),
                   username, generate_password_hash(password), email)
    except ValueError:
        if db.execute("SELECT COUNT(*) AS cnt FROM users WHERE username=?", username)[0]["cnt"] > 0:
            flash('Username already exists', 'danger')
        elif db.execute("SELECT COUNT(*) AS cnt FROM users WHERE email=?", email)[0]["cnt"] > 0:
            flash('Email already exists', 'danger')
        return render_template("auth/register.html",
                               site_key=app.config['HCAPTCHA_SITE']), 400

    if not app.config['TESTING']:
        token = create_jwt({'email': email}, app.config['SECRET_KEY'])
        text = render_template('email/confirm_account.html',
                               username=username, token=token)
        send_email('TopsOJ Account Confirmation',
                   app.config['MAIL_DEFAULT_SENDER'], [email], text)

    flash(('An account creation confirmation email has been sent to the email address '
           'you provided. Be sure to check your spam folder!'), 'success')
    logger.info((f"User {username} ({email}) has initiated a registration request "
                 f"on IP {request.remote_addr}"), extra={"section": "auth"})
    return render_template("auth/register.html", site_key=app.config['HCAPTCHA_SITE'])


@app.route('/confirmregister/<token>')
def confirm_register(token):
    try:
        token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        sys.stderr.write(str(e))
        token = 0
    if not token:
        flash("Email verification link invalid", "danger")
        return redirect("/register")
    if datetime.strptime(token["expiration"], "%Y-%m-%dT%H:%M:%S.%f%z") < datetime.now(pytz.UTC):
        db.execute(
            "DELETE FROM users WHERE verified=0 and email=:email", email=token['email'])
        flash("Email verification link expired. Please register again using the same email.",  # noqa
              "danger")
        return redirect("/register")

    r = db.execute("UPDATE users SET verified=1 WHERE email=? AND verified=0", token['email'])
    if r == 0:
        flash("Email verification link invalid", "danger")
        return redirect("/register")

    # Log user in
    user = db.execute(
        "SELECT * FROM users WHERE email=?", token['email'])[0]
    perms = db.execute("SELECT * FROM user_perms WHERE user_id=?", user["id"])
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["perms"] = set([x["perm_id"] for x in perms])

    os.makedirs("metadata/users/" + str(session["user_id"]), exist_ok = True)
    open('metadata/users/' + str(session["user_id"]) + '/profile.md', 'w').close()
    open('metadata/users/' + str(session["user_id"]) + '/profile.html', 'w').close()

    logger.info((f"User #{session['user_id']} ({session['username']}) has successfully "
                 f"registered on IP {request.remote_addr}"), extra={"section": "auth"})
    return redirect("/problem/helloworld")

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

@app.route("/settings/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    if request.method == "GET":
        return render_template("auth/changepassword.html")

    # Reached using POST

    old_password = request.form.get("password")
    new_password = request.form.get("newPassword")
    confirmation = request.form.get("confirmation")

    # Ensure passwords were submitted and they match
    if not old_password:
        flash('Password cannot be blank', 'danger')
        return render_template("auth/changepassword.html"), 400
    if not new_password or len(new_password) < 8:
        flash('New password must be at least 8 characters', 'danger')
        return render_template("auth/changepassword.html"), 400
    if not confirmation or new_password != confirmation:
        flash('Passwords do not match', 'danger')
        return render_template("auth/changepassword.html"), 400

    # Ensure username exists and password is correct
    rows = db.execute("SELECT * FROM users WHERE id=:id", id=session["user_id"])
    if len(rows) != 1 or not check_password_hash(rows[0]["password"], old_password):
        flash('Incorrect password', 'danger')
        return render_template("auth/changepassword.html"), 401

    db.execute("UPDATE users SET password=:new WHERE id=:id",
               new=generate_password_hash(new_password), id=session["user_id"])

    logger.info((f"User #{session['user_id']} ({session['username']}) has changed "
                 "their password"), extra={"section": "auth"})
    flash("Password change successful", "success")
    return redirect("/settings")

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

if __name__ == "__main__":
    app.run(debug=True, port=5000)
    
