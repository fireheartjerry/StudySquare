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
ui = WebUI(app, debug=True)
try:
    app.config.from_object('settings')
except Exception as e:
    sys.stderr.write(str(e))
    app.config.from_object('default_settings')
app.jinja_env.globals['CLUB_NAME'] = app.config['CLUB_NAME']
app.jinja_env.globals['USE_CAPTCHA'] = app.config['USE_CAPTCHA']
app.jinja_env.globals.update(check_perm=check_perm)

# Add middlewares
if app.config["USE_X_FORWARDED_FOR"]:
    app.wsgi_app = ProxyFix(app.wsgi_app)

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


@app.route('/cancelregister/<token>')
def cancel_register(token):
    try:
        token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        sys.stderr.write(str(e))
        token = 0
    r = db.execute("DELETE FROM users WHERE verified=0 and email=?", token['email'])
    if r == 0:
        flash("Email verification link invalid", "danger")
        return redirect("/register")
    db.execute(
        "DELETE FROM users WHERE verified=0 and email=:email", email=token['email'])
    flash("Your registration has been successfully removed from our database.", "success")
    logger.info((f"User with email {token['email']} has cancelled "
                 f"registration on IP {request.remote_addr}"), extra={"section": "auth"})
    return redirect("/register")


@app.route('/confirmlogin/<token>')
def confirm_login(token):
    try:
        token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        sys.stderr.write(str(e))
        token = 0

    if not token:
        flash('Invalid login verification link', 'danger')
        return render_template("auth/login.html",
                               site_key=app.config['HCAPTCHA_SITE']), 400
    if datetime.strptime(token["expiration"], "%Y-%m-%dT%H:%M:%S.%f%z") < datetime.now(pytz.UTC):
        flash('Login verification link expired; Please re-login', 'danger')
        return render_template("auth/login.html",
                               site_key=app.config['HCAPTCHA_SITE']), 401

    # Log user in
    user = db.execute("SELECT * FROM users WHERE email=:email", email=token['email'])[0]
    perms = db.execute("SELECT * FROM user_perms WHERE user_id=?", user["id"])

    # Remember which user has logged in
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["perms"] = set([x["perm_id"] for x in perms])

    logger.info((f"User #{session['user_id']} ({session['username']}) logged in via 2FA "
                 f"on IP {request.remote_addr}"), extra={"section": "auth"})
    return redirect("/")


@app.route("/settings")
@login_required
def settings():
    highlight_tags = bool(request.args.get("highlight_tags"))
    show_tags = db.execute("SELECT show_global_tags FROM users WHERE id=:uid", uid=session["user_id"])[0]['show_global_tags']
    timed_mode = db.execute("SELECT timed_mode FROM users WHERE id=:uid", uid=session["user_id"])[0]['timed_mode']
    return render_template("settings.html", show_tags=show_tags, highlight_tags=highlight_tags, timed_mode=timed_mode)


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


@app.route("/settings/toggle2fa", methods=["GET", "POST"])
@login_required
def toggle2fa():
    user = db.execute("SELECT * FROM users WHERE id=:id", id=session["user_id"])[0]

    if request.method == "GET":
        return render_template("toggle2fa.html", status=user["twofa"])

    # Reached via POST

    password = request.form.get("password")

    if not password or not check_password_hash(user['password'], password):
        flash('Incorrect password', 'danger')
        return render_template("toggle2fa.html", status=user["twofa"]), 401

    msg = "disabled" if user["twofa"] else "enabled"
    if user["twofa"]:
        db.execute("UPDATE users SET twofa=0 WHERE id=:id", id=session["user_id"])
    else:
        db.execute("UPDATE users SET twofa=1 WHERE id=:id", id=session["user_id"])
    flash("2FA successfully " + msg, "success")
    logger.info(f"User #{session['user_id']} ({session['username']}) {msg} 2FA",
                extra={"section": "auth"})
    return redirect("/settings")

@app.route("/settings/toggletags")
@login_required
def toggletags():
    show_tags = db.execute("SELECT show_global_tags FROM users WHERE id=:uid", uid=session["user_id"])[0]['show_global_tags']
    db.execute("UPDATE users SET show_global_tags=:new_show_tags WHERE id=:uid", new_show_tags=not show_tags,uid=session["user_id"])
    flash("Successfully changed tag showing setting.", "success")
    return redirect("/settings")

@app.route("/settings/toggletimed")
@login_required
def toggletimed():
    timed_mode = db.execute("SELECT timed_mode FROM users WHERE id=:uid", uid=session["user_id"])[0]['timed_mode']
    db.execute("UPDATE users SET timed_mode=:new_timed_mode WHERE id=:uid", new_timed_mode=not timed_mode,uid=session["user_id"])
    flash("Successfully changed timed mode setting.", "success")
    return redirect("/settings")

@app.route("/forgotpassword", methods=["GET", "POST"])
def forgotpassword():
    if request.method == "GET":
        return render_template("auth/forgotpassword.html",
                               site_key=app.config['HCAPTCHA_SITE'])

    # Reached via POST

    email = request.form.get("email")
    if not email:
        flash('Email cannot be blank', 'danger')
        return render_template("auth/forgotpassword.html"), 400

    # Ensure captcha is valid
    if app.config['USE_CAPTCHA']:
        if not check_captcha(app.config['HCAPTCHA_SECRET'],
                             request.form.get('h-captcha-response'),
                             app.config['HCAPTCHA_SITE']):
            return render_template("auth/forgotpassword.html",
                                   site_key=app.config['HCAPTCHA_SITE']), 400

    rows = db.execute("SELECT * FROM users WHERE email = :email",
                      email=request.form.get("email"))

    if len(rows) == 1:
        token = create_jwt({'user_id': rows[0]["id"]}, app.config['SECRET_KEY'])
        text = render_template('email/reset_password.html',
                               username=rows[0]["username"], token=token)
        logger.info((f"User #{rows[0]['id']} ({rows[0]['username']}) initiated a "
                     f"password reset from IP {request.remote_addr}"),
                    extra={"section": "auth"})
        if not app.config['TESTING']:
            send_email('TopsOJ Password Reset',
                       app.config['MAIL_DEFAULT_SENDER'], [email], text)

    flash(('If there is an account associated with that email, a password reset email '
           'has been sent'), 'success')
    return render_template("auth/forgotpassword.html")


@app.route('/resetpassword/<token>', methods=['GET', 'POST'])
def reset_password_user(token):
    try:
        token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = token['user_id']
    except Exception as e:
        sys.stderr.write(str(e))
        user_id = 0
    if not user_id or datetime.strptime(token["expiration"], "%Y-%m-%dT%H:%M:%S.%f%z") < datetime.now(pytz.UTC):
        flash('Password reset link expired/invalid', 'danger')
        return redirect('/forgotpassword')

    if request.method == "GET":
        return render_template('auth/resetpassword.html')

    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    if not password or len(password) < 8:
        flash('New password must be at least 8 characters', 'danger')
        return render_template("auth/resetpassword.html"), 400
    if not confirmation or password != confirmation:
        flash('Passwords do not match', 'danger')
        return render_template("auth/resetpassword.html"), 400

    db.execute("UPDATE users SET password=:new WHERE id=:id",
               new=generate_password_hash(password), id=user_id)

    logger.info((f"User #{user_id} completed a password reset from "
                 f"IP {request.remote_addr}"), extra={"section": "auth"})
    flash('Your password has been successfully reset', 'success')
    return redirect("/login")


@app.route("/contests")
def contests():
    past = db.execute(
        "SELECT * FROM contests WHERE end < datetime('now') ORDER BY end DESC")
    current = db.execute(
        ("SELECT * FROM contests WHERE end > datetime('now') AND "
         "start <= datetime('now') ORDER BY end DESC"))
    future = db.execute(
        "SELECT * FROM contests WHERE start > datetime('now') ORDER BY start DESC")

    organizations = {row["org_id"] for row in db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session.get("user_id", 0))}
    if not check_perm(["ADMIN", "SUPERADMIN"]):
        past = [contest for contest in past if not (contest['private'] and contest['private_org'] not in organizations)]
        current = [contest for contest in current if not (contest['private'] and contest['private_org'] not in organizations)]
        future = [contest for contest in future if not (contest['private'] and contest['private_org'] not in organizations)]

    for contest in past:
        if contest['private']:
            contest['organization_name'] = db.execute("SELECT name FROM organizations WHERE id=:org_id", org_id=contest['private_org'])[0]['name']

    for contest in current:
        if contest['private']:
            contest['organization_name'] = db.execute("SELECT name FROM organizations WHERE id=:org_id", org_id=contest['private_org'])[0]['name']

    for contest in future:
        if contest['private']:
            contest['organization_name'] = db.execute("SELECT name FROM organizations WHERE id=:org_id", org_id=contest['private_org'])[0]['name']

    for contest in current:
        contest['first_time'] = False
        user_info = db.execute("SELECT end_time FROM contest_users WHERE contest_id=:cid AND user_id=:uid", cid=contest['id'], uid=session['user_id']) if session.get("user_id") else {}
        if not user_info:
            contest['first_time'] = True
        else:
            contest['window_ended'] = None
            if contest['use_window_timer']:
                contest['window_ended'] = datetime.now(pytz.UTC) > pytz.utc.localize(datetime.strptime(user_info[0]['end_time'], "%Y-%m-%d %H:%M:%S"))
    return render_template("contest/contests.html",
                           past=past, current=current, future=future)


@app.route("/contests/create", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def create_contest():
    if request.method == "GET":
        return render_template("contest/create.html")

    # Reached using POST

    contest_id = request.form.get("contest_id")

    # Ensure contest ID is valid
    if not contest_id or not verify_text(contest_id) or contest_id == "None":
        flash('Invalid contest ID', 'danger')
        return render_template("contest/create.html"), 400

    contest_name = request.form.get("contest_name")
    scoreboard_key = request.form.get("scoreboard_key")

    # Ensure contest doesn't already exist
    check = db.execute("SELECT * FROM contests WHERE id=:cid OR name=:contest_name",
                       cid=contest_id, contest_name=contest_name)
    if len(check) != 0:
        flash('A contest with that name or ID already exists', 'danger')
        return render_template("contest/create.html"), 409

    start = request.form.get("start")
    end = request.form.get("end")

    # Ensure start and end dates are valid
    check_start = datetime.strptime(start, "%Y-%m-%dT%H:%M:%S.%fZ")
    check_end = datetime.strptime(end, "%Y-%m-%dT%H:%M:%S.%fZ")
    if pytz.utc.localize(check_end) < pytz.utc.localize(check_start):
        flash('Contest cannot end before it starts!', 'danger')
        return render_template("contest/create.html"), 400

    description_md = request.form.get("description_md").replace('\r', '')
    description_html = request.form.get("description_html").replace('\r', '')
    scoreboard_visible = bool(request.form.get("scoreboard_visible"))
    style = request.form.get("style")
    use_window_timer = bool(request.form.get("use_window_timer"))
    rated = bool(request.form.get("rated"))
    window_time = -1
    submission_limit = int(request.form.get("submission_limit")) if style not in ["amc", "aime"] else 1
    show_verdict = bool(request.form.get("show_verdicts"))
    team = bool(request.form.get("team"))
    export_category = request.form.get("export_category")
    weight = float(request.form.get("weight"))
    
    if use_window_timer:
        window_time = request.form.get("window_time")

    if submission_limit == 0 or submission_limit < -1:
        flash('Submission limit must be -1 or a positive integer', 'danger')
        return render_template("contest/create.html"), 400

    if style not in ["standard", "guts", "amc", "aime"]:
        flash('Invalid contest style', 'danger')
        return render_template("contest/create.html"), 400

    if style == "guts" and submission_limit != 1:
        submission_limit = 1

    if not description_md:
        flash('Description cannot be empty', 'danger')
        return render_template("contest/create.html"), 400
    
    if not (0 <= weight <= 1):
        flash('Contest weight must be between 0 and 1, inclusive.', 'danger')
        return render_template("contest/create.html"), 400

    db.execute(("INSERT INTO contests (id, name, start, end, scoreboard_visible, scoreboard_key, style, default_submission_limit, use_window_timer, window_time_seconds, team_contest, show_verdict, export_category, rated, weight)"
         " VALUES (?, ?, datetime(?), datetime(?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
        contest_id, contest_name, start, end, scoreboard_visible, scoreboard_key, style, submission_limit, use_window_timer, window_time, team, show_verdict, export_category, rated, weight)

    os.makedirs('metadata/contests/' + contest_id)
    write_file('metadata/contests/' + contest_id + '/description.md', description_md)
    write_file('metadata/contests/' + contest_id + '/description.html', description_html)

    logger.info((f"User #{session['user_id']} ({session['username']}) created "
                 f"contest {contest_id}"), extra={"section": "contest"})
    flash('Contest successfully created', 'success')
    return redirect("/contest/" + contest_id)

@app.route("/mathgym")
def math_gym():
    team_account = db.execute("SELECT team_account AS team FROM users WHERE id=:id", id=session["user_id"])[0]['team'] if session.get("user_id") else False
    if team_account:
        flash("You are using a team account, so you aren't allowed to access the math gym!", "danger")
        return redirect("/")
    mcp_raw = db.execute("SELECT id FROM problems WHERE id LIKE 'potd%' AND draft=0 ORDER BY id;")
    all_potds = [val['id'] for val in mcp_raw]
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
    return render_template("gym/gym.html", potd_count=len(all_potds), most_recent_potd=all_potds[-1], is_ongoing_contest=is_ongoing_contest)

def get_problem_name(problem_id):
    name=db.execute("SELECT name FROM problems WHERE id = :problem_id",problem_id=problem_id)

    if name:
        return name[0]['name']
    else:
        return None

@app.route("/mathgym/potdrankings")
def potd_rankings():
    user_info = db.execute("SELECT user_id FROM problem_solved WHERE problem_id LIKE 'potd%' GROUP BY user_id ORDER BY COUNT(*) DESC")
    result_list = []
    for user_dict in user_info:
        user_id = user_dict['user_id']
        points = db.execute(("SELECT SUM(CASE WHEN problem_id LIKE 'potd%' AND "
                             "(problem_id LIKE '%normal' OR problem_id GLOB '*[0-9]') "
                             "THEN 1 ELSE 0 END) AS one_pointers, SUM(CASE WHEN "
                             "problem_id LIKE 'potd%' AND problem_id LIKE '%challenge' "
                             "THEN 1 ELSE 0 END) AS two_pointers FROM problem_solved "
                             "WHERE user_id=:uid"), uid=user_id)[0]
        one_pointers = points['one_pointers']
        two_pointers = points['two_pointers']
        query = ("SELECT u.username, COALESCE(MAX(s.date), '') AS closest "
                "FROM users u "
                "LEFT JOIN submissions s ON u.id = s.user_id AND s.problem_id LIKE 'potd%' "
                "WHERE u.id = :uid")

        result = db.execute(query, uid=user_id)[0]

        result_dict = {
            'username': result['username'],
            'potd_points': one_pointers + 2*two_pointers,
            'most_recent_sub': result['closest'],
            'rating': db.execute("SELECT rating FROM users WHERE id=:uid", uid=user_id)[0]['rating'],
            'admin': db.execute("SELECT admin FROM users WHERE id=:uid", uid=user_id)[0]['admin']
        }
        result_list.append(result_dict)
    result_list.sort(key=lambda x: x['most_recent_sub'])
    result_list.sort(key=lambda x: x['potd_points'], reverse=True)
    return render_template("gym/potd_rankings.html", rank_data=result_list)

def get_user_name(user_id):
    name=db.execute("SELECT username FROM users WHERE id = :user_id",user_id=user_id)

    if name:
        return name[0]['username']
    else:
        return None

@app.route("/problemranking/<problem_id>")
def problem_rankings(problem_id):
    user_info = db.execute("SELECT user_id,time_taken FROM problem_solved WHERE problem_id = :problem_id AND time_taken!=-1 ORDER BY time_taken ASC",
                           problem_id=problem_id)
    result_list = []
    for user_dict in user_info:
        user_id = user_dict['user_id']

        result_dict = {
            'username': get_user_name(user_id),
            'potd_points': user_dict['time_taken']
        }
        result_list.append(result_dict)
    result_list.sort(key=lambda x: x['potd_points'], reverse=False)
    return render_template("problem/problem_rankings.html", rank_data=result_list, problem_name=get_problem_name(problem_id), problem_id=problem_id)

@app.route("/mathgym/mentalmathrankings")
def mental_math_rankings():
    user_info = db.execute("SELECT username,id,time_taken_on_mental_math FROM users ORDER BY time_taken_on_mental_math ASC")
    result_list = []
    for user_dict in user_info:
        user_id = user_dict['id']

        result_dict = {
            'username': user_dict['username'],
            'potd_points': user_dict['time_taken_on_mental_math']/1000
        }
        result_list.append(result_dict)
    result_list.sort(key=lambda x: x['potd_points'], reverse=False)
    return render_template("gym/mentalmath_rankings.html", rank_data=result_list)

@app.route("/submit-time",methods=['POST'])
@login_required
def submit_time():
    try:
        data=request.get_json()
        time_taken=int(data.get('timeTaken')*1000)

        print('time taken:',time_taken)

        if time_taken is None or not isinstance(time_taken, int):
            raise ValueError("Invalid timeTaken value")

        # Update the user's time_taken_on_mental_math value
        user_id = session.get("user_id")  # Assuming current_user.id gives the user's ID
        time_taken=int((time_taken+db.execute(
            "SELECT time_taken_on_mental_math FROM users WHERE id = ?", user_id
        )[0]['time_taken_on_mental_math']*2)/3)
        
        db.execute(
            "UPDATE users SET time_taken_on_mental_math = ? WHERE id = ?",
            time_taken, user_id
        )

        result = db.execute(
            "SELECT time_taken_on_mental_math FROM users WHERE id = ?", user_id
        )

        print(result)

        return "", 200
    except Exception as e:
        print(f"Error processing timeTaken: {e}")
        return "", 400

@app.route("/mathgym/mentalmath")
@login_required
def mental_math():
    return render_template("gym/mentalmath.html")

@app.route("/mathgym/triangulate", methods=["GET", "POST"])
def triangulate():
    if session.get("username"):
        last_play_time = db.execute("SELECT last_play_time FROM game_times WHERE user_id=:uid", uid=session["user_id"])
        best_score = db.execute("SELECT score FROM game_leaderboard WHERE user_id=:uid AND game_type='triangulate'", uid=session["user_id"])
        best_score = "N/A" if not best_score else best_score[0]['score']
        time_left = None
        rated = False
        if last_play_time:
            last_play_time = pytz.utc.localize(datetime.strptime(last_play_time[0]['last_play_time'], "%Y-%m-%d %H:%M:%S"))
            if datetime.now(UTC) - last_play_time > timedelta(hours=3):
                rated = True
            time_left = timedelta(hours=3) - (datetime.now(UTC) - last_play_time)
        else:
            rated = True
    if request.method == "GET":
        if session.get("username"):
            if not rated:
                hours, remainder = divmod(time_left.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                end_time = datetime.now(UTC) + time_left
                time_left = f"{hours}:{minutes}:{seconds}"
                return render_template("gym/triangulate.html", rated=rated, time_left=time_left, end_time=end_time, best_score=best_score)
            return render_template("gym/triangulate.html", rated=rated, best_score=best_score)
        else:
            return render_template("gym/triangulate.html", rated=False, no_account=True)
    if session.get("username"):
        score = float(request.form.get("score"))
        play_time = db.execute("SELECT last_play_time FROM game_times WHERE user_id=:uid AND game_type='triangulate'", uid=session["user_id"])
        if play_time:
            if datetime.now(UTC) - pytz.utc.localize(datetime.strptime(play_time[0]['last_play_time'], "%Y-%m-%d %H:%M:%S")) >= timedelta(hours=4):
                db.execute("UPDATE game_times SET last_play_time=datetime('now') WHERE user_id=:uid AND game_type='triangulate'", uid=session["user_id"])
                user_lb_info = db.execute("SELECT score FROM game_leaderboard WHERE user_id=:uid AND game_type='triangulate'", uid=session["user_id"])
                if user_lb_info:
                    if score < user_lb_info[0]['score']:
                        db.execute("UPDATE game_leaderboard SET score=:score WHERE user_id=:uid AND game_type='triangulate'", score=score, uid=session["user_id"])
                else:
                    db.execute("INSERT INTO game_leaderboard (user_id, score, game_type) VALUES (?, ?, 'triangulate')", session["user_id"], score)
        else:
            db.execute("INSERT INTO game_times (user_id, last_play_time, game_type) VALUES (?, datetime('now'), 'triangulate')", session["user_id"])
            db.execute("INSERT INTO game_leaderboard (user_id, score, game_type) VALUES (?, ?, 'triangulate')", session["user_id"], score)
        logger.info((f"User #{session['user_id']} ({session['username']}) played a game of triangulate."))
    else:
        logger.info((f"A user without an account has played a game of triangulate."))
    return redirect("/mathgym/triangulate")

@app.route("/mathgym/triangulate/leaderboard")
def triangulate_leaderboard():
    rank_data = db.execute("""
        SELECT gl.user_id, gl.score, u.username, u.rating
        FROM game_leaderboard AS gl
        JOIN users AS u ON gl.user_id = u.id
        WHERE gl.game_type = 'triangulate'
        ORDER BY gl.score ASC
    """)
    return render_template("gym/triangulate_rankings.html", rank_data=rank_data)

@app.route("/mathgym/beperfect")
def be_perfect():
    return render_template("gym/beperfect.html")

@app.route("/mathgym/resources")
def resources():
    return render_template("gym/resources.html")

def get_random_files(directory, num_files):
    png_files = [f for f in os.listdir(directory) if f.endswith('.png')]
    return random.sample(png_files, min(num_files, len(png_files)))

@app.route("/mathgym/mockgenerator", methods=["GET", "POST"])
@login_required
def mockgenerator():
    contest_type = request.args.get("contest-type")
    mock_type = request.args.get("mock-type")
    year_type = request.args.get("year-type")
    type = request.args.get("type-form")
    if request.method == "GET":
        time_map = {
            "amc10" : "01:15:00",
            "amc12" : "01:15:00",
            "amc8" : "00:40:00",
            "aime" : "03:00:00",
            "pascal" : "01:00:00",
            "cayley" : "01:00:00",
            "fermat" : "01:00:00"
        }
        
        year_map = {
            "amc10" : [2002, 2023],
            "amc12" : [2002, 2023],
            "amc8" : [2002, 2024],
            "aime" : [1983, 2024],
            "pascal" : [1997, 2023],
            "cayley" : [1997, 2023],
            "fermat" : [1997, 2023]
        }
        
        problem_cnt_map = {
            "amc10" : 25,
            "amc12" : 25,
            "amc8" : 25,
            "aime" : 15,
            "pascal" : 25,
            "cayley" : 25,
            "fermat" : 25
        }

        problems, answers, pids = [], [], []
        if not contest_type or not mock_type or not year_type:
            return render_template("gym/mock_generator.html", generate=False, year_map=year_map, time_map=time_map)
        
        ranges_1 = [[1, 2, 3], [4, 5, 6], [7, 8, 9], [10, 11, 12], [13, 14, 15]]
        ranges_2 = [[1, 2, 3, 4, 5], [6, 7, 8, 9, 10], [11, 12, 13, 14, 15], [16, 17, 18, 19, 20], [21, 22, 23, 24, 25]]

        time = time_map[contest_type]
        if mock_type == "unique":
            year_range = year_map[contest_type]
            years = [random.randint(year_range[0], year_range[1]) for _ in range(problem_cnt_map[contest_type])]

            if contest_type == "amc10" or contest_type == "amc12":
                types = random.choices(["A", "B"], k=25)
                for group in ranges_2:
                    random.shuffle(group)
                problems = [problem for group in ranges_2 for problem in group]
                base_path = f"static/AMC/{contest_type[-2:]}/"
                file_names = [f"{str(year)[-2:]}_{contest_type}{tp}_p{problem}.png" for year, tp, problem in zip(years, types, problems)]
                pids = [f"{str(year)[-2:]}_{contest_type}{tp}_p{str(problem).zfill(2)}" for year, tp, problem in zip(years, types, problems)]
                problems = [os.path.join(base_path, f"{year}/{tp}/{fname}") for year, tp, fname in zip(years, types, file_names)]
            
            elif contest_type == "amc8":
                for group in ranges_2:
                    random.shuffle(group)
                problems = [problem for group in ranges_2 for problem in group]
                base_path = f"static/AMC/8/"
                years = [year if year != 2021 else random.choice([2020, 2022]) for year in years]
                file_names = [f"{str(year)[-2:]}_{contest_type}_p{problem}.png" for year, problem in zip(years, problems)]
                pids = [f"{str(year)[-2:]}_{contest_type}_p{str(problem).zfill(2)}" for year, problem in zip(years, problems)]
                problems = [os.path.join(base_path, f"{year}/{fname}") for year, fname in zip(years, file_names)]
            
            elif contest_type == "aime":
                for group in ranges_1:
                    random.shuffle(group)
                problems = [problem for group in ranges_1 for problem in group]
                base_path = f"static/AIME/"
                types = [random.choice(["_I", "_II"]) if year >= 2000 else "" for year in years]
                file_names = [f"{str(year)[-2:]}_{contest_type}{tp}_p{problem}.png" for year, tp, problem in zip(years, types, problems)]
                pids = [f"{str(year)[-2:]}_{contest_type}{tp}_p{str(problem).zfill(2)}" for year, tp, problem in zip(years, types, problems)]
                problems = [os.path.join(base_path, f"{tp[1:]}/{year}/{fname}" if year >= 2000 else f"pre_2000/{year}/{fname}") for year, tp, fname in zip(years, types, file_names)]
            
            elif contest_type in ["pascal", "cayley", "fermat"]:
                for group in ranges_2:
                    random.shuffle(group)
                problems = [problem for group in ranges_2 for problem in group]
                base_path = f"static/{contest_type}/"
                file_names = [f"{str(year)[-2:]}_{contest_type}_p{str(problem).zfill(2)}.png" for year, problem in zip(years, problems)]
                pids = [f"{str(year)[-2:]}_{contest_type}_p{str(problem).zfill(2)}" for year, problem in zip(years, problems)]
                problems = [os.path.join(base_path, f"{year}/{fname}") for year, fname in zip(years,file_names)]

            answers = [db.execute("SELECT flag FROM problems WHERE id=:pid", pid=pid)[0]['flag'] for pid in pids]    
        elif mock_type == "year":
            if contest_type in ["amc8", "amc10", "amc12"]:
                raw_pnames = []
                base_directory = f"static/AMC/{contest_type[3:]}/{year_type}"
                if contest_type != "amc8":
                    if int(year_type) == 2024:
                        flash("2024 AMC 10/12 has not happened yet.", "danger")
                        return redirect("/mathgym/mockgenerator")
                    base_directory += f"/{type}"
                for f in os.listdir(base_directory):
                    parts = f.split('_')
                    num = parts[-1][1:-4].zfill(2)
                    raw_pnames.append('_'.join(parts[:-1]) + '_p' + num + '.png')
                problems = [p.replace("_p0", "_p") for p in sorted([f"{base_directory}/{name}" for name in raw_pnames])]
                pids = sorted([p.split('/')[-1][:-4] for p in raw_pnames])

            elif contest_type == "aime":
                raw_pnames = []
                base_directory = f"static/AIME/{+type if int(year_type) >= 2000 else 'pre_2000'}/{year_type}"
                for f in os.listdir(base_directory):
                    parts = f.split('_')
                    num = parts[-1][1:-4].zfill(2)
                    raw_pnames.append('_'.join(parts[:-1]) + '_p' + num + '.png')
                problems = [p.replace("_p0", "_p") for p in sorted([f"{base_directory}/{name}" for name in raw_pnames])]
                pids = sorted([p.split('/')[-1][:-4] for p in raw_pnames])
                
            elif contest_type in ["pascal", "cayley", "fermat"]:
                raw_pnames = []
                base_directory = f"static/{contest_type}/{year_type}"
                for f in os.listdir(base_directory):
                    parts = f.split('_')
                    num = parts[-1][1:-4].zfill(2)
                    raw_pnames.append('_'.join(parts[:-1]) + '_p' + num + '.png')
                problems = [p for p in sorted([f"{base_directory}/{name}" for name in raw_pnames])]
                pids = sorted([p.split('/')[-1][:-4] for p in raw_pnames])
            
            answers_raw = db.execute("SELECT flag FROM problems WHERE id IN (?)", pids)
            answers = [a['flag'] for a in answers_raw]
        formatted_contest_type = ""
        mx_score = 0
        contest_types = {
            "amc10": ("AMC 10", 150),
            "amc12": ("AMC 12", 150),
            "amc8": ("AMC 8", 25),
            "aime": ("AIME", 15),
            "pascal": ("Pascal", 150),
            "cayley": ("Cayley", 150),
            "fermat": ("Fermat", 150)
        }
        formatted_contest_type, mx_score = contest_types.get(contest_type, ("", 0))
        title = f"Mock {formatted_contest_type}"
        if mock_type == "unique":
            title += " (Unique)"
        elif mock_type == "year":
            if contest_type == "aime":
                title += " "
            title += f"{type} ({year_type})"
        flash("Here are your problems! The timer has started.", "success")
        return render_template("gym/mock_generator.html", problems=problems, answers=answers, generate=True, time=time, contest_type=formatted_contest_type, mock_type=mock_type, year_type=year_type, max_score=mx_score, type=type, title=title, pids=pids)

    score = request.form.get("score")
    time = request.form.get("time")
    correct = request.form.getlist("correct[]")
    wrong = request.form.getlist("wrong[]")
    blank = request.form.getlist("blank[]") if contest_type in ["amc10", "amc12"] else []
    user_answers = request.form.getlist("user_answers[]")
    pid_list = request.form.getlist("pid_list[]")

    correct = (correct[0].split(',') if correct[0] else []) if correct else []
    wrong = (wrong[0].split(',') if wrong[0] else []) if wrong else []
    blank = (blank[0].split(',') if blank[0] else []) if blank else []
    user_answers = user_answers[0].split(',') if user_answers[0] else []
    pid_list = pid_list[0].split(',') if pid_list[0] else []
    pid_to_user_answers = {pid_list[i]: user_answers[i] for i in range(len(pid_list))}

    for problem in correct:
        data = db.execute("SELECT flag, point_value FROM problems WHERE id=?", problem)[0]
        answer = data["flag"]
        check = db.execute("SELECT * FROM problem_solved WHERE user_id=:uid AND problem_id=:pid", uid=session["user_id"], pid=problem)
        if not check:
            db.execute("INSERT INTO problem_solved (user_id, problem_id) VALUES (?, ?)", session["user_id"], problem)
            db.execute(("UPDATE users SET total_points=total_points+:pv, "
                        "problems_solved=problems_solved+1 WHERE id=:uid"),
                    pv=data["point_value"], uid=session["user_id"])
        db.execute(("INSERT INTO submissions (date, user_id, problem_id, correct, submitted) "
                    "VALUES (datetime('now'), :user_id, :problem_id, :check, :flag)"),
                user_id=session["user_id"], problem_id=problem, check=1, flag=answer)

    for problem in wrong:
        if pid_to_user_answers[problem] == "no-answer":
            continue
        db.execute(("INSERT INTO submissions (date, user_id, problem_id, correct, submitted) "
                    "VALUES (datetime('now'), :user_id, :problem_id, :check, :flag)"),
                user_id=session["user_id"], problem_id=problem, check=0, flag=pid_to_user_answers[problem])

    flash("Mock Saved! New problems have been added to your profiles and submissions.", "success")
    return redirect("/mathgym/mockgenerator")

@app.route('/problems')
def problems():
    silly=request.args.get("silly",default="false")
    if silly=='true':
        silly=True
    else:
        silly=False

    keywords=request.args.get("keywords",default="")
    original=keywords
    
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    category = request.args.get("category")
    if not category:
        category = None

    title = request.args.get("title")
    if not title:
        title = None

    points_ub = request.args.get("pub")
    points_lb = request.args.get("plb")
    if (points_ub and not points_lb) or (not points_ub and points_lb):
        flash("Invalid point range, must have both upperbound and lowerbound", "danger")
        return redirect(url_for("problems"))
    if not points_ub and not points_lb:
        points_ub = None
        points_lb = None
    else:
        points_ub = int(points_ub)
        points_lb = int(points_lb)

    tags = request.args.get("tags")
    if not tags:
        tags = None
    else:
        tags = json.loads(tags)
        if not tags or tags == ["None"]:
            tags = None
    
    nosolve = request.args.get("nosolves")
    if not nosolve:
        nosolve = None
    else:
        nosolve = bool(nosolve)

    clienthidesolves = request.args.get("clienthidesolves")
    if not clienthidesolves:
        clienthidesolves = None
    else:
        clienthidesolves = bool(clienthidesolves)
    
    order_type = request.args.get("order")
    if not order_type:
        order_type = None

    solved_data = db.execute("SELECT problem_id FROM problem_solved WHERE user_id=:uid",
                             uid=session["user_id"]) if session.get("user_id") else []
    solved = set()
    selected_tags = set()
    for row in solved_data:
        solved.add(row["problem_id"])
    
    organizations = {row["org_id"] for row in db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session.get("user_id", 0))}
    
    # create query
    args = []
    modifier = " WHERE (draft=0"
    if not silly:
        query = "SELECT p.*, COUNT(DISTINCT problem_solved.user_id) AS sols FROM problems p LEFT JOIN problem_solved ON p.id=problem_solved.problem_id"
        count_query = "SELECT COUNT(*) AS cnt FROM problems p"
    else:
        query = """WITH wrong AS (
                SELECT user_id, problem_id, correct, submitted, MIN(date) AS min_date
                FROM submissions
                GROUP BY user_id, problem_id)
                SELECT p.*, COUNT(DISTINCT problem_solved.user_id) AS sols FROM problems p LEFT JOIN problem_solved ON p.id=problem_solved.problem_id
                LEFT JOIN wrong ON p.id=wrong.problem_id"""
        count_query = """WITH wrong AS (
                SELECT user_id, problem_id, correct, submitted, MIN(date) AS min_date
                FROM submissions
                GROUP BY user_id, problem_id)
                SELECT COUNT(*) AS cnt FROM problems p
                LEFT JOIN wrong ON p.id=wrong.problem_id"""
        args.append(session['user_id'])
        modifier = " WHERE wrong.correct=0 AND wrong.user_id=? AND (draft=0"

    if keywords!="":
        original=keywords
        keywords=keywords.split(" ")

        keywords_list = [keyword.lower() for keyword in keywords]
        placeholders='?'
        problem_query = f"SELECT problem_id FROM problems WHERE keyword IN ({placeholders})"
        cache = problem_db.execute(problem_query, [keywords[i] for i in range(len(keywords))])
        problems = [j['problem_id'] for j in cache]

        modifier += " AND p.id IN (?)"
        args.append(problems)

    if category is not None:
        modifier += " AND category=?"
        args.append(category)
    if title is not None:
        modifier += " AND (LOWER(p.name) LIKE ? OR LOWER(p.id) LIKE ?)"
        processed = '%' + title.lower() + '%'
        args += [processed, processed]
    if points_ub is not None and points_lb is not None:
        modifier += " AND p.point_value BETWEEN ? AND ?"
        args += [points_lb, points_ub]
    if tags is not None:
        query += " LEFT JOIN problem_tags pt ON p.id = pt.problem_id"
        query += " LEFT JOIN tags t ON pt.tag_id = t.id"
        count_query += " LEFT JOIN problem_tags pt ON p.id = pt.problem_id"
        count_query += " LEFT JOIN tags t ON pt.tag_id = t.id"
        modifier += " AND t.name IN (?)"
        args.append(tags)
        selected_tags = set(tags)
    if nosolve is not None and nosolve:
        count_query += " LEFT JOIN problem_solved ON p.id=problem_solved.problem_id"
        modifier += " AND problem_solved.problem_id IS NULL"
    if clienthidesolves is not None and clienthidesolves:
        modifier += " AND p.id NOT IN (?)"
        args.append(list(solved))
    
    if not check_perm(["ADMIN", "SUPERADMIN"]):
        modifier += " AND (p.private=0"
        if organizations:
            modifier += " OR p.private_org IN (?))"
            args.append(list(organizations))
        else:
            modifier += ")"

    query += modifier+')'
    count_query += modifier+')'
    query += " GROUP BY p.id"
    if order_type:
        reverse = order_type[0] == '-'
        if reverse:
            order_type = order_type[1:]
        if order_type == "name":
            query += " ORDER BY p.name"
        elif order_type == "category":
            query += " ORDER BY category"
        elif order_type == "points":
            query += " ORDER BY p.point_value"
        elif order_type == "solves":
            query += " ORDER BY sols"
        query += " DESC" if reverse else " ASC"
    else:
        query += " ORDER BY p.id ASC"
    data = db.execute(query, *args)
    selectable_problems=[]

    for i in data:
        selectable_problems.append(i['id'])

    query += " LIMIT 50 OFFSET ?"
    args.append(page)
    data = db.execute(query, *args)
    length = db.execute(count_query, *(args[:-1]))
    
    if (length == 0):
        flash('No such problems exist.', 'warning')
        return redirect("/problems")
    
    for row in data:
        tag_ids = [tag['tag_id'] for tag in db.execute("SELECT tag_id FROM problem_tags WHERE problem_id=:pid", pid=row['id'])]
        row['tags'] = []
        for tid in tag_ids:
            tag_name = db.execute("SELECT name FROM tags WHERE id=:tid", tid=tid)[0]['name']
            row['tags'].append(tag_name)
        row['tags'].sort()

    categories = db.execute("SELECT DISTINCT category FROM problems WHERE draft=0 OR private_org IN (?)", list(organizations))
    categories.sort(key=lambda x: x['category'])

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
    
    attempted = db.execute("SELECT DISTINCT problem_id FROM submissions WHERE correct=0 "
                           "AND user_id=:uid", uid=session["user_id"]) if session.get("user_id") else []
    incorrect = set([val['problem_id'] for val in attempted if val['problem_id'] not in solved])
    tags_raw = db.execute(("SELECT DISTINCT tags.name FROM tags "
                           "JOIN problem_tags ON tags.id = problem_tags.tag_id;"))
    all_tags = ["None"]+sorted([val['name'] for val in tags_raw])
    length = length[0]['cnt']
    total_problems = db.execute("SELECT COUNT(*) as cnt FROM problems WHERE draft=0")[0]['cnt']
    submitted_problems = db.execute("SELECT COUNT(DISTINCT problem_id) AS cnt FROM submissions")[0]['cnt']
    submitted_users = db.execute("SELECT COUNT(DISTINCT user_id) AS cnt FROM submissions")[0]['cnt']
    subs = db.execute("SELECT COUNT(*) as cnt FROM submissions")[0]['cnt']
    empty_problems = total_problems-submitted_problems
    plb = points_lb if points_lb else 1
    pub = points_ub if points_ub else 10
    show_tags = db.execute("SELECT show_global_tags FROM users WHERE id=:uid", uid=session["user_id"])[0]['show_global_tags'] if session.get("user_id") else True
    
    # Get top 5 problems by most recent submissions in the past 7 days
    top_5_problems = db.execute("""
        SELECT p.*, COUNT(*) AS cnt, COUNT(DISTINCT problem_solved.user_id) AS sols
        FROM submissions s
        JOIN problems p ON s.problem_id = p.id
        LEFT JOIN problem_solved ON p.id=problem_solved.problem_id
        WHERE s.date >= datetime('now', '-7 days')
        GROUP BY s.problem_id
        ORDER BY cnt DESC
        LIMIT 5
    """)
    
    return render_template('problem/problems.html',
                           data=data, solved=solved, length=-(-length // 50),
                           categories=categories, selected=category, is_ongoing_contest=is_ongoing_contest, incorrect=incorrect, title=title, tags=all_tags, selected_tags=selected_tags,
                           total_problems=total_problems, submitted_problems=submitted_problems,
                           submitted_users=submitted_users, empty_problems=empty_problems, subs=subs, plb=plb, pub=pub, show_tags=show_tags, top_5_problems=top_5_problems,
                           selectable_problems=selectable_problems, default=original)


@app.route("/problems/create", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def create_problem():
    if request.method == "GET":
        return render_template("problem/create.html")

    # Reached via POST

    problem_id = request.form.get("id")
    name = request.form.get("name")
    description_md = request.form.get("description_md")
    description_html = request.form.get("description_html")
    hints_md = request.form.get("hints_md")
    hints_html = request.form.get("hints_html")
    point_value = request.form.get("point_value")
    category = request.form.get("category")
    ans = request.form.get("answer")
    draft = 1 if request.form.get("draft") else 0
    taglist = request.form.getlist("taglist[]")
    taglist = json.loads(taglist[0]) if taglist else []
    flag_hint = request.form.get("flag_hint")
    if not flag_hint:
        flag_hint = ""
    instanced = bool(request.form.get("instanced"))

    if (not problem_id or not name or not description_md or not point_value
            or not category or not ans):
        flash('You have not entered all required fields', 'danger')
        return render_template("problem/create.html"), 400

    # Check if problem ID is valid
    if not verify_text(problem_id):
        flash('Invalid problem ID', 'danger')
        return render_template("problem/create.html"), 400

    # Check if flag is valid
    if not verify_flag(ans):
        flash('Invalid flag', 'danger')
        return render_template("problem/create.html"), 400

    description_md = description_md.replace('\r', '')
    if not hints_md:
        hints_md = ""

    # Ensure problem does not already exist
    problem_info = db.execute("SELECT id FROM problems WHERE id=:problem_id OR name=:name",
                              problem_id=problem_id, name=name)
    if len(problem_info) != 0:
        flash('A problem with this name or ID already exists', 'danger')
        return render_template("problem/create.html"), 409

    # Check if file exists & upload if it does
    file = request.files["file"]
    if file.filename:
        filename = problem_id + ".zip"
        file.save("dl/" + filename)
        description_md += f'\n\n[{filename}](/dl/{filename})'

    # Modify problems table
    db.execute(("INSERT INTO problems (id, name, point_value, category, flag, draft, "
                "flag_hint, instanced) VALUES (:id, :name, :point_value, :category, "
                ":flag, :draft, :fhint, :inst)"),
               id=problem_id, name=name, point_value=point_value, category=category,
               flag=ans, draft=draft, fhint=flag_hint, inst=instanced)
    
    # Add to tags table
    tags_raw = db.execute("SELECT name FROM tags")
    curr_tags = [] if not tags_raw else set([val['name'] for val in tags_raw])
    for tag in taglist:
        if tag not in curr_tags:
            db.execute("INSERT INTO tags (name) VALUES (:name)", name=tag)
        tid = db.execute("SELECT id FROM tags WHERE name=:name", name=tag)[0]['id']
        db.execute(("INSERT INTO problem_tags (tag_id, problem_id) "
                    "VALUES (:tid, :pid)"), tid=tid, pid=problem_id)

    os.makedirs('metadata/problems/' + problem_id)
    write_file('metadata/problems/' + problem_id + '/description.md', description_md)
    write_file('metadata/problems/' + problem_id + '/description.html', description_html)
    write_file('metadata/problems/' + problem_id + '/hints.md', hints_md)
    write_file('metadata/problems/' + problem_id + '/hints.html', hints_html)
    open('metadata/problems/' + problem_id + '/editorial.md', 'w').close()
    logger.info((f"User #{session['user_id']} ({session['username']}) created "
                 f"problem {problem_id}"), extra={"section": "problem"})
    flash('Problem successfully created', 'success')
    return redirect("/problem/" + problem_id)

@app.route('/problems/draft')
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def draft_problems():
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    data = db.execute("SELECT * FROM problems WHERE draft=1 LIMIT 50 OFFSET ?", page)
    length = db.execute("SELECT COUNT(*) AS cnt FROM problems WHERE draft=1")[0]["cnt"]

    return render_template('problem/draft_problems.html',
                           data=data, length=-(-length // 50))

@app.route("/users/<username>/profile")
def profile(username):
    user_info = db.execute("SELECT * FROM users WHERE username=:username", username=username)
    if len(user_info) == 0:
        return render_template("error/404.html"), 404
    organizations = db.execute("SELECT o.id, o.name FROM organization_members om JOIN organizations o ON om.org_id=o.id WHERE om.user_id=:uid ORDER BY o.name ASC", uid=user_info[0]["id"])
    return render_template("profile/profile.html", user_data=user_info[0], organizations=organizations)

@app.route("/users/<username>/profile/userinfo")
def userinfo(username):
    user_info = db.execute("SELECT * FROM users WHERE username=:username", username=username)
    if len(user_info) == 0:
        return render_template("error/404.html"), 404
    uid = db.execute("SELECT id FROM users WHERE username=:username", username=username)[0]["id"]
    submissions = db.execute(("SELECT COUNT(*) as cnt FROM submissions WHERE user_id=:uid"), uid=uid)[0]["cnt"]

    better_points_users = db.execute("SELECT COUNT(DISTINCT id)+1 AS cnt FROM users WHERE total_points > (SELECT total_points FROM users WHERE id=?) AND banned=0 AND verified=1", uid)[0]['cnt']
    worse_points_users = db.execute("SELECT COUNT(DISTINCT id) AS cnt FROM users WHERE total_points < (SELECT total_points FROM users WHERE id=?) AND banned=0 AND verified=1", uid)[0]['cnt']
    total_points = better_points_users + worse_points_users

    better_solves_users = db.execute("SELECT COUNT(DISTINCT id)+1 AS cnt FROM users WHERE problems_solved > (SELECT problems_solved FROM users WHERE id=?) AND banned=0 AND verified=1", uid)[0]['cnt']
    worse_solves_users = db.execute("SELECT COUNT(DISTINCT id) AS cnt FROM users WHERE problems_solved < (SELECT problems_solved FROM users WHERE id=?) AND banned=0 AND verified=1", uid)[0]['cnt']
    total_solves = better_solves_users + worse_solves_users
    
    total_problems = db.execute("SELECT COUNT(*) AS cnt FROM problems")[0]["cnt"]
    percentage_solved = round(user_info[0]['problems_solved'] / total_problems * 100, 2)
    percentage_by_points = round((total_points - better_points_users + 1) / total_points * 100, 2)
    percentage_by_solved = round((total_solves - better_solves_users + 1) / total_solves * 100, 2)

    points_gradient, solved_gradient = "", ""
    if better_points_users == 1:
        points_gradient = "linear-gradient(90deg, rgba(255,218,0,1) 0%, rgba(255,255,255,1) 100%);"
    elif better_points_users == 2:
        points_gradient = "linear-gradient(90deg, rgba(181,181,181,1) 0%, rgba(255,255,255,1) 100%);"
    elif better_points_users == 3:
        points_gradient = "linear-gradient(90deg, rgba(223,141,60,1) 0%, rgba(255,255,255,1) 100%);"
    elif better_points_users == 4:
        points_gradient = "linear-gradient(90deg, rgb(116, 31, 34) 0%, rgba(255,255,255,1) 100%);"
    elif better_points_users == 5:
        points_gradient = "linear-gradient(90deg, rgb(116, 31, 34) 0%, rgba(255,255,255,1) 100%);"

    if better_solves_users == 1:
        solved_gradient = "linear-gradient(90deg, rgba(255,218,0,1) 0%, rgba(255,255,255,1) 100%);"
    elif better_solves_users == 2:
        solved_gradient = "linear-gradient(90deg, rgba(181,181,181,1) 0%, rgba(255,255,255,1) 100%);"
    elif better_solves_users == 3:
        solved_gradient = "linear-gradient(90deg, rgba(223,141,60,1) 0%, rgba(255,255,255,1) 100%);"
    elif better_solves_users == 4:
        solved_gradient = "linear-gradient(90deg, rgb(116, 31, 34) 0%, rgba(255,255,255,1) 100%);"
    elif better_solves_users == 5:
        solved_gradient = "linear-gradient(90deg, rgb(116, 31, 34) 0%, rgba(255,255,255,1) 100%);"

    organizations = db.execute("SELECT o.id, o.name FROM organization_members om JOIN organizations o ON om.org_id=o.id WHERE om.user_id=:uid ORDER BY o.name ASC", uid=user_info[0]["id"])
    rating_updates = db.execute("SELECT * FROM rating_updates WHERE user_id=:uid ORDER BY date DESC", uid=user_info[0]["id"])
    
    return render_template("profile/userinfo.html", user_data=user_info[0], submissions=int(submissions), rank_by_points=better_points_users, rank_by_solved=better_solves_users, points_gradient=points_gradient, solved_gradient=solved_gradient, percentage_solved=percentage_solved, percentage_by_points=percentage_by_points, percentage_by_solved=percentage_by_solved, organizations=organizations, rating_updates=rating_updates)

@app.route("/users/<username>/profile/edit", methods=["GET", "POST"])
@login_required
def editprofile(username):
    user_data = db.execute("SELECT id FROM users WHERE username=:username", username=username)
    if len(user_data) == 0:
        return render_template("error/404.html"), 404
    uid = user_data[0]["id"]
    if (session["username"] != username or session["user_id"] != uid) and not check_perm(["SUPERADMIN"]):
        return render_template("error/404.html"), 404
    if request.method == "GET":
        return render_template('profile/edit_profile.html', user_data=user_data[0])
    new_profile_md = request.form.get("profile_md")
    new_profile_html = request.form.get("profile_html")
    if not new_profile_md:
        flash('You have not entered a description.', 'danger')
        return render_template('problem/edit_problem.html', user_data=user_data[0]), 400
    write_file('metadata/users/' + str(uid) + '/profile.md', new_profile_md)
    write_file('metadata/users/' + str(uid) + '/profile.html', new_profile_html)
    logger.info((f"User #{session['user_id']} ({session['username']}) updated their profile."),
                extra={"section": "profile"})
    flash('Profile successfully edited', 'success')
    return redirect(f"/users/{username}/profile")

@app.route("/rankings")
def rankings():
    query = request.args.get("q")
    modifier = ""
    args = []
    if query:
        modifier = "WHERE verified=1 AND banned=0 AND username LIKE ?"
        args = ['%' + query + '%']
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    # Leaderboard ordered by total points
    leaderboard_points = db.execute(
        f"SELECT * FROM users {modifier} ORDER BY total_points DESC LIMIT 50 OFFSET ?", *args, page)
    
    # Leaderboard ordered by rating
    leaderboard_rating = db.execute(
        f"SELECT * FROM users {modifier} ORDER BY rating DESC LIMIT 50 OFFSET ?", *args, page)
    
    length = db.execute(f"SELECT COUNT(*) AS cnt FROM users {modifier}", *args)[0]["cnt"]
    banned_users = db.execute("SELECT * FROM users WHERE verified=1 AND banned=1 ORDER BY total_points DESC")
    
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

    if int(page) <= 1 and not query:
        leaderboard_points[0]["image"] = "../assets/images/gold.png"
        leaderboard_points[1]["image"] = "../assets/images/silver.png"
        leaderboard_points[2]["image"] = "../assets/images/bronze.png"
        leaderboard_points[3]["image"] = "../assets/images/star.png"
        leaderboard_points[4]["image"] = "../assets/images/star.png"
        leaderboard_points[0]["title"] = "This user is first place."
        leaderboard_points[1]["title"] = "This user is second place."
        leaderboard_points[2]["title"] = "This user is third place."
        leaderboard_points[3]["title"] = "This user is fourth place."
        leaderboard_points[4]["title"] = "This user is fifth place."

        leaderboard_rating[0]["image"] = "../assets/images/gold.png"
        leaderboard_rating[1]["image"] = "../assets/images/silver.png"
        leaderboard_rating[2]["image"] = "../assets/images/bronze.png"
        leaderboard_rating[3]["image"] = "../assets/images/star.png"
        leaderboard_rating[4]["image"] = "../assets/images/star.png"
        leaderboard_rating[0]["title"] = "This user is first place."
        leaderboard_rating[1]["title"] = "This user is second place."
        leaderboard_rating[2]["title"] = "This user is third place."
        leaderboard_rating[3]["title"] = "This user is fourth place."
        leaderboard_rating[4]["title"] = "This user is fifth place."

    if length == 0:
        flash('No such users exist.', 'warning')
        return redirect(url_for("rankings"))

    points_last_week = db.execute("""SELECT u.username, u.rating, u.admin, SUM(p.point_value) AS total_points
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
        
    return render_template("rankings.html", 
                           leaderboard_points=leaderboard_points, 
                           leaderboard_rating=leaderboard_rating,
                           is_ongoing_contest=is_ongoing_contest, 
                           banned_users=banned_users, 
                           length=-(-length // 50), 
                           page=page, 
                           client_username=session['username'] if session.get("username") else None, 
                           points_last_week=points_last_week)

@app.route("/organizations")
def organizations():
    return redirect("/organizations/public")

@app.route("/organizations/public")
def organizations_public():
    query = """
    SELECT o.*, u.username AS owner_username, COUNT(DISTINCT om.user_id) AS users
    FROM organizations AS o
    JOIN users AS u ON o.owner_id = u.id
    LEFT JOIN organization_members AS om ON o.id = om.org_id
    WHERE o.private=0
    GROUP BY o.name
    ORDER BY o.name ASC
    """
    data = db.execute(query)
    owned_organizations_data = db.execute("SELECT id FROM organizations WHERE owner_id=:uid AND private=0", uid=session["user_id"]) if session.get("user_id") else []
    owned = set()
    for org in owned_organizations_data:
        owned.add(org["id"])
    return render_template("organization/organizations.html", data=data, owned=owned)

@app.route("/organizations/private")
def organizations_private():
    query = """
    SELECT o.*, u.username AS owner_username, COUNT(DISTINCT om.user_id) AS users
    FROM organizations AS o
    JOIN users AS u ON o.owner_id = u.id
    LEFT JOIN organization_members AS om ON o.id = om.org_id
    WHERE o.private=1
    GROUP BY o.name
    ORDER BY o.name ASC
    """
    data = db.execute(query)
    owned_organizations_data = db.execute("SELECT id FROM organizations WHERE owner_id=:uid AND private=1", uid=session["user_id"]) if session.get("user_id") else []
    owned = set()
    for org in owned_organizations_data:
        owned.add(org["id"])
    return render_template("organization/organizations.html", data=data, owned=owned, private=True)

@app.route("/organizations/create", methods=["GET", "POST"])
@admin_required
def create_organization():
    if request.method == "GET":
        return render_template("organization/createorganization.html")

    name = request.form.get("name")
    owner_id = request.form.get("owner")
    description_md = request.form.get("description_md").replace('\r', '')
    description_html = request.form.get("description_html").replace('\r', '')
    private = request.form.get("private_org")
    
    if not name or not owner_id or not description_md:
        flash('You have not entered all required fields.', 'danger')
        return render_template("organization/createorganization.html"), 400
    
    private = bool(private)
    password_hash = None
    if private:
        password = request.form.get("password")
        password_confirmation = request.form.get("password_confirmation")
        if not password or len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template("organization/createorganization.html"), 400
        if password == '12345678':
            flash('Please choose a password better than that.', 'danger')
            return render_template("organization/createorganization.html"), 400
        if password != password_confirmation:
            flash('Passwords do not match.', 'danger')
            return render_template("organization/createorganization.html"), 400
        password_hash = generate_password_hash(password)

    db.execute("INSERT INTO organizations (name, owner_id, private, join_code) VALUES (:name, :owner_id, :private, :password)", name=name, owner_id=owner_id, private=private, password=password_hash)
    org_id = db.execute("SELECT id FROM organizations WHERE name=:name", name=name)[0]["id"]
    db.execute("INSERT INTO organization_members (org_id, user_id, admin) VALUES (:org_id, :owner_id, 1)", org_id=org_id, owner_id=owner_id)
    
    write_file('metadata/organizations/' + str(org_id) + '.md', description_md)
    write_file('metadata/organizations/' + str(org_id) + '.html', description_html)

    logger.info((f"User #{session['user_id']} ({session['username']}) created "
                 f"organization {org_id}"), extra={"section": "organization"})

    flash('Organization successfully created', 'success')
    return redirect("/organizations")

@app.route("/team")
def team():
    return render_template("info/team.html")

@app.route("/changelog")
def changelog():
    return render_template("info/changelog.html")

@app.route("/discordserver")
def discordserver():
    return render_template("info/discordserver.html")

@app.route("/uptime")
def uptime():
    return render_template("info/uptime.html")

@app.route("/submissions")
def user_submissions():
    query = """
        SELECT c.id
        FROM contests c
        INNER JOIN contest_users cu ON c.id = cu.contest_id
        WHERE cu.user_id = ? 
            AND c.start <= datetime('now') 
            AND c.end >= datetime('now')
            AND c.scoreboard_visible = 0
    """
    if session.get("user_id"):
        curr_contests = db.execute(query, session["user_id"])
        if len(curr_contests) != 0 and not check_perm(["ADMIN", "SUPERADMIN"]):
            flash("You cannot view submissions while in a contest where the scoreboard is hidden!", "danger")
            return redirect("/")
    submissions = None

    modifier = " WHERE"
    args = []

    # Construct query
    query = request.args.copy()
    if query.get("username"):
        modifier += " username=? AND"
        args.append(query.get("username"))

    if query.get("problem_id"):
        modifier += " problem_id=? AND"
        args.append(query.get("problem_id"))

    if query.get("correct"):
        modifier += " correct=? AND"
        args.append(query.get("correct") == "AC")

    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50
    modifier += " 1=1"

    length = len(db.execute(("SELECT submissions.*, users.username FROM submissions "
                             "LEFT JOIN users ON user_id=users.id") + modifier, *args))

    args.append(page)
    submissions = db.execute(("SELECT submissions.*, users.username, users.rating, users.admin FROM submissions "
                              f"LEFT JOIN users ON user_id=users.id {modifier}"
                              " LIMIT 50 OFFSET ?"), *args)

    return render_template("info/submissions_user.html", data=submissions, length=-(-length // 50))

@app.route("/courses")
def courses():
    return render_template("course/courses.html")

@app.route("/courses/create", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def create_course():
    if request.method == "GET":
        return render_template("course/create.html")

    # Reached via POST

    course_id = request.form.get("id")
    name = request.form.get("name")
    description_md = request.form.get("description_md")
    description_html = request.form.get("description_html")
    public = bool(request.form.get("public"))

    if (not course_id or not name or not description_md or not description_html):
        flash('You have not entered all required fields', 'danger')
        return render_template("course/create.html"), 400

    # Check if course ID is valid
    if not verify_text(course_id):
        flash('Invalid course ID', 'danger')
        return render_template("course/create.html"), 400

    description_md = description_md.replace('\r', '')

    # Ensure course does not already exist
    course_info = db.execute("SELECT id FROM courses WHERE id=:course_id OR name=:name",
                              course_id=course_id, name=name)
    if len(course_info) != 0:
        flash('A course with this name or ID already exists', 'danger')
        return render_template("course/create.html"), 409

    # Modify courses table
    db.execute(("INSERT INTO courses (id, name, public, date_created)"
                " VALUES (?, ?, ?, datetime('now'))"),
                course_id, name, public)

    os.makedirs('metadata/courses/' + course_id)
    write_file('metadata/courses/' + course_id + '/description.md', description_md)
    write_file('metadata/courses/' + course_id + '/description.html', description_html)
    logger.info((f"User #{session['user_id']} ({session['username']}) created "
                 f"course {course_id}"), extra={"section": "problem"})
    flash('Course successfully created', 'success')
    return redirect("/course/" + course_id)

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


@app.route("/teapot")
def teapot():
    return render_template("error/418.html"), 418


# Security headers
@app.after_request
def security_policies(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


if __name__ == "__main__":
    ui.run()
    
