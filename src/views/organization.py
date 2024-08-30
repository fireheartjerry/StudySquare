from flask import (Blueprint, flash, redirect, render_template, request, session,
                   current_app as app, url_for)
import logging
import os

from helpers import *  # noqa
from db import db

from werkzeug.security import check_password_hash, generate_password_hash
from re import match

api = Blueprint("organization", __name__)

logger = logging.getLogger("TOPSOJ")

@api.route("/<org_id>")
def organization(org_id):
    if not org_exists(org_id):
        return render_template("organization/org_noexist.html"), 404
    
    data = db.execute("SELECT * FROM organizations WHERE id=:oid", oid = org_id)
    owner = db.execute("SELECT username FROM users WHERE id=:oid", oid = data[0]["owner_id"])[0]["username"]
    member_count = db.execute("SELECT COUNT(DISTINCT user_id) AS cnt FROM organization_members WHERE org_id=:oid", oid = org_id)[0]["cnt"]
    inside_organization = False
    owned = False

    if session.get("user_id"):
        user_org_data = db.execute("SELECT * FROM organization_members WHERE org_id=:oid AND user_id=:uid", oid = org_id, uid = session["user_id"])
        if user_org_data:
            inside_organization = True
            if user_org_data[0]["admin"] == 1:
                owned = True

    all_time_points = db.execute("SELECT users.* FROM users INNER JOIN organization_members ON users.id=organization_members.user_id WHERE organization_members.org_id=? ORDER BY total_points DESC LIMIT ?", org_id, min(3, member_count))
    
    upcoming_contests = db.execute("SELECT * FROM contests WHERE private_org=:oid AND start > datetime('now') ORDER BY start ASC", oid = org_id)
    current_contests = db.execute("SELECT * FROM contests WHERE private_org=:oid AND start <= datetime('now') AND end >= datetime('now') ORDER BY start ASC", oid = org_id)
    past_contests = db.execute("SELECT * FROM contests WHERE private_org=:oid AND end < datetime('now') ORDER BY end DESC", oid = org_id)

    return render_template("organization/organization.html", data=data[0], owner=owner, member_count=member_count,inside_organization=inside_organization, owned=owned, all_time_points=all_time_points, upcoming_contests=upcoming_contests, current_contests=current_contests, past_contests=past_contests)

@api.route("/<org_id>/members")
def org_members(org_id):
    if not org_exists(org_id):
        return render_template("organization/org_noexist.html"), 404

    org_data = db.execute("SELECT * FROM organizations WHERE id=:oid", oid = org_id)
    user_data = db.execute("SELECT users.* FROM users INNER JOIN organization_members ON users.id=organization_members.user_id WHERE organization_members.org_id=? ORDER BY total_points DESC", org_id)
    is_owner = session["user_id"] == db.execute("SELECT owner_id FROM organizations WHERE id=:oid", oid=org_id)[0]["owner_id"] if session.get("user_id") else False

    return render_template("organization/members.html", org_data=org_data[0], user_data=user_data, is_owner=is_owner)

@api.route("/<org_id>/members/remove", methods=["POST"])
@org_admin_required
def remove_user(org_id):
    if not org_exists(org_id):
        return render_template("organization/org_noexist.html"), 404

    org_data = db.execute("SELECT name, id FROM organizations WHERE id=:oid", oid = org_id)
    user_id = request.form.get("user_id")
    if not user_id:
        flash("No user ID specified, please try again.", "danger")
        return redirect("/organization/" + org_id + "/members")
        
    if not db.execute("SELECT * FROM organization_members WHERE org_id=? AND user_id=?", org_id, user_id):
        flash("User is not in this organization.", "danger")
        return redirect("/organization/" + org_id + "/members")
    if int(user_id) == session["user_id"]:
        flash("You can not remove yourself from an organization.", "danger")
        return redirect("/organization/" + org_id + "/members")

    db.execute("DELETE FROM organization_members WHERE org_id=? AND user_id=?", org_id, user_id)

    flash("User successfully removed from organization.", "success")
    logger.info((f'User #{user_id} removed from organization {org_data[0]["name"]} ({org_data[0]["id"]}) by '
                 f'user #{session["user_id"]} ({session["username"]})'),
                extra={"section": "contest"})
    return redirect("/organization/" + org_id + "/members")

@api.route("/<org_id>/members/transfer", methods=["POST"])
@org_admin_required
def transfer_ownership(org_id):
    if not org_exists(org_id):
        return render_template("organization/org_noexist.html"), 404

    new_owner_id = request.form.get("user_id")
    if not new_owner_id:
        flash("No user ID specified, please try again.", "danger")
        return redirect("/organization/" + org_id + "/members")
    
    if not db.execute("SELECT * FROM organization_members WHERE org_id=? AND user_id=?", org_id, new_owner_id):
        flash("User is not in this organization.", "danger")
        return redirect("/organization/" + org_id + "/members")

    org_data = db.execute("SELECT name, id FROM organizations WHERE id=:oid", oid = org_id)
    
    current_owner_id = db.execute("SELECT owner_id FROM organizations WHERE id=:oid", oid=org_id)[0]["owner_id"]
    if new_owner_id == current_owner_id:
        flash("The user you are trying to transfer ownership to is already the owner.", "danger")
        return redirect("/organization/" + org_id + "/members")

    new_owner_username = db.execute("SELECT username FROM users WHERE id=:uid", uid=new_owner_id)[0]['username']
    current_owner_username = db.execute("SELECT username FROM users WHERE id=:uid", uid=current_owner_id)[0]['username']

    db.execute("UPDATE organizations SET owner_id=? WHERE id=?", new_owner_id, org_id)
    db.execute("UPDATE organization_members SET admin=1 WHERE org_id=? AND user_id=?", org_id, new_owner_id)
    db.execute("UPDATE organization_members SET admin=0 WHERE org_id=? AND user_id=?", org_id, current_owner_id)

    flash(f"Organization ownership successfully transferred to {new_owner_username} ({new_owner_id}).", "success")
    logger.info((f'Ownership of organization {org_data[0]["name"]} ({org_data[0]["id"]}) transferred from user #{current_owner_id} ({current_owner_username}) to user #{new_owner_id} ({new_owner_username}) by '
                 f'user #{session["user_id"]} ({session["username"]})'),
                extra={"section": "contest"})
    return redirect("/organization/" + org_id + "/members")

@api.route("/<org_id>/dashboard")
@org_admin_required
def org_dashboard(org_id):
    if not org_exists(org_id):
        return render_template("organization/org_noexist.html"), 404

    data = db.execute("SELECT * FROM organizations WHERE id=?", org_id)
    return render_template("organization/dashboard.html", data=data[0])


@api.route("/<org_id>/join")
@login_required
def join_org(org_id):
    if not org_exists(org_id):
        return render_template("organization/org_noexist.html"), 404
    org_data = db.execute("SELECT private, name FROM organizations WHERE id=:oid", oid = org_id)
    if org_data[0]['private'] and not check_perm(["ADMIN", "SUPERADMIN"]):
        return redirect("/organization/" + org_id)
    if db.execute("SELECT * FROM organization_members WHERE org_id=:oid AND user_id=:uid", oid = org_id, uid = session["user_id"]):
        flash("You are already in this organization.", 'danger'), 400
        return redirect("/organization/" + org_id)
    db.execute("INSERT INTO organization_members (org_id, user_id, admin) VALUES (?, ?, ?)", org_id, session["user_id"], check_perm(["ADMIN", "SUPERADMIN"]))
    flash(f'You have joined the organization \"{org_data[0]["name"]}\".', 'success')
    logger.info((f"User #{session['user_id']} ({session['username']}) joined "
                 f"organization {org_id}"), extra={"section": "organization"})
    return redirect("/organization/" + org_id)

@api.route("/<org_id>/joinprivate", methods=["GET", "POST"])
@login_required
def join_private_org(org_id):
    if not org_exists(org_id):
        return render_template("organization/org_noexist.html"), 404
    org_data = db.execute("SELECT private, name, join_code FROM organizations WHERE id=:oid", oid = org_id)
    if not org_data[0]['private']:
        return redirect("/organization/" + org_id)
    if not check_perm(["ADMIN", "SUPERADMIN"]):
        if request.method == "GET":
            return render_template("organization/joinprivate.html", org_data=org_data[0])
        password = request.form.get("password")
        if not password:
            flash("Password cannot be empty.", "danger")
            return render_template("organization/joinprivate.html", org_data=org_data[0]), 400
        if not check_password_hash(org_data[0]["join_code"], password):
            flash("Incorrect password.", "danger")
            return render_template("organization/joinprivate.html", org_data=org_data[0]), 400
    if db.execute("SELECT * FROM organization_members WHERE org_id=:oid AND user_id=:uid", oid = org_id, uid = session["user_id"]):
        flash("You are already in this organization.", 'danger'), 400
        return redirect("/organization/" + org_id)
    flash(f'You have joined the organization \"{org_data[0]["name"]}\".', 'success')
    db.execute("INSERT INTO organization_members (org_id, user_id) VALUES (?, ?)", org_id, session["user_id"])
    logger.info((f"User #{session['user_id']} ({session['username']}) joined "
                 f"organization {org_id}"), extra={"section": "organization"})
    return redirect("/organization/" + org_id)

@api.route("/<org_id>/leave",  methods=["POST"])
@login_required
def leave_org(org_id):
    if not org_exists(org_id):
        return render_template("organization/org_noexist.html"), 404
    org_name = db.execute("SELECT name FROM organizations WHERE id=:oid", oid = org_id)[0]['name']
    user_id = request.form.get("user_id")
    if not user_id:
        flash("No user ID specified, please try again.", "danger")
        return redirect("/organization/" + org_id)
    is_owner = user_id == db.execute("SELECT owner_id FROM organizations WHERE id=:oid", oid=org_id)[0]["owner_id"]
    in_org = db.execute("SELECT * FROM organization_members WHERE org_id=:oid AND user_id=:uid", oid = org_id, uid = user_id)
    if not in_org:
        flash("You are not in this organization.", "danger")
        return redirect("/organization/" + org_id)
    if is_owner:
        flash("You can not leave an organization you own. Ask an admin to transfer ownership or delete this organization.", "danger")
        return redirect("/organization/" + org_id)
    db.execute("DELETE FROM organization_members WHERE org_id=? AND user_id=?", org_id, session["user_id"])
    flash(f'You have left the organization \"{org_name}\".', 'success')
    logger.info((f"User #{session['user_id']} ({session['username']}) left "
                 f"organization {org_id}"), extra={"section": "organization"})
    return redirect("/organization/" + org_id)

@api.route("/<org_id>/edit", methods=["GET", "POST"])
@org_admin_required
def editorganization(org_id):
    if not org_exists(org_id):
        flash('That organization does not exist', 'danger')
        return redirect("/organization/organizations")

    data = db.execute("SELECT * FROM organizations WHERE id=:oid", oid=org_id)
    is_owner = session["user_id"] == data[0]["owner_id"] if session.get("user_id") else False

    if request.method == "GET":
        return render_template("organization/editorganization.html", data=data[0], is_owner=is_owner)
    
    new_name = data[0]["name"] if is_owner and not check_perm(["ADMIN", "SUPERADMIN"]) else request.form.get("name")
    new_description_md = request.form.get("description_md").replace('\r', '')
    new_description_html = request.form.get("description_html").replace('\r', '')

    if not new_name:
        flash('Name cannot be empty', 'danger')
        return render_template("organization/editorganization.html", data=data[0], is_owner=is_owner), 400
    if not new_description_md:
        flash('Description cannot be empty', 'danger')
        return render_template("organization/editorganization.html", data=data[0], is_owner=is_owner), 400
    
    db.execute("UPDATE problems SET category=:new_name WHERE category=:old_name", new_name=new_name, old_name=data[0]["name"])
    db.execute("UPDATE organizations SET name=:name WHERE id=:oid", name=new_name, oid=org_id)
    
    write_file('metadata/organizations/' + org_id + '.md', new_description_md)
    write_file('metadata/organizations/' + org_id + '.html', new_description_html)
    
    logger.info((f"User #{session['user_id']} ({session['username']}) updated "
                 f"organization {org_id}"), extra={"section": "organization"})
    flash('Organization successfully edited', 'success')
    return redirect("/organization/" + org_id)

@api.route("/<org_id>/createproblem", methods=["GET", "POST"])
@admin_required
def createproblem(org_id):
    if not org_exists(org_id):
        return render_template("organization/org_noexist.html"), 404

    org_data = db.execute("SELECT * FROM organizations WHERE id=:oid", oid = org_id)
    if not org_data[0]["private"]:
        return redirect("/organization/" + org_id)
    
    if request.method == "GET":
        return render_template("organization/createproblem.html", org_data=org_data[0])
    
    problem_id = "org-" + str(org_id) + "-" + request.form.get("id")
    name = request.form.get("name")
    category = org_data[0]["name"]
    description_md = request.form.get("description_md").replace('\r', '')
    description_html = request.form.get("description_html").replace('\r', '')
    hints_md = request.form.get("hints_md").replace('\r', '')
    hints_html = request.form.get("hints_html").replace('\r', '')
    point_value = request.form.get("point_value")
    ans = request.form.get("answer")
    taglist = request.form.getlist("taglist[]")
    taglist = json.loads(taglist[0]) if taglist else []

    if (not problem_id or not name or not description_md or not point_value
            or not category or not ans):
        flash('You have not entered all required fields', 'danger')
        return render_template("organization/createproblem.html"), 400

    # Check if problem ID is valid
    if not verify_text(problem_id):
        flash('Invalid problem ID', 'danger')
        return render_template("organization/createproblem.html"), 400

    # Check if flag is valid
    if not verify_flag(ans):
        flash('Invalid answer', 'danger')
        return render_template("organization/createproblem.html"), 400

    description_md = description_md.replace('\r', '')
    if not hints_md:
        hints_md = ""

    problem_info = db.execute("SELECT id FROM problems WHERE id=:problem_id OR name=:name",
                              problem_id=problem_id, name=name)
    if len(problem_info) != 0:
        flash('A problem with this name or ID already exists', 'danger')
        return render_template("organization/createproblem.html"), 400

    db.execute(("INSERT INTO problems (id, name, point_value, category, flag, draft, "
                " private, private_org) VALUES (:id, :name, :point_value, :category, "
                ":flag, :draft, :private, :private_org)"),
               id=problem_id, name=name, point_value=point_value, category=category,
               flag=ans, draft=False, private=True, private_org=org_id)

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

    flash('Problem successfully created', 'success')
    logger.info((f"User #{session['user_id']} ({session['username']}) created "
                 f"a private problem (id: {problem_id}, title: {name}) problem in organization {org_data[0]['name']} ({org_id})"), extra={"section": "organization"})
    return redirect("/problem/" + problem_id)

@api.route("/<org_id>/createcontest", methods=["GET", "POST"])
@admin_required
def createcontest(org_id):
    if not org_exists(org_id):
        return render_template("organization/org_noexist.html"), 404

    org_data = db.execute("SELECT * FROM organizations WHERE id=:oid", oid = org_id)
    if not org_data[0]["private"]:
        return redirect("/organization/" + org_id)

    if request.method == "GET":
        return render_template("organization/createcontest.html", org_data=org_data[0])

    # Reached using POST

    contest_id = "org-" + str(org_id) + "-" + request.form.get("contest_id")

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
    standard = bool(request.form.get("standard"))
    use_window_timer = bool(request.form.get("use_window_timer"))
    window_time = -1
    submission_limit = int(request.form.get("submission_limit"))
    show_verdict = bool(request.form.get("show_verdicts"))
    team = bool(request.form.get("team"))
    export_category = request.form.get("export_category")
    
    if use_window_timer:
        window_time = request.form.get("window_time")

    if submission_limit == 0 or submission_limit < -1:
        flash('Submission limit must be -1 or a positive integer', 'danger')
        return render_template("contest/create.html"), 400

    if not standard and submission_limit != 1:
        flash('This is a guts contest, so the submission limit MUST be 1', 'danger')
        return render_template("contest/create.html"), 400

    if not description_md:
        flash('Description cannot be empty', 'danger')
        return render_template("contest/create.html"), 400

    db.execute(("INSERT INTO contests (id, name, start, end, scoreboard_visible, scoreboard_key, standard, default_submission_limit, use_window_timer, window_time_seconds, team_contest, show_verdict, export_category, private, private_org) "
         " VALUES (?, ?, datetime(?), datetime(?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
        contest_id, contest_name, start, end, scoreboard_visible, scoreboard_key, standard, submission_limit, use_window_timer, window_time, show_verdict, team, export_category, True, org_id)

    os.makedirs('metadata/contests/' + contest_id)
    write_file('metadata/contests/' + contest_id + '/description.md', description_md)
    write_file('metadata/contests/' + contest_id + '/description.html', description_html)

    logger.info((f"User #{session['user_id']} ({session['username']}) created "
                 f"a private contest {contest_id} in organization {org_data[0]['name']} ({org_id})"), extra={"section": "contest"})
    flash('Contest successfully created', 'success')
    return redirect("/contest/" + contest_id)

@api.route("/<org_id>/changepassword", methods=["GET", "POST"])
@org_admin_required
def change_password(org_id):
    if not org_exists(org_id):
        return render_template("organization/org_noexist.html"), 404
    org_data = db.execute("SELECT * FROM organizations WHERE id=:oid", oid = org_id)
    if not org_data[0]['private']:
        return redirect("/organization/" + org_id)
    if request.method == "GET":
        return render_template("organization/changepassword.html", org_data=org_data[0])
    current_password = request.form.get("current-password")
    if not check_password_hash(org_data[0]["join_code"], current_password):
        flash("Incorrect current password.", "danger")
        return render_template("organization/changepassword.html", org_data=org_data[0]), 400
    password_hash = None
    password = request.form.get("password")
    if not password or len(password) < 8:
        flash('Password must be at least 8 characters long.', 'danger')
        return render_template("organization/createorganization.html"), 400
    if password == '12345678':
        flash('Please choose a password better than that.', 'danger')
        return render_template("organization/createorganization.html"), 400
    password_hash = generate_password_hash(password)
    db.execute("UPDATE organizations SET join_code=:password_hash WHERE id=:oid", password_hash=password_hash, oid=org_id)
    flash("Password successfully changed.", "success")
    logger.info((f"User #{session['user_id']} ({session['username']}) changed "
                 f"password for organization {org_id}"), extra={"section": "organization"})
    return redirect("/organization/" + org_id)

@api.route("/<org_id>/resetpass", methods=["POST"])
@admin_required
def reset_password(org_id):
    if not org_exists(org_id):
        return render_template("organization/org_noexist.html"), 404
    org_data = db.execute("SELECT * FROM organizations WHERE id=:oid", oid = org_id)
    if not org_data[0]['private']:
        return redirect("/organization/" + org_id)
    password = generate_password()
    db.execute("UPDATE organizations SET join_code=:p WHERE id=:oid",
               p=generate_password_hash(password), oid=org_id)
    flash(f"Password for {org_data[0]['name']} was reset! Their new password is {password}",  # noqa
          "success")
    logger.info((f"Organization #{org_data[0]['id']} ({org_data[0]['name']})'s password reset by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "auth"})
    return redirect("/organization/" + org_id)

@api.route("/<org_id>/delete", methods=["GET", "POST"])
@admin_required
def delete_org(org_id):
    if not org_exists(org_id):
        return render_template("organization/org_noexist.html"), 404
    name = db.execute("SELECT name FROM organizations WHERE id=:oid", oid=org_id)[0]['name']
        
    if request.method == "GET":
        return render_template("organization/delete_confirm.html", data=name)
    
    db.execute("BEGIN")
    db.execute("DELETE FROM organizations WHERE id=:oid", oid=org_id)
    db.execute("DELETE FROM organization_members WHERE org_id=:oid", oid=org_id)
    db.execute("UPDATE problems SET private=0 WHERE private_org=:oid AND private=1", oid=org_id)
    db.execute("UPDATE problems SET private_org=0 WHERE private_org=:oid", oid=org_id)
    db.execute("COMMIT")
    
    os.remove('metadata/organizations/' + org_id + '.md')
    os.remove('metadata/organizations/' + org_id + '.html')
    
    logger.info((f"User #{session['user_id']} ({session['username']}) deleted "
                 f"organization {org_id}"), extra={"section": "organization"})
    flash('Organization successfully deleted', 'success')
    return redirect("/organizations")
