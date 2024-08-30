from flask import (Blueprint, flash, redirect, render_template, request,
                   send_file, session)
import logging
import os
import shutil
import zipfile
from io import BytesIO
from datetime import datetime, timezone
from math import floor, log

UTC = timezone.utc

from helpers import *  # noqa
from db import *

api = Blueprint("problem", __name__)

logger = logging.getLogger("TOPSOJ")

def add_problem_into_pdatabase(pid):
    try:
        with open("metadata/problems/"+pid+"/description.md") as file:
            content=file.readlines()
            file.close()
    except:
        print("problem markdown file missing:",pid)
        print("please delete problemdatabase.db, restore the old version of database.db and rerun this program")
        raise RuntimeError("problem markdown file missing")
        #continue

    words=[]
    for j in content:
        cache=j.split(' ')
        for k in cache:
            words.append(k)

    for j in words:
        try:
            problem_db.execute("INSERT INTO problems (problem_id,keyword) values (:pid,:word)",
                                pid=pid,word=j)
        except:
            pass


@api.route('<problem_id>', methods=["GET", "POST"])
def problem(problem_id):
    #check if the user has already solved the problem
    solved=db.execute("SELECT * FROM problem_solved WHERE problem_id=:problem_id AND user_id=:user_id",problem_id=problem_id,user_id=session['user_id'])
    if len(solved)==0:
        #if it has not already solved the problem, check if it has seen the problem before
        now=datetime.now().isoformat()
        solving=db.execute("SELECT * FROM unfinished_problems WHERE problem_id = :problem_id AND user_id = :user_id",problem_id=problem_id,user_id=session['user_id'])
        if len(solving)==0:
            #record the time the user first saw the problem
            print(1)
            db.execute("INSERT INTO unfinished_problems (problem_id,user_id,start_time) VALUES (:problem_id,:user_id,:start_time)",
                       problem_id=problem_id,user_id=session['user_id'],start_time=now)
    

    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)
    team_account = db.execute("SELECT team_account AS team FROM users WHERE id=:id", id=session["user_id"])[0]['team'] if session.get("user_id") else False
    timed_mode = db.execute("SELECT timed_mode FROM users WHERE id=:uid", uid=session["user_id"])[0]['timed_mode'] if session.get("user_id") else False

    # Ensure problem exists
    if len(data) != 1 or (data[0]["draft"] == 1 and not check_perm(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER"])):
        return render_template("problem/problem_noexist.html"), 404
    
    # Ensure user has perms to view the problem (if private)
    org_data = db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session["user_id"]) if session.get("user_id") else []
    organizations = set([row["org_id"] for row in org_data])
    if data[0]["private"] and data[0]["private_org"] not in organizations and not check_perm(["ADMIN", "SUPERADMIN"]):
        return redirect("/problems")

    data[0]["editorial"] = read_file(f"metadata/problems/{problem_id}/editorial.md")
    data[0]["solved"] = len(
        db.execute("SELECT * FROM problem_solved WHERE user_id=? AND problem_id=?",
                   session["user_id"], problem_id)) == 1 if session.get("user_id") else False

    tag_ids = [tag['tag_id'] for tag in db.execute("SELECT tag_id FROM problem_tags WHERE problem_id=:pid", pid=problem_id)]
    tags = []

    for tid in tag_ids:
       tag_name = db.execute("SELECT name FROM tags WHERE id=:tid", tid=tid)[0]['name']
       tags.append(tag_name)

    can_next, can_prev = False, False
    nxt, prev = "", ""
    contest_problem = bool(db.execute("SELECT contest_problem AS cp FROM problems WHERE id=:pid", pid=problem_id)[0]['cp'])

    if (contest_problem):
        p_number = int(data[0]['name'].split()[-1])
        increment = lambda s: re.sub(r'(\d+)$', lambda match: str(int(match.group()) + 1).zfill(2), s)
        decrement = lambda s: re.sub(r'(\d+)$', lambda match: str(int(match.group()) - 1).zfill(2), s)
        if p_number > 1:
            can_prev = True
            prev = "/problem/"+decrement(data[0]['id'])
        if p_number < int(db.execute("SELECT contest_problem_num AS cpn FROM problems WHERE id=:pid", pid=problem_id)[0]['cpn']):
            can_next = True
            nxt = "/problem/"+increment(data[0]['id'])

    if request.method == "GET":
        return render_template('problem/problem.html', data=data[0], username=session['username'] if session.get("user_id") else "" , tags=sorted(tags), can_next=can_next, can_prev=can_prev, nxt=nxt, prev=prev, team_account=team_account, timed_mode=timed_mode, private_org_name=db.execute("SELECT name FROM organizations WHERE id=:oid", oid=data[0]["private_org"])[0]['name'] if data[0]["private"] else None)
    
    if team_account:
        flash("You are using a team account, so you aren't allowed to submit to problems!", "danger")
        return render_template('problem/problem.html', data=data[0], timed_mode=timed_mode, private_org_name=db.execute("SELECT name FROM organizations WHERE id=:oid", oid=data[0]["private_org"])[0]['name'] if data[0]["private"] else None), 400

    # Reached via POST
    ans = request.form.get("answer")
    
    if not session.get("user_id"):
        flash('You must be logged in to submit an answer', 'warning')
        return render_template('problem/problem.html', data=data[0]), 400

    if not ans:
        flash('Cannot submit an empty answer', 'danger')
        return render_template('problem/problem.html', data=data[0], timed_mode=timed_mode, private_org_name=db.execute("SELECT name FROM organizations WHERE id=:oid", oid=data[0]["private_org"])[0]['name'] if data[0]["private"] else None), 400

    if not verify_flag(ans):
        flash('Invalid answer', 'danger')
        return render_template('problem/problem.html', data=data[0], timed_mode=timed_mode, private_org_name=db.execute("SELECT name FROM organizations WHERE id=:oid", oid=data[0]["private_org"])[0]['name'] if data[0]["private"] else None), 400

    check = data[0]["flag"] == ans
    most_recent_sub_date = db.execute("SELECT date FROM submissions WHERE user_id=:uid AND correct=1 AND contest_id IS NULL ORDER BY date DESC LIMIT 1", uid=session["user_id"])
    db.execute(("INSERT INTO submissions (date, user_id, problem_id, correct, submitted) "
                "VALUES (datetime('now'), :user_id, :problem_id, :check, :flag)"),
               user_id=session["user_id"], problem_id=problem_id, check=check, flag=ans)

    if not check:
        flash('The answer you submitted was incorrect', 'danger')
        return render_template('problem/problem.html', data=data[0], timed_mode=timed_mode, private_org_name=db.execute("SELECT name FROM organizations WHERE id=:oid", oid=data[0]["private_org"])[0]['name'] if data[0]["private"] else None)

    # Check if user already solved this problem
    check = db.execute(
        "SELECT * FROM problem_solved WHERE user_id=:uid AND problem_id=:pid",
        uid=session["user_id"], pid=problem_id)
    streak_broken, streak_added, first_streak = False, False, False
    streak_bonus, new_streak = 0, 0
    if len(check) == 0:
        # Get difference in days between the most recent submission and the current submission
        current_streak = db.execute("SELECT streak FROM users WHERE id=:uid", uid=session["user_id"])[0]['streak']
        previous_AC_submissions = db.execute("SELECT date FROM submissions WHERE user_id=:uid AND correct=1", uid=session["user_id"])
        if len(most_recent_sub_date) > 0:
            most_recent_sub_date = most_recent_sub_date[0]['date']
            diff = (datetime.now(pytz.UTC).date()-pytz.utc.localize(datetime.strptime(most_recent_sub_date, "%Y-%m-%d %H:%M:%S")).date()).days
            # write_file("test2.txt", f"{previous_AC_submissions}\n{most_recent_sub_date}\n{diff}\n{datetime.now(pytz.UTC)}\n{pytz.utc.localize(datetime.strptime(most_recent_sub_date, '%Y-%m-%d %H:%M:%S'))}")
            if diff == 1 or current_streak == 0:
                streak_added = True
                db.execute("UPDATE users SET streak=streak+1 WHERE id=:uid", uid=session["user_id"])
            elif diff > 1:
                streak_broken = True
                db.execute("UPDATE users SET streak=1 WHERE id=:uid", uid=session["user_id"])
        elif len(previous_AC_submissions) == 1:
            db.execute("UPDATE users SET streak=1 WHERE id=:uid", uid=session["user_id"])
            first_streak = True
        new_streak = db.execute("SELECT streak FROM users WHERE id=:uid", uid=session["user_id"])[0]['streak']

        # bonus is logarithm function
        streak_bonus = floor(log(max(1, new_streak)))

        #calculate time taken
        solved=db.execute("SELECT * FROM unfinished_problems WHERE user_id=:user_id AND problem_id=:problem_id",user_id=session['user_id'],problem_id=problem_id)
        start_time=solved[0]['start_time']
        start_time=datetime.fromisoformat(start_time)

        delta=datetime.now()-start_time
        delta=delta.total_seconds()

        db.execute("INSERT INTO problem_solved(user_id, problem_id, time_taken) VALUES(:uid, :pid, :time_taken)",
                   uid=session["user_id"], pid=problem_id, time_taken=delta)

        db.execute("DELETE FROM unfinished_problems WHERE problem_id=:problem_id AND user_id=:user_id",problem_id=problem_id,user_id=session['user_id'])

        # Update total points and problems solved
        db.execute(("UPDATE users SET total_points=total_points+:pv, "
                    "problems_solved=problems_solved+1 WHERE id=:uid"),
                   pv=int(data[0]["point_value"])+streak_bonus, uid=session["user_id"])

    data[0]["solved"] = True
    flash('Congratulations! You have solved this problem!', 'success')

    return render_template('problem/problem.html', data=data[0], username=session['username'], can_next=can_next, can_prev=can_prev, nxt=nxt, prev=prev, streak_broken=streak_broken, streak_added=streak_added, first_streak=first_streak, new_streak=new_streak, timed_mode=timed_mode, streak_bonus=streak_bonus, private_org_name=db.execute("SELECT name FROM organizations WHERE id=:oid", oid=data[0]["private_org"])[0]['name'] if data[0]["private"] else None)


@api.route('<problem_id>/publish', methods=["POST"])
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def publish_problem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) != 1:
        return render_template("problem/problem_noexist.html"), 404

    # Ensure user has perms to view the problem (if private)
    org_data = db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session["user_id"]) if session.get("user_id") else []
    organizations = set()
    for row in org_data:
        organizations.add(row["org_id"])
    if data[0]["private"] and data[0]["private_org"] not in organizations and not check_perm(["ADMIN", "SUPERADMIN"]):
        return redirect("/problems")

    db.execute("UPDATE problems SET draft=0 WHERE id=:problem_id", problem_id=problem_id)

    logger.info(f"User #{session['user_id']} ({session['username']}) published {problem_id}",  # noqa
                extra={"section": "problem"})
    flash('Problem successfully published', 'success')
    
    add_problem_into_pdatabase(problem_id)
    
    return redirect("/problem/" + problem_id)


@api.route('<problem_id>/editorial')
@login_required
def problem_editorial(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

    if data[0]["draft"] == 1 and session["admin"] != 1:
        return render_template("problem/problem_noexist.html"), 404

    # Ensure user has perms to view the problem (if private)
    org_data = db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session["user_id"]) if session.get("user_id") else []
    organizations = set()
    for row in org_data:
        organizations.add(row["org_id"])
    if data[0]["private"] and data[0]["private_org"] not in organizations and not check_perm(["ADMIN", "SUPERADMIN"]):
        return redirect("/problems")

    return render_template('problem/problemeditorial.html', data=data[0])


@api.route('<problem_id>/edit', methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def editproblem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    tags = db.execute(("SELECT t.name FROM tags t JOIN "
                       "problem_tags pt ON t.id=pt.tag_id "
                       "WHERE pt.problem_id=:pid"), pid=problem_id)

    # Extract tag names from the result
    tag_names = [tag['name'] for tag in tags]

    # Ensure user has perms to view the problem (if private)
    org_data = db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session["user_id"]) if session.get("user_id") else []
    organizations = set()
    for row in org_data:
        organizations.add(row["org_id"])
    if data[0]["private"] and data[0]["private_org"] not in organizations and not check_perm(["ADMIN", "SUPERADMIN"]):
        return redirect("/problems")

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

    if request.method == "GET":
        return render_template('problem/edit_problem.html', data=data[0], tags=sorted(tag_names))

    # Reached via POST
    
    new_name = request.form.get("name")
    new_description_md = request.form.get("description_md")
    new_description_html = request.form.get("description_html")
    new_hint_md = request.form.get("hints_md")
    new_hint_html = request.form.get("hints_html")
    new_category = data[0]["category"] if data[0]["private"] else request.form.get("category")
    new_points = int(request.form.get("point_value"))
    new_answer = request.form.get("answer")
    new_instanced = bool(request.form.get("instanced"))
    new_taglist_raw = request.form.getlist("taglist[]")
    new_taglist = set(json.loads(new_taglist_raw[0])) if new_taglist_raw else []

    if not new_name or not new_description_md or not new_category or not new_points:
        flash('You have not entered all required fields. To submit the hints or the description, you must open the markdown editor at least once.', 'danger')
        return render_template('problem/edit_problem.html', data=data[0]), 400

    if new_answer:
        if not verify_flag(new_answer):
            flash('Invalid answer', 'danger')
            return render_template('problem/edit_problem.html', data=data[0]), 400
        if request.form.get("rejudge"):
            db.execute("UPDATE submissions SET correct=0 WHERE problem_id=:pid",
                       pid=problem_id)
            db.execute(
                ("UPDATE users SET total_points=total_points-:pv, "
                 "problems_solved=problems_solved-1 WHERE id IN "
                 "(SELECT user_id FROM problem_solved WHERE problem_id=:pid)"),
                pv=data[0]["point_value"], pid=problem_id
            )
            db.execute("DELETE FROM problem_solved WHERE problem_id=:pid", pid=problem_id)
            db.execute(("UPDATE submissions SET correct=1 WHERE "
                        "problem_id=:pid AND submitted=:flag"),
                       pid=problem_id, flag=new_answer)
            db.execute(("INSERT INTO problem_solved (user_id, problem_id) "
                        "SELECT DISTINCT user_id, problem_id FROM submissions WHERE "
                        "problem_id=:pid AND correct=1"), pid=problem_id)
            db.execute(
                ("UPDATE users SET total_points=total_points+:pv, "
                 "problems_solved=problems_solved+1 WHERE id IN "
                 "(SELECT user_id FROM problem_solved WHERE problem_id=:pid)"),
                pv=data[0]["point_value"], pid=problem_id
            )
    else:
        new_answer = data[0]["flag"]

    new_description_md = new_description_md.replace('\r', '')
    if not new_hint_md:
        new_hint_md = ""

    db.execute(("UPDATE problems SET name=:name, category=:category, point_value=:pv, "
                "flag=:flag, flag_hint=:fhint, instanced=:inst WHERE id=:problem_id"),
               name=new_name, category=new_category, pv=new_points,
               problem_id=problem_id, flag=new_answer, fhint="",
               inst=new_instanced)
    db.execute(
        ("UPDATE users SET total_points=total_points+:dpv WHERE id IN "
         "(SELECT user_id FROM problem_solved WHERE problem_id=:pid)"),
        dpv=new_points - data[0]["point_value"], pid=problem_id
    )

    tags_raw = db.execute("SELECT name FROM tags")
    old_tags = [val["tag_id"] for val in db.execute("SELECT tag_id FROM problem_tags WHERE problem_id=:pid", pid=problem_id)]
    available_tags = [] if not tags_raw else set([val['name'] for val in tags_raw])
    for tag in old_tags:
        name = db.execute("SELECT name FROM tags WHERE id=:tid", tid=tag)[0]['name']
        if name not in new_taglist:
            db.execute("DELETE FROM problem_tags WHERE tag_id=:tid and problem_id=:pid", tid=tag, pid=problem_id)
    already_there_raw = db.execute("SELECT tag_id FROM problem_tags WHERE problem_id=:pid", pid=problem_id)
    already_there = set([val["tag_id"] for val in already_there_raw])
    for tag in new_taglist:
        if tag not in available_tags:
            db.execute("INSERT INTO tags (name) VALUES (:name)", name=tag)
        tid = db.execute("SELECT id FROM tags WHERE name=:name", name=tag)[0]['id']
        if tid not in already_there:
            db.execute(("INSERT INTO problem_tags (tag_id, problem_id) "
                        "VALUES (:tid, :pid)"), tid=tid, pid=problem_id)

    write_file('metadata/problems/' + problem_id + '/description.md', new_description_md)
    write_file('metadata/problems/' + problem_id + '/hints.md', new_hint_md)
    write_file('metadata/problems/' + problem_id + '/description.html', new_description_html)
    write_file('metadata/problems/' + problem_id + '/hints.html', new_hint_html)

    problem_db.execute("DELETE FROM problems WHERE problem_id=:pid",pid=problem_id)
    add_problem_into_pdatabase(problem_id)

    logger.info((f"User #{session['user_id']} ({session['username']}) updated problem "
                 f"{problem_id}"), extra={"section": "problem"})
    flash('Problem successfully edited', 'success')
    return redirect("/problem/" + problem_id)


@api.route('<problem_id>/editeditorial', methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def problem_editeditorial(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

    # Ensure user has perms to view the problem (if private)
    org_data = db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session["user_id"]) if session.get("user_id") else []
    organizations = set()
    for row in org_data:
        organizations.add(row["org_id"])
    if data[0]["private"] and data[0]["private_org"] not in organizations and not check_perm(["ADMIN", "SUPERADMIN"]):
        return redirect("/problems")

    if request.method == "GET":
        return render_template('problem/edit_editorial.html', data=data[0])

    # Reached via POST

    new_editorial_md = request.form.get("editorial_md")
    new_editorial_md = new_editorial_md.replace('\r', '')

    new_editorial_html = request.form.get("editorial_html")
    new_editorial_html = new_editorial_html.replace('\r', '')
    
    if not new_editorial_md or not new_editorial_html:
        flash('You have not entered all required fields. To submit the editorial, you must open the markdown editor at least once.', 'danger')
        return render_template('problem/edit_editorial.html', data=data[0]), 400

    write_file('metadata/problems/' + problem_id + '/editorial.md', new_editorial_md)
    write_file('metadata/problems/' + problem_id + '/editorial.html', new_editorial_html)

    logger.info((f"User #{session['user_id']} ({session['username']}) updated the "
                 f"editorial for problem {problem_id}"), extra={"section": "problem"})
    flash('Editorial successfully edited', 'success')
    return redirect("/problem/" + problem_id)


@api.route('<problem_id>/delete', methods=["POST"])
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def delete_problem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

    # Ensure user has perms to view the problem (if private)
    org_data = db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session["user_id"]) if session.get("user_id") else []
    organizations = set()
    for row in org_data:
        organizations.add(row["org_id"])
    if data[0]["private"] and data[0]["private_org"] not in organizations and not check_perm(["ADMIN", "SUPERADMIN"]):
        return redirect("/problems")

    db.execute("BEGIN")
    db.execute("DELETE FROM problems WHERE id=:pid", pid=problem_id)
    db.execute(
        ("UPDATE users SET total_points=total_points-:pv, "
         "problems_solved=problems_solved-1 WHERE id IN "
         "(SELECT user_id FROM problem_solved WHERE problem_id=:pid)"),
        pv=data[0]["point_value"], pid=problem_id
    )
    db.execute("DELETE FROM problem_solved WHERE problem_id=:pid", pid=problem_id)
    db.execute("DELETE FROM problem_tags WHERE problem_id=:pid", pid=problem_id)
    db.execute("DELETE FROM submissions WHERE problem_id=:pid", pid=problem_id)
    db.execute("COMMIT")
    shutil.rmtree(f"metadata/problems/{problem_id}")

    problem_db.execute("DELETE FROM problems WHERE problem_id=:pid",pid=problem_id)

    logger.info((f"User #{session['user_id']} ({session['username']}) deleted "
                 f"problem {problem_id}"), extra={"section": "problem"})
    flash('Problem successfully deleted', 'success')
    return redirect("/problems")


@api.route('<problem_id>/download')
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def download_problem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

    # Ensure user has perms to view the problem (if private)
    org_data = db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session["user_id"]) if session.get("user_id") else []
    organizations = set()
    for row in org_data:
        organizations.add(row["org_id"])
    if data[0]["private"] and data[0]["private_org"] not in organizations and not check_perm(["ADMIN", "SUPERADMIN"]):
        return render_template("problem/problem_noexist.html"), 404

    temp_zipfile = BytesIO()
    zf = zipfile.ZipFile(temp_zipfile, 'w', zipfile.ZIP_DEFLATED)
    for file in os.listdir(f'metadata/problems/{problem_id}'):
        zf.write(f'metadata/problems/{problem_id}/' + file, file)
    if os.path.exists(f'dl/{problem_id}.zip'):
        zf.write(f'dl/{problem_id}.zip', f'{problem_id}.zip')
    zf.close()
    temp_zipfile.seek(0)
    return send_file(temp_zipfile, mimetype='zip',
                     download_name=f'{problem_id}.zip', as_attachment=True)
