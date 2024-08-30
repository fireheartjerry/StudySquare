from flask import (Blueprint, flash, redirect, render_template, request,
                   send_file, session, current_app as app)
import logging
import os
import shutil
import zipfile
from math import sqrt, pow
from re import match, search
from io import BytesIO

from helpers import *  # noqa
from db import db
from datetime import datetime, timedelta
import pytz
import random, json

api = Blueprint("contest", __name__)
logger = logging.getLogger("TOPSOJ")

@api.route("/<contest_id>")
@login_required
def contest(contest_id):
    # Ensure contest exists
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404

    team_contest = contest_info[0]["team_contest"]
    team_account = db.execute("SELECT team_account AS team FROM users WHERE id=:id", id=session["user_id"])[0]['team']
    if team_account and not team_contest:
        flash("You are using a team account, so you aren't allowed to access non-team contests!", "danger")
        return redirect("/contests")
    if not team_account and team_contest and not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER", "SITE_TESTER"]):
        flash("You are using a non-team account, so you aren't allowed to access team contests!", "danger")
        return redirect("/contests")   

    # Ensure contest started or user is admin
    started = datetime.now(pytz.UTC) > pytz.utc.localize(datetime.strptime(contest_info[0]["start"], "%Y-%m-%d %H:%M:%S"))
    if not started and not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER", "SITE_TESTER"]):
        flash('The contest has not started yet!', 'danger')
        return redirect("/contests")

    org_data = db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session["user_id"]) if session.get("user_id") else []
    organizations = set([row["org_id"] for row in org_data])
    if contest_info[0]["private"] and contest_info[0]["private_org"] not in organizations and not check_perm(["ADMIN", "SUPERADMIN"]):
        return redirect("/contests")

    title = contest_info[0]["name"]
    scoreboard_key = contest_info[0]["scoreboard_key"]
    style = db.execute("SELECT style FROM contests WHERE id=:cid", cid=contest_id)[0]['style']
    
    solved_info = db.execute(
        "SELECT problem_id FROM contest_solved WHERE contest_id=:cid AND user_id=:uid",
        cid=contest_id, uid=session["user_id"])

    solved_data = set()
    for row in solved_info:
        solved_data.add(row["problem_id"])

    data = []
    info = db.execute(
        ("SELECT * FROM contest_problems WHERE contest_id=:cid AND draft=0 "
         "GROUP BY problem_id ORDER BY problem_id ASC, category ASC;"),
        cid=contest_id)

    solve_count = dict()
    for row in db.execute(("SELECT problem_id, COUNT(user_id) AS solves FROM "
                           "contest_solved WHERE contest_id=:cid AND user_id NOT IN ("
                           "SELECT user_id FROM contest_users WHERE contest_id=:cid AND "
                           "hidden=1) GROUP BY problem_id"), cid=contest_id):
        if row["problem_id"] is None:
            continue
        solve_count[row["problem_id"]] = row["solves"]
    
    # Fetch required data outside the loop
    contest_lock_data = db.execute("SELECT DISTINCT problem_id, required_id FROM contest_lock WHERE contest_id=:cid",
                                cid=contest_id)
    contest_user_submissions = set(val["problem_id"] for val in db.execute("SELECT DISTINCT problem_id FROM submissions WHERE user_id=:uid AND contest_id=:cid", uid=session["user_id"], cid=contest_id))
    problems_with_reqs = set(row['problem_id'] for row in contest_lock_data)

    for row in info:
        problem_id = row["problem_id"]
        requirements, required_subs = [], 0
        if problem_id in problems_with_reqs:
            requirements = [req["required_id"] for req in contest_lock_data if req["problem_id"] == problem_id]
            required_subs = sum(1 for req in requirements if req in contest_user_submissions)
        keys = {
            "name": row["name"],
            "category": row["category"],
            "problem_id": problem_id,
            "solved": 1 if problem_id in solved_data else 0,
            "submitted": 1 if problem_id in contest_user_submissions else 0,
            "viewable": 1 if required_subs >= len(requirements) or style != 'guts' else 0,
            "required": sorted(requirements),
            "point_value": row["point_value"],
            "sols": solve_count[problem_id] if problem_id in solve_count else 0,
            "dynamic": 0 if row["score_users"] == -1 else 1,
        }
        data.append(keys)
    if style == 'guts':
        problems_per_set = db.execute("SELECT COUNT(category) as cnt FROM contest_problems WHERE category='Set 1'")[0]['cnt']
        viewable_categories = sorted([val['category'] for val in data if val['submitted'] and val['viewable']])
        set_numbers = [int(search(r"^Set (\d+)$", val).group(1)) for val in viewable_categories if 'Set' in val]
        highest_set = max((num for num in set_numbers if set_numbers.count(num) >= problems_per_set), default=None)
        if highest_set:
            highest_set += 1
            for row in data:
                if row['category'] == "Basic":
                    continue
                if int(row['category'].split(' ')[-1]) == highest_set:
                    break
                row['viewable'] = 2
    end_time_contest = db.execute("SELECT end FROM contests WHERE id=:id", id=contest_id)
    ended = contest_ended(end_time_contest)
    end_time_contest = end_time_contest[0]['end']
    scoreboard = contest_info[0]["scoreboard_visible"] or check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
    limit = db.execute(("SELECT default_submission_limit AS sub_lim FROM contests "
                        "WHERE id=:cid"),
                        cid=contest_id)[0]["sub_lim"]
    show_verdict = bool(db.execute("SELECT show_verdict FROM contests WHERE id=:id", id=contest_id)[0]['show_verdict'])
    id_to_names = {row['problem_id']: row['name'] for row in data}
    submitted = {row['problem_id']: row['submitted'] for row in data}

    user_info = db.execute(
        "SELECT * FROM contest_users WHERE contest_id=:cid AND user_id=:uid",
        cid=contest_id, uid=session["user_id"])
    time_left = 0
    first_time = False
    if len(user_info) == 0 and datetime.now(pytz.UTC) < pytz.utc.localize(datetime.strptime(contest_info[0]["end"], "%Y-%m-%d %H:%M:%S")):
        duration_seconds = 0
        if contest_info[0]["use_window_timer"]:
            duration_seconds = contest_info[0]['window_time_seconds']
            hours = duration_seconds // 3600
            minutes = (duration_seconds % 3600) // 60
            seconds = duration_seconds % 60
            time_left = duration_seconds
        end_time = datetime.now(pytz.UTC)+timedelta(seconds=duration_seconds) if started else pytz.utc.localize(datetime.strptime(contest_info[0]["start"], "%Y-%m-%d %H:%M:%S"))+timedelta(seconds=duration_seconds)
        rating = db.execute("SELECT rating FROM users WHERE id=:uid", uid=session["user_id"])[0]["rating"]
        db.execute("INSERT INTO contest_users (contest_id, user_id, end_time, rating) VALUES(:cid, :uid, :end_time, :rating)",
                cid=contest_id, uid=session["user_id"], end_time=end_time, rating=rating)
        db.execute("UPDATE users SET contests_completed=contests_completed+1 WHERE id=?",
                session["user_id"])
        first_time = True
    elif contest_info[0]["use_window_timer"] and started and not ended:
        end_time = pytz.utc.localize(datetime.strptime(user_info[0]["end_time"], "%Y-%m-%d %H:%M:%S"))
        current_time = datetime.now(pytz.UTC)
        duration_seconds = contest_info[0]['window_time_seconds']
        if (current_time - end_time).total_seconds() > duration_seconds and not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"]):
            flash("Your timed window for this contest has expired. You may no longer view this contest until it ends.", "danger")
            return redirect("/contests")
        else:
            time_remaining = (end_time-current_time).total_seconds()
            hours = int(time_remaining // 3600)
            minutes = int((time_remaining % 3600) // 60)
            seconds = int(time_remaining % 60)
            time_left = time_remaining
    if len(user_info) != 0 and user_info[0]["submitted"] and not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"]):
        flash("You have already submitted to this contest. You may no longer view this contest until it ends.", "danger")
        return redirect("/contests")
    ended = contest_ended(db.execute("SELECT end FROM contests WHERE id=:id", id=contest_id))
    if not ended and started:
        end_time = db.execute("SELECT end_time FROM contest_users WHERE contest_id=:cid AND user_id=:uid", cid=contest_id, uid=session['user_id'])[0]['end_time'] if contest_info[0]["use_window_timer"] else None
        if time_left:
            hours = int(time_left // 3600)
            minutes = int((time_left % 3600) // 60)
            seconds = int(time_left % 60)
            time_left = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            if time_left[0] == '-':
                time_left = "00:00:00"
    else:
        time_left = ""
        end_time = ""
        
    return render_template("contest/contest.html", title=title, scoreboard_key=scoreboard_key, data=data, ended=ended, username=session['username'], scoreboard=scoreboard, style=style, default_limit=limit, id_to_names=id_to_names, submitted=submitted, show_verdict=show_verdict, time_left=time_left, end_time=end_time, first_time=first_time, end_time_contest=end_time_contest, private=bool(contest_info[0]['private']), private_org=contest_info[0]['private_org'], org_name=db.execute("SELECT name FROM organizations WHERE id=:id", id=contest_info[0]["private_org"])[0]["name"] if bool(contest_info[0]['private']) else "", problem_cnt=db.execute("SELECT COUNT(*) as cnt FROM contest_problems WHERE contest_id=:cid", cid=contest_id)[0]['cnt'], contest_id=contest_id, rated=contest_info[0]['rated'])

@api.route('/<contest_id>/edit', methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def editcontest(contest_id):
    data = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)

    # Ensure contest exists
    if len(data) == 0:
        flash('That contest does not exist', 'danger')
        return redirect("/contests")

    if request.method == "GET":
        return render_template('contest/edit.html', data=data[0])

    # Reached via POST
    new_name = request.form.get("name")
    new_description_md = request.form.get("description_md").replace('\r', '')
    new_description_html = request.form.get("description_html").replace('\r', '')
    start = request.form.get("start")
    end = request.form.get("end")
    scoreboard_visible = bool(request.form.get("scoreboard_visible"))
    show_verdict = bool(request.form.get("show_verdict"))
    team = bool(request.form.get("team"))
    new_rated = bool(request.form.get("rated"))
    new_export_category = request.form.get("export_category")
    new_weight = float(request.form.get("weight"))

    if not new_name:
        flash('Name cannot be empty', 'danger')
        return render_template('contest/edit.html', data=data[0]), 400
    if not new_description_md or not new_description_html:
        flash('Description cannot be empty', 'danger')
        return render_template('contest/edit.html', data=data[0]), 400

    # Ensure start and end dates are valid
    check_start = pytz.utc.localize(datetime.strptime(start, "%Y-%m-%dT%H:%M:%S.%fZ"))
    check_end = pytz.utc.localize(datetime.strptime(end, "%Y-%m-%dT%H:%M:%S.%fZ"))
    if check_end < check_start:
        flash('Contest cannot end before it starts!', 'danger')
        return render_template("contest/edit.html", data=data[0]), 400
    if not (0 <= new_weight <= 1):
        flash('Contest weight must be between 0 and 1, inclusive.', 'danger')
        return render_template("contest/edit.html", data=data[0]), 400

    db.execute(("UPDATE contests SET name=?, start=datetime(?), end=datetime(?), "
                "scoreboard_visible=?, team_contest=?, show_verdict=?, export_category=?, rated=?, weight=? WHERE id=?"),
               new_name, start, end, scoreboard_visible, team, show_verdict, new_export_category, new_rated, new_weight, contest_id)

    write_file(f'metadata/contests/{contest_id}/description.md', new_description_md)
    write_file(f'metadata/contests/{contest_id}/description.html', new_description_html)

    logger.info((f"User #{session['user_id']} ({session['username']}) updated "
                 f"contest {contest_id}"), extra={"section": "contest"})
    flash('Contest successfully edited', 'success')
    return redirect("/contests")


@api.route("/<contest_id>/delete", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def delete_contest(contest_id):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html")

    if request.method == "GET":
        return render_template("contest/delete_confirm.html", data=contest_id)

    # Reached using POST

    db.execute("BEGIN")
    db.execute("DELETE FROM contests WHERE id=:cid", cid=contest_id)
    db.execute("DELETE FROM contest_users WHERE contest_id=:cid", cid=contest_id)
    db.execute("DELETE FROM contest_solved WHERE contest_id=:cid", cid=contest_id)
    db.execute("DELETE FROM contest_problems WHERE contest_id=:cid", cid=contest_id)
    db.execute("COMMIT")

    shutil.rmtree('metadata/contests/' + contest_id)

    logger.info((f"User #{session['user_id']} ({session['username']}) deleted "
                 f"contest {contest_id}"), extra={"section": "contest"})
    flash('Contest successfully deleted', 'success')
    return redirect("/contests")


@api.route("/<contest_id>/notify", methods=['GET', 'POST'])
@admin_required
def contest_notify(contest_id):
    if request.method == "GET":
        return render_template('contest/notify.html')

    subject = request.form.get("subject")
    if not subject:
        flash('Must provide subject', 'danger')
        return render_template('contest/notify.html'), 400
    message = request.form.get("message")
    if not message:
        flash('Must provide message', 'danger')
        return render_template('contest/notify.html'), 400

    data = db.execute(("SELECT email FROM contest_users JOIN users on user_id=users.id "
                       "WHERE contest_users.contest_id=:cid"),
                      cid=contest_id)
    emails = [participant["email"] for participant in data]
    if not app.config['TESTING']:
        send_email(subject, app.config['MAIL_DEFAULT_SENDER'], [], message, emails)

    logger.info((f"User #{session['user_id']} ({session['username']}) sent a "
                 f"notification email to participants of contest {contest_id}"),
                extra={"section": "problem"})
    flash('Participants successfully notified', 'success')
    return redirect("/contest/" + contest_id)


@api.route("/<contest_id>/drafts")
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def contest_drafts(contest_id):
    # Ensure contest exists
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404

    data = db.execute("SELECT * FROM contest_problems WHERE contest_id=:cid AND draft=1",
                      cid=contest_id)

    return render_template("contest/draft_problems.html",
                           title=contest_info[0]["name"], data=data)


@api.route("/<contest_id>/problem/<problem_id>", methods=["GET", "POST"])
@login_required
def contest_problem(contest_id, problem_id):
    # Ensure contest and problem exist
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404
    
    uid = session["user_id"]
    
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    org_data = db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session["user_id"]) if session.get("user_id") else []
    organizations = set([row["org_id"] for row in org_data])
    if contest_info[0]["private"] and contest_info[0]["private_org"] not in organizations and not check_perm(["ADMIN", "SUPERADMIN"]):
        return redirect("/contests")
    
    if contest_info[0]["style"] in ["amc", "aime"]:
        return redirect(f"/contest/{contest_id}")

    # check if problem is viewable if it is a guts contest
    style = db.execute("SELECT style FROM contests WHERE id=:cid", cid=contest_id)[0]['style']
    if style == 'guts':
        raw = db.execute(("SELECT DISTINCT required_id FROM contest_lock "
                                      "WHERE problem_id=:pid AND contest_id=:cid"),
                                      pid=problem_id, cid=contest_id)
        requirements = set(req["required_id"] for req in raw)
        valid = db.execute(("SELECT COUNT(DISTINCT problem_id) AS cnt FROM submissions WHERE user_id=:uid "
                            "AND contest_id=:cid_query AND problem_id IN "
                            "(SELECT DISTINCT required_id FROM contest_lock WHERE "
                            "contest_id=:cid_req AND problem_id=:pid)"),
                            uid=session["user_id"], cid_query=contest_id, cid_req=contest_id, pid=problem_id)[0]["cnt"]
        if valid != len(requirements) and not check_perm(["ADMIN", "SUPERADMIN"]):
            flash('You have not solved the required problems to view this question!', 'danger')
            return redirect(f"/contest/{contest_id}")

    # Ensure contest started or user is admin
    check = db.execute("SELECT * FROM contests WHERE id=?", contest_id)
    start = pytz.utc.localize(datetime.strptime(check[0]["start"], "%Y-%m-%d %H:%M:%S"))
    started = datetime.now(pytz.UTC) > start

    if datetime.now(pytz.UTC) < start and not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER", "SITE_TESTER"]):
        flash('The contest has not started yet!', 'danger')
        return redirect("/contests")

    check = db.execute(("SELECT * FROM contest_problems WHERE contest_id=:cid AND "
                        "problem_id=:pid"),
                        cid=contest_id, pid=problem_id)
    if len(check) != 1 or (check[0]["draft"] and not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])):
        return render_template("contest/contest_problem_noexist.html"), 404

    ended = contest_ended(db.execute("SELECT end FROM contests WHERE id=:id", id=contest_id))
    show_verdict = bool(db.execute("SELECT show_verdict FROM contests WHERE id=:id", id=contest_id)[0]['show_verdict'])

    # Check if problem is solved
    check[0]["solved"] = len(db.execute(("SELECT * FROM contest_solved WHERE contest_id=:cid AND "
                                         "problem_id=:pid AND user_id=:uid"),
                                         cid=contest_id, pid=problem_id, uid=uid)) == 1

    limit = db.execute(("SELECT submission_limit AS sub_lim FROM contest_problems "
                        "WHERE contest_id=:cid AND problem_id=:pid"),
                        cid=contest_id, pid=problem_id)[0]["sub_lim"]
    if limit == 0:
        limit = db.execute("SELECT default_submission_limit AS sub_lim FROM contests WHERE id=:cid", cid=contest_id)[0]["sub_lim"]

    total_problems = db.execute("SELECT COUNT(problem_id) AS cnt FROM contest_problems WHERE contest_id=:cid", cid=contest_id)[0]["cnt"]
    nxt, prev = "", ""
    nxt_set, prev_set = "", ""
    can_next, can_prev = False, False
    can_next_set, can_prev_set = False, False
    if style != 'guts':
        if problem_id == "basic":
            can_next = True
            nxt = "p01"
        else:
            problem_number = int(problem_id[1:])
            can_next = problem_number < total_problems
            can_prev = problem_number > 1
            if can_next:
                nxt = "p"+str(problem_number+1).zfill(2)
            if can_prev:
                prev = "p"+str(problem_number-1).zfill(2)
    else:
        if problem_id == "basic":
            can_next_set = True
            can_next = False
            can_prev = False
            nxt_set = "s1p1"
        elif problem_id != "set_bonus":
            problems_per_set = db.execute("SELECT COUNT(*) as cnt FROM contest_problems WHERE category='Set 1' AND contest_id=:cid", cid=contest_id)[0]['cnt']
            categories = db.execute("SELECT category FROM contest_problems WHERE category LIKE 'Set%'")
            total_sets = max(int(val['category'].split(' ')[-1]) for val in categories)
            set_number, problem_number = map(int, re.findall(r'\d+', problem_id))
            if set_number < total_sets:
                can_next_set = True
                nxt_set = f"s{set_number + 1}p1"
            if set_number > 1:
                can_prev_set = True
                prev_set = f"s{set_number - 1}p3"
            if problem_number < problems_per_set:
                can_next = True
                nxt = f"s{set_number}p{problem_number + 1}"
            if problem_number > 1:
                can_prev = True
                prev = f"s{set_number}p{problem_number - 1}"
    ended = contest_ended(db.execute("SELECT end FROM contests WHERE id=:id", id=contest_id))
    started = datetime.now(pytz.UTC) > pytz.utc.localize(datetime.strptime(contest_info[0]["start"], "%Y-%m-%d %H:%M:%S"))
    if not ended and started:
        end_t = db.execute(
            "SELECT end_time FROM contest_users WHERE contest_id=:cid AND user_id=:uid",
            cid=contest_id, uid=session["user_id"])[0]['end_time']
        time_left = 0
        if contest_info[0]["use_window_timer"]:
            end_time = pytz.utc.localize(datetime.strptime(end_t, "%Y-%m-%d %H:%M:%S"))
            current_time = datetime.now(pytz.UTC)
            duration_seconds = contest_info[0]['window_time_seconds']
            if (current_time - end_time).total_seconds() > duration_seconds and not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"]):
                flash("Your timed window for this contest has expired. You may no longer view this contest until it ends.", "danger")
                return redirect("/contests")
            else:
                time_remaining = (end_time-current_time).total_seconds()
                hours = int(time_remaining // 3600)
                minutes = int((time_remaining % 3600) // 60)
                seconds = int(time_remaining % 60)
                time_left = time_remaining
        end_time = db.execute("SELECT end_time FROM contest_users WHERE contest_id=:cid AND user_id=:uid", cid=contest_id, uid=session['user_id'])[0]['end_time'] if contest_info[0]["use_window_timer"] else None

        if time_left:
            hours = int(time_left // 3600)
            minutes = int((time_left % 3600) // 60)
            seconds = int(time_left % 60)
            time_left = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            if time_left[0] == '-':
                time_left = "00:00:00"
    else:
        time_left = ""
        end_time = ""
    last_sub = db.execute("SELECT submitted AS ans FROM submissions WHERE user_id=:uid AND contest_id=:cid AND problem_id=:pid ORDER BY date DESC LIMIT 1", uid=uid, cid=contest_id, pid=problem_id) 
    if request.method == "GET":
        return render_template("contest/contest_problem.html", data=check[0], ended=ended, username=session['username'], sub_lim=limit, can_next=can_next, can_prev=can_prev, nxt=nxt, prev=prev, show_verdict=show_verdict, can_next_set=can_next_set, can_prev_set=can_prev_set, nxt_set=nxt_set, prev_set=prev_set, time_left=time_left, end_time=end_time, last_sub=last_sub, private=bool(contest_info[0]['private']), private_org=contest_info[0]['private_org'], org_name=db.execute("SELECT name FROM organizations WHERE id=:id", id=contest_info[0]["private_org"])[0]["name"] if bool(contest_info[0]['private']) else "")

    # Reached via POST
    # Check if user is disqualified and in the contest
    user = db.execute(
        "SELECT * FROM contest_users WHERE user_id=:uid AND contest_id=:cid",
        uid=uid, cid=contest_id)
    if len(user) > 0 and user[0]["points"] == -999999:
        flash('You are disqualified from this contest', 'danger')
        return render_template("contest/contest_problem.html", data=check[0], sub_lim=limit, show_verdict=show_verdict, can_next=can_next, can_prev=can_prev, nxt=nxt, prev=prev, can_next_set=can_next_set, can_prev_set=can_prev_set, nxt_set=nxt_set, prev_set=prev_set, time_left=time_left, end_time=end_time, last_sub=last_sub, private=bool(contest_info[0]['private']), private_org=contest_info[0]['private_org'], org_name=db.execute("SELECT name FROM organizations WHERE id=:id", id=contest_info[0]["private_org"])[0]["name"] if bool(contest_info[0]['private']) else "")
    if len(user) == 0 and not contest_ended(db.execute("SELECT end FROM contests WHERE id=:id", id=contest_id)):
        db.execute("INSERT INTO contest_users(contest_id, user_id) VALUES (:cid, :uid)",
                   cid=contest_id, uid=uid)

    ans = request.form.get("answer")
    if not ans or not verify_flag(ans):
        flash('Invalid answer', 'danger')
        return render_template("contest/contest_problem.html", data=check[0], sub_lim=limit, show_verdict=show_verdict, can_next=can_next, can_prev=can_prev, nxt=nxt, prev=prev, can_next_set=can_next_set, can_prev_set=can_prev_set, nxt_set=nxt_set, prev_set=prev_set, time_left=time_left, end_time=end_time, last_sub=last_sub, private=bool(contest_info[0]['private']), private_org=contest_info[0]['private_org'], org_name=db.execute("SELECT name FROM organizations WHERE id=:id", id=contest_info[0]["private_org"])[0]["name"] if bool(contest_info[0]['private']) else ""), 400

    # Ensure contest hasn't ended
    if ended:
        if ans != check[0]["flag"]:
            flash('Your answer is incorrect', 'danger')
            return render_template("contest/contest_problem.html", data=check[0], sub_lim=limit, ended=ended, can_next=can_next, can_prev=can_prev, nxt=nxt, prev=prev, show_verdict=show_verdict, can_next_set=can_next_set, can_prev_set=can_prev_set, nxt_set=nxt_set, prev_set=prev_set, time_left=time_left, end_time=end_time, last_sub=last_sub, private=bool(contest_info[0]['private']), private_org=contest_info[0]['private_org'], org_name=db.execute("SELECT name FROM organizations WHERE id=:id", id=contest_info[0]["private_org"])[0]["name"] if bool(contest_info[0]['private']) else "")
        flash('Congratulations! You have solved this problem!', 'success')

        check1 = db.execute(("SELECT * FROM contest_solved WHERE contest_id=:cid "
                         "AND user_id=:uid AND problem_id=:pid"),
                        cid=contest_id, uid=uid, pid=problem_id)
        if len(check1) == 0:
            db.execute(("INSERT INTO contest_solved(contest_id, user_id, problem_id) "
                        "VALUES(:cid, :uid, :pid)"),
                       cid=contest_id, pid=problem_id, uid=uid)
            points = 0
            db.execute(("UPDATE contest_users SET lastAC=datetime('now'), "
                        "points=points+:points WHERE contest_id=:cid AND user_id=:uid"),
                       cid=contest_id, points=points, uid=uid)


        check[0]["solved"] = True
        return render_template("contest/contest_problem.html", data=check[0], sub_lim=limit, show_verdict=show_verdict, ended=ended, can_next=can_next, can_prev=can_prev, nxt=nxt, prev=prev, can_next_set=can_next_set, can_prev_set=can_prev_set, nxt_set=nxt_set, prev_set=prev_set, time_left=time_left, end_time=end_time, last_sub=last_sub, private=bool(contest_info[0]['private']), private_org=contest_info[0]['private_org'], org_name=db.execute("SELECT name FROM organizations WHERE id=:id", id=contest_info[0]["private_org"])[0]["name"] if bool(contest_info[0]['private']) else ""), 400

    sub_cnt = db.execute(("SELECT COUNT(*) AS cnt FROM submissions WHERE user_id=:uid "
                          "AND contest_id=:cid AND problem_id=:pid AND date > :start"),
                          uid=uid, cid=contest_id, pid=problem_id, start=start)[0]["cnt"]+1

    # if user is not admin or limit is infinite
    if (sub_cnt > limit and limit != -1 and started) and not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"]):
        flash(f'You have reached your submission limit of {limit} for this question. You may no longer submit.', 'warning')
        return render_template("contest/contest_problem.html", data=check[0], sub_lim=limit, show_verdict=show_verdict, can_next=can_next, can_prev=can_prev, nxt=nxt, prev=prev, can_next_set=can_next_set, can_prev_set=can_prev_set, nxt_set=nxt_set, prev_set=prev_set, time_left=time_left, end_time=end_time, last_sub=last_sub, private=bool(contest_info[0]['private']), private_org=contest_info[0]['private_org'], org_name=db.execute("SELECT name FROM organizations WHERE id=:id", id=contest_info[0]["private_org"])[0]["name"] if bool(contest_info[0]['private']) else "")

    db.execute(("INSERT INTO submissions(date, user_id, problem_id, contest_id, correct, "
         "submitted) VALUES(datetime('now'), :uid, :pid, :cid, :correct, :flag)"),
        uid=uid, pid=problem_id, cid=contest_id,
        correct=(ans == check[0]["flag"]), flag=ans)

    # Check if answer is correct
    if ans != check[0]["flag"]:
        left = str(limit-sub_cnt)
        if check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"]) or limit == -1:
            left = '\u221e' # infinity symbol
        if (show_verdict or not started) or check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"]):
            flash(f'Your answer is incorrect. You have {left} submission(s) left.', 'danger')
        else:
            flash(f'Your submission has been successfully recorded into our database. You have {left} submission(s) left.', 'success')
        return render_template("contest/contest_problem.html", data=check[0], sub_lim=limit, show_verdict=show_verdict, can_next=can_next, can_prev=can_prev, nxt=nxt, prev=prev, can_next_set=can_next_set, can_prev_set=can_prev_set, nxt_set=nxt_set, prev_set=prev_set, time_left=time_left, end_time=end_time, last_sub=last_sub, private=bool(contest_info[0]['private']), private_org=contest_info[0]['private_org'], org_name=db.execute("SELECT name FROM organizations WHERE id=:id", id=contest_info[0]["private_org"])[0]["name"] if bool(contest_info[0]['private']) else "")

    # Check if user has already found this flag
    check1 = db.execute(("SELECT * FROM contest_solved WHERE contest_id=:cid "
                         "AND user_id=:uid AND problem_id=:pid"),
                        cid=contest_id, uid=uid, pid=problem_id)
    if len(check1) == 0:
        if check[0]["score_users"] != -1:  # Dynamic scoring
            update_dyn_score(contest_id, problem_id)
        else:  # Static scoring
            db.execute(("INSERT INTO contest_solved(contest_id, user_id, problem_id) "
                        "VALUES(:cid, :uid, :pid)"),
                    cid=contest_id, pid=problem_id, uid=uid)
            points = check[0]["point_value"]
            db.execute(("UPDATE contest_users SET lastAC=datetime('now'), "
                        "points=points+:points WHERE contest_id=:cid AND user_id=:uid"),
                       cid=contest_id, points=points, uid=uid)

    check[0]["solved"] = True
    left = str(limit-sub_cnt)
    if check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"]) or limit == -1:
        left = '\u221e'
    if (show_verdict or not started) or check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"]):
        flash(f'Congratulations! You have solved this problem!\nYou have {left} submission(s) left.', 'success')
    else:
        flash(f'Your submission has been successfully recorded into our database. You have {left} submission(s) left.', 'success')
    return render_template("contest/contest_problem.html", data=check[0], ended=ended, username=session['username'], verdict_alert=check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"]) and not show_verdict, sub_lim=limit, can_next=can_next, can_prev=can_prev, nxt=nxt, prev=prev, can_next_set=can_next_set, can_prev_set=can_prev_set, nxt_set=nxt_set, prev_set=prev_set, show_verdict=show_verdict, time_left=time_left, end_time=end_time, last_sub=last_sub, private=bool(contest_info[0]['private']), private_org=contest_info[0]['private_org'], org_name=db.execute("SELECT name FROM organizations WHERE id=:id", id=contest_info[0]["private_org"])[0]["name"] if bool(contest_info[0]['private']) else "")

@api.route('/<contest_id>/submit', methods=["POST"])
@login_required
def contest_submit(contest_id):
    # Ensure contest exists
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404

    org_data = db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session["user_id"]) if session.get("user_id") else []
    organizations = set([row["org_id"] for row in org_data])
    if contest_info[0]["private"] and contest_info[0]["private_org"] not in organizations and not check_perm(["ADMIN", "SUPERADMIN"]):
        return redirect("/contests")
    
    if contest_info[0]['style'] not in ["amc", "aime"]:
        flash("This contest does not support submitting answers.", "danger")
        return redirect("/contest/" + contest_id)
    
    submitted = db.execute("SELECT submitted FROM contest_users WHERE contest_id=:cid AND user_id=:uid", cid=contest_id, uid=session["user_id"])[0]["submitted"]
    if submitted:
        flash("You have already submitted your answers.", "danger")
        return redirect("/contest/" + contest_id)
    
    problem_count = db.execute("SELECT COUNT(*) as cnt FROM contest_problems WHERE contest_id=:cid", cid=contest_id)[0]['cnt']
    user_answers, answer_key = [], []
    score = 0.0

    for i in range(1, problem_count+1):
        choice = request.form.get(f"p{i}")
        if not choice:
            choice = "blank"
        user_answers.append({"problem_id": f"p{str(i).zfill(2)}", "choice": choice})
        correct_answer = db.execute("SELECT flag FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid", cid=contest_id, pid=f"p{str(i).zfill(2)}")[0]['flag']
        answer_key.append({"problem_id": f"p{str(i).zfill(2)}", "choice": correct_answer})
        
    for i in range(1, problem_count+1):
        problem_id = f"p{str(i).zfill(2)}"
        db.execute(("INSERT INTO submissions(date, user_id, problem_id, contest_id, correct, "
            "submitted) VALUES(datetime('now'), :uid, :pid, :cid, :correct, :flag)"),
            uid=session["user_id"], pid=problem_id, cid=contest_id,
            correct=(user_answers[i-1]["choice"] == answer_key[i-1]["choice"]), flag=user_answers[i-1]["choice"])
        if user_answers[i-1]["choice"] == "blank":
            score += 1.5
        elif user_answers[i-1]["choice"] == answer_key[i-1]["choice"]:
            score += 6.0
            db.execute(("INSERT INTO contest_solved(contest_id, user_id, problem_id) "
                        "VALUES(:cid, :uid, :pid)"),
                       cid=contest_id, pid=problem_id, uid=session["user_id"])

    db.execute(("UPDATE contest_users SET lastAC=datetime('now'), "
            "points=:points, submitted=1 WHERE contest_id=:cid AND user_id=:uid"),
           cid=contest_id, points=score, uid=session["user_id"])
    
    message = "Your answers have been submitted into our database."
    if contest_info[0]['scoreboard_visible']:
        message += " You can view the scoreboard to see your results and ranking."
    flash(message, "success")
    return redirect("/contest/" + contest_id)
            
            
@api.route('/<contest_id>/problem/<problem_id>/delete', methods=["POST"])
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def delete_contest_problem(contest_id, problem_id):
    data = db.execute(("SELECT * FROM contest_problems WHERE "
                      "problem_id=:pid AND contest_id=:cid"), pid=problem_id, cid=contest_id)

    # Ensure problem exists
    if not data:
        return render_template("contest/contest_problem_noexist.html"), 404

    db.execute("BEGIN")
    db.execute(("DELETE FROM contest_problems WHERE "
                "problem_id=:pid AND contest_id=:cid"), pid=problem_id, cid=contest_id)
    db.execute(
        ("UPDATE contest_users SET points=points-:pv WHERE user_id IN "
         "(SELECT user_id FROM contest_solved WHERE contest_id=:cid AND problem_id=:pid)"),
        pv=data[0]["point_value"], cid=contest_id, pid=problem_id
    )
    db.execute("DELETE FROM contest_solved WHERE contest_id=:cid AND problem_id=:pid", cid=contest_id, pid=problem_id)
    db.execute("DELETE FROM submissions WHERE contest_id=:cid AND problem_id=:pid", cid=contest_id, pid=problem_id)
    db.execute("COMMIT")
    shutil.rmtree(f"metadata/contests/{contest_id}/{problem_id}")

    logger.info((f"User #{session['user_id']} ({session['username']}) deleted "
                 f"problem {problem_id} from contest {contest_id}"), extra={"section": "contest"})
    flash('Problem successfully deleted', 'success')
    return redirect("/contest/" + contest_id)

@api.route("/<contest_id>/problem/<problem_id>/publish", methods=["POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def publish_contest_problem(contest_id, problem_id):
    # Ensure contest and problem exist
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    check = db.execute(
        "SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid",
        cid=contest_id, pid=problem_id)

    if len(check) != 1:
        return render_template("contest/contest_problem_noexist.html"), 404

    db.execute(
        "UPDATE contest_problems SET draft=0 WHERE problem_id=:pid AND contest_id=:cid",
        pid=problem_id, cid=contest_id)

    logger.info((f"User #{session['user_id']} ({session['username']}) published "
                 f"{problem_id} from contest {contest_id}"), extra={"section": "contest"})
    flash('Problem successfully published', 'success')
    return redirect("/contest/" + contest_id + "/problem/" + problem_id)


@api.route('/<contest_id>/problem/<problem_id>/edit', methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def edit_contest_problem(contest_id, problem_id):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    # Ensure problem exists
    data = db.execute(
        "SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid",
        cid=contest_id, pid=problem_id)
    if len(data) != 1:
        return render_template("contest/contest_problem_noexist.html"), 404

    style = db.execute("SELECT style FROM contests WHERE id=:cid", cid=contest_id)[0]['style']
    names = db.execute("SELECT name FROM contest_problems where contest_id=:cid", cid=contest_id)
    ids = db.execute("SELECT problem_id FROM contest_problems where contest_id=:cid", cid=contest_id)
    prob_list = [f"{name['name']} ({problem['problem_id']})" for name, problem in zip(names, ids)]
    req_raw = db.execute("SELECT DISTINCT required_id FROM contest_lock WHERE problem_id=:pid", pid=problem_id)
    requirements = [req['required_id'] for req in req_raw]

    if request.method == "GET":
        return render_template('contest/edit_problem.html', data=data[0], style=style, prob_list=prob_list, requirements=requirements)

    # Reached via POST

    new_name = request.form.get("name")
    new_description_md = request.form.get("description_md")
    new_description_html = request.form.get("description_html")
    new_hint_md = request.form.get("hints_md")
    new_hint_html = request.form.get("hints_html")
    new_category = request.form.get("category")
    new_points = request.form.get("point_value")
    new_flag = request.form.get("answer")
    new_instanced = bool(request.form.get("instanced"))

    if (not new_name or not new_description_md or not new_category
            or (not new_points and data[0]["score_users"] == -1)):
        flash('You have not entered all required fields', 'danger')
        return render_template('contest/edit_problem.html', data=data[0]), 400

    if new_flag:
        if not verify_flag(new_flag):
            flash('Invalid answer', 'danger')
            return render_template('contest/edit_problem.html', data=data[0]), 400
        if request.form.get("rejudge"):
            rejudge_contest_problem(contest_id, problem_id, new_flag)
    else:
        new_flag = data[0]["flag"]
        new_flag_hint = data[0]["flag_hint"]

    new_description_md = new_description_md.replace('\r', '')
    new_description_html = new_description_html.replace('\r', '')
    if not new_hint_md:
        new_hint_md = ""
        new_hint_html = ""

    # Only edit score for statically scored problems whose value has changed
    if data[0]["score_users"] == -1 and data[0]["point_value"] != new_points:
        point_change = int(new_points) - data[0]["point_value"]
        db.execute(("UPDATE contest_users SET points=points+:point_change WHERE "
                    "contest_id=:cid AND user_id IN (SELECT user_id FROM contest_solved "
                    "WHERE contest_id=:cid AND problem_id=:pid)"),
                   point_change=point_change, cid=contest_id, pid=problem_id)
        db.execute(("UPDATE contest_problems SET point_value=:pv WHERE contest_id=:cid "
                    "AND problem_id=:pid"),
                   pv=int(new_points), cid=contest_id, pid=problem_id)

    db.execute(("UPDATE contest_problems SET name=:name, category=:category, flag=:flag, "
                "flag_hint=:fhint, instanced=:inst WHERE contest_id=:cid AND problem_id=:pid"),
               name=new_name, category=new_category, flag=new_flag, cid=contest_id,
               pid=problem_id, fhint="", inst=new_instanced)

    if style == 'guts':
        required_problems = set(request.form.getlist("selected_problems[]"))
        existing_problems_raw = db.execute("SELECT DISTINCT problem_id FROM contest_lock WHERE contest_id=:cid AND problem_id=:pid", cid=contest_id, pid=problem_id)
        existing_problems = set([prob['problem_id'] for prob in existing_problems_raw])
        for existing_problem in existing_problems:
            if existing_problem not in required_problems:
                db.execute("DELETE FROM contest_lock WHERE contest_id=:cid AND problem_id=:pid",
                        cid=contest_id, pid=existing_problem)
        for requirement in required_problems:
            if requirement in existing_problems:
                continue
            db.execute(("INSERT INTO contest_lock(contest_id, problem_id, required_id) "
                    " VALUES(:cid, :pid, :rid)"),
                    cid=contest_id, pid=problem_id, rid=requirement)

    write_file(f'metadata/contests/{contest_id}/{problem_id}/description.md', new_description_md)
    write_file(f'metadata/contests/{contest_id}/{problem_id}/hints.md', new_hint_md)
    write_file(f'metadata/contests/{contest_id}/{problem_id}/description.html', new_description_html)
    write_file(f'metadata/contests/{contest_id}/{problem_id}/hints.html', new_hint_html)

    logger.info((f"User #{session['user_id']} ({session['username']}) edited problem "
                 f"{problem_id} in contest {contest_id}"),
                extra={"section": "contest"})
    flash('Problem successfully edited', 'success')
    return redirect("/contest/" + contest_id + "/problem/" + problem_id)


@api.route("/<contest_id>/scoreboard")
@login_required
def contest_scoreboard(contest_id):
    # Ensure contest exists
    ended = contest_ended(db.execute("SELECT end FROM contests WHERE id=:id", id=contest_id))
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404
    
    started = datetime.now(pytz.UTC) > pytz.utc.localize(datetime.strptime(contest_info[0]["start"], "%Y-%m-%d %H:%M:%S"))

    # Ensure proper permissions
    if not (contest_info[0]["scoreboard_visible"] or check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])):
        flash('You are not allowed to view the scoreboard!', 'danger')
        return redirect(request.referrer)

    user_data = db.execute("SELECT points FROM contest_users WHERE user_id=:uid", uid=session["user_id"])
    if not user_data and not ended:
        flash("You are not allowed to view the scoreboard unless you participate in this contest!", 'danger')
        return redirect("/contests")

    org_data = db.execute("SELECT org_id FROM organization_members WHERE user_id=:uid", uid=session["user_id"]) if session.get("user_id") else []
    organizations = set([row["org_id"] for row in org_data])
    if contest_info[0]["private"] and contest_info[0]["private_org"] not in organizations and not check_perm(["ADMIN", "SUPERADMIN"]):
        return redirect("/contests")

    data = db.execute(
        ("SELECT contest_users.user_id, contest_users.points, contest_users.lastAC, users.username, users.rating FROM contest_users "
        "JOIN users ON contest_users.user_id = users.id "
        "WHERE contest_users.contest_id = :cid AND contest_users.hidden = 0 "
        "ORDER BY contest_users.points DESC, contest_users.lastAC ASC"),
        cid=contest_id)
    
    def custom_sort(row):
        return (-row['points'], row['time_taken'][0])

    end_time_contest = db.execute("SELECT end FROM contests WHERE id=:id", id=contest_id)
    ended = contest_ended(end_time_contest)


    if contest_info[0]['use_window_timer'] and started:
        end_time = db.execute("SELECT user_id, end_time FROM contest_users WHERE contest_id=:cid", cid=contest_id)
        end_time = {row['user_id'] : pytz.utc.localize(datetime.strptime(row['end_time'], "%Y-%m-%d %H:%M:%S")) for row in end_time if row['end_time']}
        
        for row in data:
            if row['lastAC']:
                row['lastAC'] = pytz.utc.localize(datetime.strptime(row['lastAC'], "%Y-%m-%d %H:%M:%S"))
                row['time_taken'] = [int(contest_info[0]['window_time_seconds']-(end_time[row['user_id']] - row['lastAC']).total_seconds())]
                hours = int(row['time_taken'][0] // 3600)
                minutes = int((row['time_taken'][0] % 3600) // 60)
                seconds = int(row['time_taken'][0] % 60)
                row['time_taken'].append(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            else:
                row['time_taken'] = [0, "00:00:00"]
            user_end_time = end_time[row['user_id']] if not ended else datetime.now(pytz.UTC)
            row['window_ended'] = user_end_time < datetime.now(pytz.UTC) or ended
            row['start_time'] = user_end_time - timedelta(seconds=contest_info[0]['window_time_seconds'])
        data.sort(key=custom_sort)
    if check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"]):
        hidden = db.execute(
            ("SELECT user_id, points, lastAC, username FROM contest_users "
             "JOIN users on user_id=users.id WHERE contest_users.contest_id=:cid AND "
             "hidden=1 ORDER BY points DESC, lastAC ASC"),
            cid=contest_id)
    else:
        hidden = db.execute(
            ("SELECT user_id, points, lastAC, username FROM contest_users "
             "JOIN users on user_id=users.id WHERE contest_users.contest_id=:cid AND "
             "hidden=1 AND user_id=:uid ORDER BY points DESC, lastAC ASC"),
            cid=contest_id, uid=session["user_id"])

    if not ended and started:
        end_t = db.execute(
            "SELECT end_time FROM contest_users WHERE contest_id=:cid AND user_id=:uid",
            cid=contest_id, uid=session["user_id"])[0]['end_time']
        time_left = 0
        if contest_info[0]["use_window_timer"]:
            end_time = pytz.utc.localize(datetime.strptime(end_t, "%Y-%m-%d %H:%M:%S"))
            current_time = datetime.now(pytz.UTC)
            duration_seconds = contest_info[0]['window_time_seconds']
            if (current_time - end_time).total_seconds() > duration_seconds and not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"]):
                flash("Your timed window for this contest has expired. You may no longer view this contest until it ends.", "danger")
                return redirect("/contests")
            else:
                time_remaining = (end_time-current_time).total_seconds()
                hours = int(time_remaining // 3600)
                minutes = int((time_remaining % 3600) // 60)
                seconds = int(time_remaining % 60)
                time_left = time_remaining
        end_time = db.execute("SELECT end_time FROM contest_users WHERE contest_id=:cid AND user_id=:uid", cid=contest_id, uid=session['user_id'])[0]['end_time'] if contest_info[0]["use_window_timer"] else None

        if time_left:
            hours = int(time_left // 3600)
            minutes = int((time_left % 3600) // 60)
            seconds = int(time_left % 60)
            time_left = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            if time_left[0] == '-':
                time_left = "00:00:00"
    else:
        time_left = 0
        end_time = "00:00:00"
    return render_template("contest/scoreboard.html",
                           title=contest_info[0]["name"], data=data, window_time=contest_info[0]["use_window_timer"], hidden=hidden, ended=ended, time_left=time_left, end_time=end_time, started=started, style=contest_info[0]["style"])


@api.route("/<contest_id>/scoreboard/ban", methods=["POST"])
@admin_required
def contest_dq(contest_id):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    user_id = request.form.get("user_id")
    if not user_id:
        flash("No user ID specified, please try again", "danger")
        return redirect("/contest/" + contest_id + "/scoreboard")

    db.execute(
        "UPDATE contest_users SET points=-999999 WHERE user_id=:uid AND contest_id=:cid",
        uid=user_id, cid=contest_id)
    
    flash("Successfully disqualified user", "success")

    logger.info((f"User #{user_id} banned from contest {contest_id} by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "contest"})
    return redirect("/contest/" + contest_id + "/scoreboard")


@api.route("/<contest_id>/scoreboard/hide", methods=["POST"])
@admin_required
def contest_hide(contest_id):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    user_id = request.form.get("user_id")
    if not user_id:
        flash("No user ID specified, please try again", "danger")
        return redirect("/contest/" + contest_id + "/scoreboard")

    db.execute(
        "UPDATE contest_users SET hidden=1 WHERE user_id=:uid AND contest_id=:cid",
        uid=user_id, cid=contest_id)
    
    flash("Successfully hidden user", "success")

    logger.info((f"User #{user_id} hidden from contest {contest_id} by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "contest"})
    return redirect("/contest/" + contest_id + "/scoreboard")


@api.route("/<contest_id>/scoreboard/unhide", methods=["POST"])
@admin_required
def contest_unhide(contest_id):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    user_id = request.form.get("user_id")
    if not user_id:
        flash("No user ID specified, please try again", "danger")
        return redirect("/contest/" + contest_id + "/scoreboard")

    db.execute(
        "UPDATE contest_users SET hidden=0 WHERE user_id=:uid AND contest_id=:cid",
        uid=user_id, cid=contest_id)
    
    flash("Successfully unhidden user", "success")

    logger.info((f"User #{user_id} unhidden from contest {contest_id} by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "contest"})
    return redirect("/contest/" + contest_id + "/scoreboard")

@api.route("/<contest_id>/scoreboard/reset_timer", methods=["POST"])
@admin_required
def contest_reset(contest_id):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    user_id = request.form.get("user_id")
    if not user_id:
        flash("No user ID specified, please try again", "danger")
        return redirect("/contest/" + contest_id + "/scoreboard")
    
    duration_seconds = db.execute("SELECT window_time_seconds as duration FROM contests WHERE id=:cid", cid=contest_id)[0]['duration']
    db.execute(
        "UPDATE contest_users SET end_time=:end_time WHERE user_id=:uid AND contest_id=:cid",
        uid=user_id, cid=contest_id, end_time=datetime.now(pytz.UTC) + timedelta(seconds=duration_seconds))
    flash("Successfully reset user's time window", "success")

    logger.info((f"User #{user_id}'s time window has been reset from contest {contest_id} by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "contest"})
    return redirect("/contest/" + contest_id + "/scoreboard")

@api.route("/<contest_id>/addproblem", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def contest_add_problem(contest_id):
    # Ensure contest exists
    contest_info = db.execute(
        "SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404

    # Ensure contest hasn't ended
    if contest_ended(contest_info):
        flash('This contest has already ended', 'danger')
        return redirect('/contest/' + contest_id)
    
    style = contest_info[0]['style']
    names = db.execute("SELECT name FROM contest_problems where contest_id=:cid", cid=contest_id)
    ids = db.execute("SELECT problem_id FROM contest_problems where contest_id=:cid", cid=contest_id)
    prob_list = [f"{name['name']} ({problem['problem_id']})" for name, problem in zip(names, ids)]
    
    if request.method == "GET":
        return render_template("contest/create_problem.html", style=style, prob_list=prob_list)

    # Reached via POST

    problem_id = request.form.get("id")
    name = request.form.get("name")
    description_md = request.form.get("description_md")
    description_html = request.form.get("description_html")
    hints_md = request.form.get("hints_md")
    hints_html = request.form.get("hints_html")
    category = request.form.get("category")
    answer = request.form.get("answer")
    draft = 1 if request.form.get("draft") else 0
    flag_hint = request.form.get("flag_hint")
    submission_limit = int(request.form.get("submission_limit"))

    if not flag_hint:
        flag_hint = ""
    instanced = bool(request.form.get("instanced"))

    if not problem_id or not name or not description_md or not description_html or not category or not answer:
        flash('You have not entered all required fields', 'danger')
        return render_template("contest/create_problem.html"), 400

    # Check if problem ID is valid
    if not verify_text(problem_id):
        flash('Invalid problem ID', 'danger')
        return render_template("contest/create_problem.html"), 400

    # Check if flag is valid
    if not verify_flag(answer):
        flash('Invalid answer', 'danger')
        return render_template("contest/create_problem.html"), 400

    if submission_limit < -1:
        flash('Submission limit must be -1, 0, or a positive integer', 'danger')
        return render_template("contest/create_problem.html"), 400

    if style == "guts":
        if submission_limit not in [0, 1]:
            flash('This problem is in a guts contest, so the submission limit MUST be 1', 'danger')
            return render_template("contest/create_problem.html"), 400
        if category != "Basic" and not match(r"^Set (\d+)$", category):
            flash("Since this is a guts contest, the category must either be 'Basic' or match the following regex: \"^Set \d+$\" (Set followed by a number).", 'danger')
            return render_template("contest/create_problem.html"), 400

    # Ensure problem does not already exist
    problem_info = db.execute(("SELECT * FROM contest_problems WHERE contest_id=:cid AND "
                               "(problem_id=:pid OR name=:name)"),
                              cid=contest_id, pid=problem_id, name=name)
    if len(problem_info) != 0:
        flash('A problem with this name or ID already exists', 'danger')
        return render_template("contest/create_problem.html"), 409

    description_md = description_md.replace('\r', '')
    description_html = description_html.replace('\r', '')

    # Check for static vs dynamic scoring
    score_type = request.form.get("score_type")
    if score_type == "dynamic":
        min_points = request.form.get("min_point_value")
        max_points = request.form.get("max_point_value")
        users_decay = request.form.get("users_point_value")
        if not min_points or not max_points or not users_decay:
            flash('You have not entered all required fields', 'danger')
            return render_template("contest/create_problem.html"), 400

        # Modify problems table
        db.execute(("INSERT INTO contest_problems VALUES(:cid, :pid, :name, :pv, "
                    ":category, :flag, :draft, :min, :max, :users, :fhint, :inst, :sub_lim)"),
                   cid=contest_id, pid=problem_id, name=name, pv=max_points,
                   category=category, flag=answer, draft=draft, min=min_points,
                   max=max_points, users=users_decay, fhint=flag_hint, inst=instanced, sub_lim=submission_limit)
    else:  # assume static
        point_value = request.form.get("point_value")
        if not point_value:
            flash('You have not entered all required fields', 'danger')
            return render_template("contest/create_problem.html"), 400

        # Modify problems table
        db.execute(("INSERT INTO contest_problems(contest_id, problem_id, name, "
                    "point_value, category, flag, draft, flag_hint, instanced, submission_limit) "
                    "VALUES(:cid, :pid, :name, :pv, :category, :flag, :draft, "
                    ":fhint, :inst, :sub_lim)"),
                   cid=contest_id, pid=problem_id, name=name, pv=point_value,
                   category=category, flag=answer, draft=draft, fhint=flag_hint,
                   inst=instanced, sub_lim=submission_limit)
    
    # if this problem is in a guts contest, add the requirements to contest_lock
    if style == "guts":
        required_problems = request.form.getlist("selected_problems[]")
        for requirement in required_problems:
            if requirement:
                db.execute(("INSERT INTO contest_lock(contest_id, problem_id, required_id) "
                            "VALUES(:cid, :pid, :rid)"),
                            cid=contest_id, pid=problem_id, rid=requirement)

    # Check if file exists & upload if it does
    file = request.files["file"]
    if file.filename:
        if not os.path.exists("dl/" + contest_id):
            os.makedirs("dl/" + contest_id)
        filename = problem_id + ".zip"
        filepath = "dl/" + contest_id + "/"
        file.save(filepath + filename)
        description_md += f'\n\n[{filename}](/{filepath + filename})'

    os.makedirs(f'metadata/contests/{contest_id}/{problem_id}')
    write_file(f'metadata/contests/{contest_id}/{problem_id}/description.md', description_md)
    write_file(f'metadata/contests/{contest_id}/{problem_id}/description.html', description_html)
    write_file(f'metadata/contests/{contest_id}/{problem_id}/hints.md', hints_md)
    write_file(f'metadata/contests/{contest_id}/{problem_id}/hints.html', hints_html)

    # Go to contest page on success
    flash('Problem successfully created', 'success')
    logger.info((f"User #{session['user_id']} ({session['username']}) added problem "
                 f"{problem_id} to contest {contest_id}"),
                extra={"section": "contest"})
    return redirect("/contest/" + contest_id + "/problem/" + problem_id)

@api.route('/<contest_id>/rate', methods=['POST'])
@admin_required
def rate_contest(contest_id):
    # Fetch contest information
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404
    
    if not contest_ended(contest_info):
        flash("This contest has not yet ended.", "danger")
        return redirect(f"/contest/{contest_id}")
    
    contest_info = contest_info[0]

    if not contest_info['rated']:
        flash("This contest is not rated.", "danger")
        return redirect(f"/contest/{contest_id}")

    def prob(ra, rb):
        return 1 / (1 + 10**((rb - ra) / 400))

    def getrankrating(contestants, rank):
        left, right = 1, 8000
        while right - left > 1:
            mid = (left + right) // 2
            seed_mid = 1 + sum(prob(u['rating'], mid) for u in contestants)
            print(seed_mid, mid)
            if seed_mid < rank:
                right = mid
            else:
                left = mid
        print(rank, left)
        # print(e)
        return left

    # Fetch user data
    user_data = db.execute("SELECT * FROM contest_users WHERE contest_id=:cid AND hidden=0", cid=contest_id)
    
    # Fetch end times
    end_time_data = db.execute("SELECT user_id, end_time FROM contest_users WHERE contest_id=:cid AND hidden=0", cid=contest_id)
    end_times = {row['user_id']: pytz.utc.localize(datetime.strptime(row['end_time'], "%Y-%m-%d %H:%M:%S")) for row in end_time_data if row['end_time']}
    
    # Process time taken for each user
    for row in user_data:
        if contest_info['use_window_timer']:
            if row['lastAC']:
                row['lastAC'] = pytz.utc.localize(datetime.strptime(row['lastAC'], "%Y-%m-%d %H:%M:%S"))
                row['time_taken'] = [int(contest_info['window_time_seconds'] - (end_times[row['user_id']] - row['lastAC']).total_seconds())]
            else:
                row['time_taken'] = [0, "00:00:00"]
        else:
            if not row['lastAC']:
                row['time_taken'] = [0]
            else:
                lastAC_time = pytz.utc.localize(datetime.strptime(row['lastAC'], "%Y-%m-%d %H:%M:%S"))
                contest_start = pytz.utc.localize(datetime.strptime(contest_info['start'], "%Y-%m-%d %H:%M:%S"))
                row['time_taken'] = [int((lastAC_time - contest_start).total_seconds())]

    # Sort users by points and time_taken
    contest_users = sorted(user_data, key=lambda row: (-row['points'], row['time_taken'][0]))

    # Add necessary data
    for rank, row in enumerate(contest_users):
        row['rating'] = 1000 if not row['rating'] else row['rating']
        row['rank'] = rank + 1
    
    for row in contest_users:
        row['seed'] = 1 + sum(prob(u['rating'], row['rating']) for u in contest_users if u != row)
    
    for row in contest_users:
        rank = sqrt(row['rank']*row['seed'])
        row['rating_needed'] = getrankrating(contest_users, rank)
        row['rating_delta'] = (row['rating_needed'] - row['rating']) // 2

    # Sort users by rating desc
    contest_users.sort(key=lambda row: row['rating'], reverse=True)
    
    # Ensure total rating delta does not exceed 0
    inc = (-sum(row['rating_delta'] for row in contest_users) / len(contest_users)) - 1
    for row in contest_users:
        row['rating_delta'] += inc
        
    # Prevent rating inflation
    zero_sum_cnt = min(4*sqrt(len(contest_users)), len(contest_users))
    inc = min(max((-sum(row['rating_delta'] for row in contest_users[:int(zero_sum_cnt)]) / zero_sum_cnt), -10), 0)
    for row in contest_users:
        row['rating_delta'] += inc
    
    # Validate the rating deltas
    contest_users.sort(key=lambda row: row['points'], reverse=True)
    for i in range(len(contest_users)):
        for j in range(i+1, len(contest_users)):
            if contest_users[i]['rating'] > contest_users[j]['rating']:
                if contest_users[i]['rating'] + contest_users[i]['rating_delta'] >= contest_users[j]['rating'] + contest_users[j]['rating_delta']:
                    raise RuntimeError(f"First rating invarient failed while comparing {contest_users[i]['user_id']} and {contest_users[j]['user_id']}")
            if contest_users[i]['rating'] < contest_users[j]['rating']:
                if contest_users[i]['rating_delta'] >= contest_users[j]['rating_delta']:
                    raise RuntimeError(f"Second rating invarient failed while comparing {contest_users[i]['user_id']} and {contest_users[j]['user_id']}")
    
    # Update user ratings in the database
    for row in contest_users:
        if row['rating_delta'] > 0:
            new_rating = int(row['rating'] + (1+float(contest_info["weight"]))*float(row['rating_delta']))
        else:
            new_rating = int(row['rating'] + float(row['rating_delta']))
        user_id = row['user_id']
        db.execute("UPDATE users SET rating=:rating WHERE id=:uid", rating=new_rating, uid=user_id)
        db.execute("INSERT INTO rating_updates(user_id, contest_id, rating, date) VALUES(:uid, :cid, :rating, :contest_end)", uid=user_id, cid=contest_id, rating=new_rating, contest_end=contest_info['end'])

    logger.info((f"User #{session['user_id']} ({session['username']}) rated contest {contest_id}"
                    f"{contest_id}"),
                    extra={"section": "problem"})
    flash("Contest successfully rated", "success")
    return redirect(f"/contest/{contest_id}")

@api.route('/<contest_id>/problem/<problem_id>/export', methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def export_contest_problem(contest_id, problem_id):
    # Ensure contest exists
    data1 = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(data1) != 1:
        return render_template("contest/contest_noexist.html"), 404
    
    if data1[0]['private']:
        return redirect('/contest/' + contest_id)

    # Ensure problem exists
    data = db.execute(
        "SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid",
        cid=contest_id, pid=problem_id)
    if len(data) != 1:
        return render_template("contest/contest_problem_noexist.html"), 404

    if request.method == "GET":
        if not contest_ended(data1):
            flash("Are you sure? The contest hasn't ended yet", 'warning')
        return render_template('contest/export_problem.html', data=data[0])

    # Reached via POST

    new_id = contest_id + "-" + problem_id  # this should be safe already

    check = db.execute("SELECT * FROM problems WHERE id=:id", id=new_id)
    if len(check) != 0:
        flash('This problem has already been exported', 'danger')
        return render_template('contest/export_problem.html', data=data[0])

    new_name = data1[0]["name"] + " - " + data[0]["name"]

    # change points value
    if request.form.get("point_value"):
        new_points = request.form.get("point_value")
    else:
        new_points = data[0]["point_value"]

    # Insert into problems databases
    db.execute(("INSERT INTO problems(id, name, point_value, category, flag) "
                "VALUES(:id, :name, :pv, :cat, :flag)"),
               id=new_id, name=new_name, pv=new_points,
               cat=data1[0]["export_category"] if data1[0]['style'] == "guts" else data[0]['category'], flag=data[0]["flag"])

    db.execute("INSERT INTO problem_solved(user_id, problem_id) SELECT user_id, :new_id "
               "FROM contest_solved WHERE contest_id=:cid AND problem_id=:pid",
               new_id=new_id, cid=contest_id, pid=problem_id)

    # Add duplicate submissions (allows rejudging and searching)
    db.execute(("INSERT INTO submissions(date, user_id, problem_id, correct, submitted) "
                "SELECT date, user_id, ?, correct, submitted FROM submissions WHERE "
                "contest_id=? AND problem_id=?"), new_id, contest_id, problem_id)

    # Update global user stats
    db.execute(("UPDATE users SET total_points=total_points+:nv, "
                "problems_solved=problems_solved+1 WHERE id IN (SELECT user_id FROM "
                "contest_solved WHERE contest_id=:cid AND problem_id=:pid)"),
                nv=new_points, cid=contest_id, pid=problem_id)

    os.makedirs(f'metadata/problems/{new_id}')
    shutil.copy(f'metadata/contests/{contest_id}/{problem_id}/description.md',
                f'metadata/problems/{new_id}/description.md')
    shutil.copy(f'metadata/contests/{contest_id}/{problem_id}/hints.md',
                f'metadata/problems/{new_id}/hints.md')
    shutil.copy(f'metadata/contests/{contest_id}/{problem_id}/description.html',
                f'metadata/problems/{new_id}/description.html')
    shutil.copy(f'metadata/contests/{contest_id}/{problem_id}/hints.html',
                f'metadata/problems/{new_id}/hints.html')
    open(f'metadata/problems/{new_id}/editorial.md', 'w').close()

    logger.info((f"User #{session['user_id']} ({session['username']}) exported problem "
                 f"{problem_id} from contest {contest_id} to {new_id}"),
                extra={"section": "problem"})
    flash('Problem successfully exported', 'success')
    return redirect("/problem/" + new_id)


@api.route('/<contest_id>/problem/<problem_id>/download')
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def download_contest_problem(contest_id, problem_id):
    temp_zipfile = BytesIO()
    zf = zipfile.ZipFile(temp_zipfile, 'w', zipfile.ZIP_DEFLATED)
    for file in os.listdir(f'metadata/contests/{contest_id}/{problem_id}'):
        zf.write(f'metadata/contests/{contest_id}/{problem_id}/' + file, file)
    if os.path.exists(f'dl/{contest_id}/{problem_id}.zip'):
        zf.write(f'dl/{contest_id}/{problem_id}.zip', f'{problem_id}.zip')
    zf.close()
    temp_zipfile.seek(0)
    return send_file(temp_zipfile, mimetype='zip',
                     download_name=f'{problem_id}.zip', as_attachment=True)
