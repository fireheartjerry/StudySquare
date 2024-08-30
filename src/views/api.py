from flask import Blueprint, redirect, current_app as app
from os.path import exists
import uuid
import logging

from helpers import *  # noqa
from db import db

api = Blueprint("api", __name__)

logger = logging.getLogger("TOPSOJ")


@api.route("/")
def api_documentation():
    return redirect("https://github.com/jdabtieu/TOPSOJ/wiki/TOPSOJ-API")


@api.route("/getkey", methods=["POST"])
@login_required
def get_api_key():
    logger.info((f"User #{session['user_id']} ({session['username']}) "
                 "generated a new API key"), extra={"section": "api"})
    new_key = str(uuid.uuid4())
    db.execute("UPDATE users SET api=? WHERE id=?", new_key, session["user_id"])
    return new_key


@api.route("/publicproblem")
def public_problem():
    if "id" not in request.args:
        return json_fail("Must provide problem ID", 400)
    problem_id = request.args["id"]

    data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)
    if len(data) == 0 or (data[0]["draft"] and not api_perm(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])):
        return json_fail("Problem not found", 404)
    
    if data[0]['private']:
        return json_fail("Problem is private", 403)
    
    hints_md = read_file(f"metadata/problems/{problem_id}/hints.md")
    hints_html = read_file(f"metadata/problems/{problem_id}/hints.html")
    editorial_md = read_file(f"metadata/problems/{problem_id}/editorial.md")
    editorial_html = read_file(f"metadata/problems/{problem_id}/editorial.html") if exists(f"metadata/problems/{problem_id}/editorial.html") else ""
    description_md = read_file(f"metadata/problems/{problem_id}/description.md")
    description_html = read_file(f"metadata/problems/{problem_id}/description.html")

    returns = {
        "description_md": description_md,
        "description_html": description_html,
        "hints_md": hints_md,
        "hints_html": hints_html,
        "editorial_md": editorial_md,
        "editorial_html": editorial_html,
        "flag_hint": data[0]["flag_hint"],
    }
    return json_success(returns)

@api.route("/privateproblem")
@api_login_required
def private_problem():
    if "id" not in request.args:
        return json_fail("Must provide problem ID", 400)
    problem_id = request.args["id"]

    data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)
    if len(data) == 0 or (data[0]["draft"] and not api_perm(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])):
        return json_fail("Problem not found", 404)
    
    if not data[0]['private']:
        return json_fail("Problem is public, please use /publicproblem path", 403)
    
    if not check_perm(["ADMIN", "SUPERADMIN"]) and not db.execute("SELECT user_id FROM organization_members WHERE org_id=:oid AND user_id=:uid", oid=data[0]["private_org"], uid=session["user_id"]):
        return json_fail("You do not have permission to view this problem", 403)
    
    hints_md = read_file(f"metadata/problems/{problem_id}/hints.md")
    hints_html = read_file(f"metadata/problems/{problem_id}/hints.html")
    editorial_md = read_file(f"metadata/problems/{problem_id}/editorial.md")
    editorial_html = read_file(f"metadata/problems/{problem_id}/editorial.html") if exists(f"metadata/problems/{problem_id}/editorial.html") else ""
    description_md = read_file(f"metadata/problems/{problem_id}/description.md")
    description_html = read_file(f"metadata/problems/{problem_id}/description.html")

    returns = {
        "description_md": description_md,
        "description_html": description_html,
        "hints_md": hints_md,
        "hints_html": hints_html,
        "editorial_md": editorial_md,
        "editorial_html": editorial_html,
        "flag_hint": data[0]["flag_hint"],
    }
    return json_success(returns)

@api.route("/contestpublic/problem")
@api_login_required
def public_contest_problem():
    if "cid" not in request.args:
        return json_fail("Must provide contest ID", 400)
    if "pid" not in request.args:
        return json_fail("Must provide problem ID", 400)
    contest_id = request.args["cid"]
    problem_id = request.args["pid"]
    
    contest = db.execute("SELECT * FROM contests WHERE id=?", contest_id)
    if len(contest) != 1:
        return json_fail("Contest not found", 404)
    start = pytz.utc.localize(datetime.strptime(contest[0]["start"], "%Y-%m-%d %H:%M:%S"))
    has_perm = api_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER", "SITE_TESTER"])
    if datetime.now(pytz.UTC) < start and not has_perm:
        return json_fail("The contest has not started", 403)
    data = db.execute(("SELECT * FROM contest_problems WHERE "
                       "contest_id=:cid AND problem_id=:pid"),
                      cid=contest_id, pid=problem_id)
    if len(data) == 0 or (data[0]["draft"] and not has_perm):
        return json_fail("Problem not found", 404)

    description_md = read_file(f"metadata/contests/{contest_id}/{problem_id}/description.md")
    description_html = read_file(f"metadata/contests/{contest_id}/{problem_id}/description.html")
    hints_md = read_file(f"metadata/contests/{contest_id}/{problem_id}/hints.md")
    hints_html = read_file(f"metadata/contests/{contest_id}/{problem_id}/hints.html")

    returns = {
        "description_md": description_md,
        "description_html": description_html,
        "hints_md": hints_md,
        "hints_html": hints_html,
        "flag_hint": data[0]["flag_hint"],
    }
    return json_success(returns)

@api.route("/contestprivate/problem")
@api_login_required
def private_contest_problem():
    if "cid" not in request.args:
        return json_fail("Must provide contest ID", 400)
    if "pid" not in request.args:
        return json_fail("Must provide problem ID", 400)
    contest_id = request.args["cid"]
    problem_id = request.args["pid"]

    contest = db.execute("SELECT * FROM contests WHERE id=?", contest_id)
    if len(contest) != 1:
        return json_fail("Contest not found", 404)
    if not contest[0]['private']:
        return json_fail("Contest is public, please use /contestpublic/problem path", 403)
    if not check_perm(["ADMIN", "SUPERADMIN"]) and not db.execute("SELECT user_id FROM organization_members WHERE org_id=:oid AND user_id=:uid", oid=data[0]["private_org"], uid=session["user_id"]):
        return json_fail("You do not have permission to view this contest", 403)

    start = pytz.utc.localize(datetime.strptime(contest[0]["start"], "%Y-%m-%d %H:%M:%S"))
    has_perm = api_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER", "SITE_TESTER"])
    if datetime.now(pytz.UTC) < start and not has_perm:
        return json_fail("The contest has not started", 403)
    data = db.execute(("SELECT * FROM contest_problems WHERE "
                       "contest_id=:cid AND problem_id=:pid"),
                      cid=contest_id, pid=problem_id)
    if len(data) == 0 or (data[0]["draft"] and not has_perm):
        return json_fail("Problem not found", 404)

    description_md = read_file(f"metadata/contests/{contest_id}/{problem_id}/description.md")
    description_html = read_file(f"metadata/contests/{contest_id}/{problem_id}/description.html")
    hints_md = read_file(f"metadata/contests/{contest_id}/{problem_id}/hints.md")
    hints_html = read_file(f"metadata/contests/{contest_id}/{problem_id}/hints.html")

    returns = {
        "description_md": description_md,
        "description_html": description_html,
        "hints_md": hints_md,
        "hints_html": hints_html,
        "flag_hint": data[0]["flag_hint"],
    }
    return json_success(returns)

@api.route("/contestpublic/scoreboard/<contest_id>")
def contest_scoreboard(contest_id):
    if not request.args.get("key"):
        return json_fail("Unauthorized", 401)

    # Ensure contest exists
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return json_fail("The contest doesn't exist", 404)

    # Ensure proper permissions
    if request.args.get("key") != contest_info[0]["scoreboard_key"]:
        return json_fail('Invalid token', 401)

    data = db.execute(
        ("SELECT user_id, points, lastAC, username FROM contest_users "
         "JOIN users on user_id=users.id WHERE contest_users.contest_id=:cid AND "
         "hidden=0 ORDER BY points DESC, lastAC ASC"),
        cid=contest_id)
    teams = db.execute("SELECT id, username FROM users")
    teams = {x["id"]: x["username"] for x in teams}
    ret = {"standings": []}
    for i in range(len(data)):
        ret["standings"].append({
            "pos": i + 1,
            "team": teams[data[i]["user_id"]],
            "score": data[i]["points"],
        })

    resp = make_response(json.dumps(ret))
    resp.headers['Content-Type'] = 'application/json; charset=utf-8'
    return resp

@api.route("/contestpublic/user/endtime")
def public_contest_user():
    if "cid" not in request.args:
        return json_fail("Must provide contest ID", 400)
    if "username" not in request.args:
        return json_fail("Must provide username", 400)
    contest_id = request.args["cid"]
    username = request.args["username"]
    user_id = db.execute("SELECT id FROM users WHERE username=:username", username=username)[0]['id']
    user_info = db.execute("SELECT end_time FROM contest_users WHERE user_id=:uid AND contest_id=:cid", uid=user_id, cid=contest_id)
    if not user_info:
        return json_fail("User not found", 404)
    return json_success(user_info[0]['end_time'])

@api.route("/contests")
def contests():
    if "id" not in request.args:
        return json_fail("Must specify ids", 400)
    ids = request.args["id"].split(",")
    res = db.execute("SELECT * FROM contests WHERE id IN (?)", ids)
    returns = {}
    for item in res:
        returns[str(item["id"])+"_md"] = read_file(f"metadata/contests/{item['id']}/description.md")
        returns[str(item["id"])+"_html"] = read_file(f"metadata/contests/{item['id']}/description.html")
    return json_success(returns)

@api.route("/announcements")
def announcement():
    if "id" not in request.args:
        return json_fail("Must specify ids", 400)
    nums = [int(e) for e in request.args["id"].split(",") if e.isdigit()][:10]
    res = db.execute("SELECT * FROM announcements WHERE id IN (?)", nums)
    returns = {}
    for item in res:
        returns[str(item["id"])+"_md"] = read_file(f"metadata/announcements/{item['id']}.md")
        returns[str(item["id"])+"_html"] = read_file(f"metadata/announcements/{item['id']}.html")
    return json_success(returns)

@api.route("/organizations")
def organization():
    if "id" not in request.args:
        return json_fail("Must specify id", 400)
    org_id = request.args["id"]
    res = db.execute("SELECT * FROM organizations WHERE id=:oid", oid=org_id)
    description_md = read_file(f"metadata/organizations/{org_id}.md")
    description_html = read_file(f"metadata/organizations/{org_id}.html")
    returns = {
        "description_md": description_md,
        "description_html": description_html
    }
    return json_success(returns)

@api.route("/profile")
def profiledata():
    if "id" not in request.args and "username" not in request.args:
        return json_fail("Must provide user ID or username", 400)
    uid = request.args["id"] if "id" in request.args else -1
    username = request.args["username"] if "username" in request.args else None
    if username:
        uid = db.execute("SELECT id FROM users WHERE username=:username", username=username)[0]['id']
    data = db.execute("SELECT * FROM users WHERE id=:uid", uid=uid)
    if len(data) == 0:
        return json_fail("User not found", 404)
    profile_md = read_file(f"metadata/users/{uid}/profile.md")
    profile_html = read_file(f"metadata/users/{uid}/profile.html")

    returns = {
        "profile_md": profile_md,
        "profile_html": profile_html,
    }
    return json_success(returns)

@api.route("/rating")
def rating():
    if "id" not in request.args and "username" not in request.args:
        return json_fail("Must provide user ID or username", 400)
    uid = request.args["id"] if "id" in request.args else None
    username = request.args["username"] if "username" in request.args else None
    if username:
        uid = db.execute("SELECT id FROM users WHERE username=:username", username=username)[0]['id']
    data = db.execute("SELECT rating FROM users WHERE id=:uid", uid=uid)
    if len(data) == 0:
        return json_fail("User not found", 404)
    
    returns = {
        "rating": data[0]["rating"]
    }
    return json_success(returns)

@api.route("/homepage")
def homepage():
    if app.config["USE_HOMEPAGE"]:
        return _homepage()
    elif not api_admin():
        return json_fail("Unauthorized", 401)
    return _homepage()


def _homepage():
    returns = {
	"data_md" : read_file(f"metadata/homepage.md"),
	"data_html" : read_file(f"metadata/homepage.html")
    }
    return json_success(returns)


@api.route("/instancer/query")
@api_login_required
def query_instancer():
    if "id" not in request.args:
        return json_fail("Must provide instancer ID", 400)

    # Check perms
    key = request.args["id"].split("/", 1)
    contest_id = key[0] if len(key) == 2 else None
    problem_id = key[-1]

    if contest_id:
        contest = db.execute("SELECT * FROM contests WHERE id=?", contest_id)
        if len(contest) != 1:
            return json_fail("Contest not found", 404)
        start = datetime.strptime(contest[0]["start"], "%Y-%m-%d %H:%M:%S")
        has_perm = api_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
        if datetime.utcnow() < start and not has_perm:
            return json_fail("The contest has not started", 403)
        data = db.execute(("SELECT * FROM contest_problems WHERE "
                           "contest_id=:cid AND problem_id=:pid"),
                          cid=contest_id, pid=problem_id)
        if len(data) == 0 or (data[0]["draft"] and not has_perm):
            return json_fail("Problem not found", 404)
    else:
        data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)
        if len(data) == 0 or (data[0]["draft"] and not has_perm):
            return json_fail("Problem not found", 404)

    body = {
        "name": request.args["id"],
        "player": session["user_id"],
    }

    headers = {
        "Authorization": "Bearer " + app.config["INSTANCER_TOKEN"],
    }

    try:
        response = requests.post(app.config["INSTANCER_HOST"] + "/api/v1/query",
                                 headers=headers, json=body)
        return json_success(response.json())
    except Exception:
        return json_fail("Failed to get a valid response from the instance server", 500)

@api.route("/instancer/create")
@api_login_required
def create_instancer():
    if "id" not in request.args:
        return json_fail("Must provide instancer ID", 400)

    # Check perms
    key = request.args["id"].split("/", 1)
    contest_id = key[0] if len(key) == 2 else None
    problem_id = key[-1]

    if contest_id:
        contest = db.execute("SELECT * FROM contests WHERE id=?", contest_id)
        if len(contest) != 1:
            return json_fail("Contest not found", 404)
        start = datetime.strptime(contest[0]["start"], "%Y-%m-%d %H:%M:%S")
        if datetime.utcnow() < start and not api_admin():
            return json_fail("The contest has not started", 403)
        data = db.execute(("SELECT * FROM contest_problems WHERE "
                           "contest_id=:cid AND problem_id=:pid"),
                          cid=contest_id, pid=problem_id)
        if len(data) == 0 or (data[0]["draft"] and not api_admin()):
            return json_fail("Problem not found", 404)
    else:
        data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)
        if len(data) == 0 or (data[0]["draft"] and not check_perm(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER"], api_get_perms())):
            return json_fail("Problem not found", 404)

    body = {
        "name": request.args["id"],
        "player": session["user_id"],
        "flag": data[0]["flag"],
    }

    headers = {
        "Authorization": "Bearer " + app.config["INSTANCER_TOKEN"],
    }

    try:
        response = requests.post(app.config["INSTANCER_HOST"] + "/api/v1/create",
                                 headers=headers, json=body)
        return json_success(response.json())
    except Exception:
        return json_fail("Failed to get a valid response from the instance server", 500)

@api.route("/instancer/destroy")
@api_login_required
def destroy_instancer():
    if "id" not in request.args:
        return json_fail("Must provide instancer ID", 400)

    # Check perms
    key = request.args["id"].split("/", 1)
    contest_id = key[0] if len(key) == 2 else None
    problem_id = key[-1]

    if contest_id:
        contest = db.execute("SELECT * FROM contests WHERE id=?", contest_id)
        if len(contest) != 1:
            return json_fail("Contest not found", 404)
        start = datetime.strptime(contest[0]["start"], "%Y-%m-%d %H:%M:%S")
        if datetime.utcnow() < start and not api_admin():
            return json_fail("The contest has not started", 403)
        data = db.execute(("SELECT * FROM contest_problems WHERE "
                           "contest_id=:cid AND problem_id=:pid"),
                          cid=contest_id, pid=problem_id)
        if len(data) == 0 or (data[0]["draft"] and not api_admin()):
            return json_fail("Problem not found", 404)
    else:
        data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)
        if len(data) == 0 or (data[0]["draft"] and not check_perm(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER"], api_get_perms())):
            return json_fail("Problem not found", 404)

    body = {
        "name": request.args["id"],
        "player": session["user_id"],
    }

    headers = {
        "Authorization": "Bearer " + app.config["INSTANCER_TOKEN"],
    }

    try:
        response = requests.post(app.config["INSTANCER_HOST"] + "/api/v1/destroy",
                                 headers=headers, json=body)
        return json_success(response.json())
    except Exception:
        return json_fail("Failed to get a valid response from the instance server", 500)
