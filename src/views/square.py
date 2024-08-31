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

api = Blueprint("square", __name__)

logger = logging.getLogger("TOPSOJ")

@api.route("/<square_id>")
def square(square_id):
    data = db.execute("SELECT * FROM squares WHERE id = :sid", sid=square_id)
    
    if not data:
        flash("Square not found", "error")
        return redirect("/squares")
    
    in_square = db.execute("SELECT COUNT(*) AS cnt FROM square_members WHERE square_id = :sid AND user_id = :uid", sid=square_id, uid=session.get("user_id", -1))[0]["cnt"]
    
    return render_template("square/square.html", data=data[0], in_square=in_square)

@api.route("/<square_id>/edit", methods=["GET", "POST"])
@login_required
def edit_square(square_id):
    data = db.execute("SELECT * FROM squares WHERE id = :sid", sid=square_id)
    
    if not data:
        flash("Square not found", "error")
        return redirect("/squares")
    
    if data[0]['creator'] != session["user_id"]:
        flash("You do not have permission to edit this square", "error")
        return redirect(f"/square/{square_id}")
    
    if request.method == "GET":
        return render_template("square/edit.html", data=data[0])
    
    # Reached via POST
    
    current_name = data[0]["name"]
    new_name = request.form.get("square_name")
    new_preview = request.form.get("preview")
    new_description = request.form.get("description")
    new_privacy = request.form.get("privacy")
    new_meeting_code = request.form.get("meeting_code")
    new_image_type = int(request.form.get("image_type"))
    new_topic = request.form.get("topic")
    
    # print these
    print("new_name:", new_name)
    print("new_preview:", new_preview)
    print("new_description:", new_description)
    print("new_privacy:", new_privacy)
    print("new_meeting_code:", new_meeting_code)
    print("new_image_type:", new_image_type)
    print("new_topic:", new_topic)
    
    if not new_name or not new_description or not new_preview or not new_meeting_code:
        flash('Please enter all required fields', 'danger')
        return render_template("square/edit.html", data=data[0]), 400

    # Ensure a square with this title does not exist already
    if db.execute("SELECT COUNT(*) AS cnt FROM squares WHERE name=?", new_name)[0]["cnt"] > 0 and new_name != current_name:
        flash('Square name already exists', 'danger')
        return render_template("square/edit.html", data=data[0]), 400
    
    # Modify squares table
    db.execute(("UPDATE squares SET name = :name, preview = :preview, description = :description, public = :public, meeting_code = :meeting_code, image_type = :image_type, topic = :topic "
                "WHERE id = :sid"),
               name=new_name, preview=new_preview, description=new_description, public=bool(int(new_privacy)), meeting_code=new_meeting_code, image_type=new_image_type, topic=new_topic, sid=square_id)
    
    db.execute("INSERT INTO activity_log(user_id, action, timestamp) VALUES(:uid, :action, datetime('now'))", uid=session["user_id"], action=f"Edited square \"{new_name}\" ({square_id}).")
    
    logger.info((f"User #{session['user_id']} ({session['username']}) edited "
                    f"square {square_id}"), extra={"section": "square"})
    flash('Square edited successfully!', 'success')
    return redirect(f"/square/{square_id}")


@api.route("/<square_id>/join", methods=["POST"])
@login_required
def join_square(square_id):
    data = db.execute("SELECT * FROM squares WHERE id = :sid", sid=square_id)
    
    if not data:
        flash("Square not found", "error")
        return redirect("/squares")
    
    in_square = db.execute("SELECT COUNT(*) AS cnt FROM square_members WHERE square_id = :sid AND user_id = :uid", sid=square_id, uid=session.get("user_id", -1))[0]["cnt"]
    
    if in_square:
        flash("You are already in this square", "error")
        return redirect(f"/square/{square_id}")
    
    db.execute("INSERT INTO square_members(square_id, user_id) VALUES(:sid, :uid)", sid=square_id, uid=session["user_id"])
    
    db.execute("INSERT INTO activity_log(user_id, action, timestamp) VALUES(:uid, :action, datetime('now'))", uid=session["user_id"], action=f"Joined square \"{data[0]['name']}\" ({square_id}).")
    
    logger.info((f"User #{session['user_id']} ({session['username']}) joined "
                    f"square {square_id}"), extra={"section": "square"})
    flash('You have joined the square', 'success')
    return redirect(f"/square/{square_id}")

    
@api.route("/<square_id>/leave", methods=["POST"])
@login_required
def leave_square(square_id):
    data = db.execute("SELECT * FROM squares WHERE id = :sid", sid=square_id)
    
    if not data:
        flash("Square not found", "error")
        return redirect("/squares")
    
    in_square = db.execute("SELECT COUNT(*) AS cnt FROM square_members WHERE square_id = :sid AND user_id = :uid", sid=square_id, uid=session.get("user_id", -1))[0]["cnt"]
    
    if not in_square:
        flash("You are not in this square", "error")
        return redirect(f"/square/{square_id}")
    
    db.execute("DELETE FROM square_members WHERE square_id = :sid AND user_id = :uid", sid=square_id, uid=session["user_id"])
    
    db.execute("INSERT INTO activity_log(user_id, action, timestamp) VALUES(:uid, :action, datetime('now'))", uid=session["user_id"], action=f"Left square \"{data[0]['name']}\" ({square_id}).")
    
    logger.info((f"User #{session['user_id']} ({session['username']}) left "
                    f"square {square_id}"), extra={"section": "square"})
    flash('You have left the square', 'success')
    return redirect("/squares")


@api.route("/<square_id>/ownerview")
@login_required
def ownerview(square_id):
    data = db.execute("SELECT * FROM squares WHERE id = :sid", sid=square_id)

    if not data:
        flash("Square not found", "error")
        return redirect("/squares")

    if data[0]['creator'] != session["user_id"]:
        flash("You do not have permission to view this page", "error")
        return redirect(f"/square/{square_id}")

    return render_template("square/ownerview.html", data=data[0])


@api.route("/<square_id>/delete", methods=["POST"])
@login_required
def delete_square(square_id):
    data = db.execute("SELECT * FROM squares WHERE id = :sid", sid=square_id)
    
    if not data:
        flash("Square not found", "error")
        return redirect("/squares")
    
    if data[0]['creator'] != session["user_id"]:
        flash("You do not have permission to delete this square", "error")
        return redirect(f"/square/{square_id}")
    
    # Delete square from database
    db.execute("DELETE FROM squares WHERE id = :sid", sid=square_id)
    
    db.execute("INSERT INTO activity_log(user_id, action, timestamp) VALUES(:uid, :action, datetime('now'))", uid=session["user_id"], action=f"Deleted square \"{data[0]['name']}\" ({square_id}).")
    
    logger.info((f"User #{session['user_id']} ({session['username']}) deleted "
                    f"square {square_id}"), extra={"section": "square"})
    flash('Square deleted successfully!', 'success')
    return redirect("/squares")