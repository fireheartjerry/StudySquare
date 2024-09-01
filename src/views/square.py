from flask import (Blueprint, flash, redirect, render_template, request,
                   send_file, session)
import logging
import os
import shutil
import zipfile
from io import BytesIO
import pytz
from datetime import datetime, timezone

from helpers import *  # noqa
from db import *

api = Blueprint("square", __name__)

logger = logging.getLogger("TOPSOJ")

@api.route("/<square_id>")
def square(square_id):
    hotkey1, hotkey2, hotkey3, hotkey4, hotkey5, hotkey6 = gethotkeys()
    data = db.execute("SELECT * FROM squares WHERE id = :sid", sid=square_id)
    
    if not data:
        flash("Square not found", "error")
        return redirect("/squares")
    
    in_square = db.execute("SELECT COUNT(*) AS cnt FROM square_members WHERE square_id = :sid AND user_id = :uid", sid=square_id, uid=session.get("user_id", -1))[0]["cnt"]
    
    duration_seconds, time_taken, join = None, None, None
    hours, minutes, seconds = 0, 0, 0
    if in_square:
        join = db.execute("SELECT join_date FROM square_members WHERE square_id = :sid AND user_id = :uid", sid=square_id, uid=session["user_id"])[0]['join_date']
        time_taken = int((datetime.now(pytz.UTC) - pytz.utc.localize(datetime.strptime(join, "%Y-%m-%d %H:%M:%S"))).total_seconds())
        hours = time_taken // 3600
        minutes = (time_taken % 3600) // 60
        seconds = time_taken % 60

    return render_template("square/square.html", data=data[0], in_square=in_square, duration_seconds=duration_seconds, hours=hours, minutes=minutes, seconds=seconds, time_taken=time_taken, join=join, hotkey1=hotkey1, hotkey2=hotkey2, hotkey3=hotkey3, hotkey4=hotkey4, hotkey5=hotkey5, hotkey6=hotkey6)

@api.route("/<square_id>/edit", methods=["GET", "POST"])
@login_required
def edit_square(square_id):
    hotkey1, hotkey2, hotkey3, hotkey4, hotkey5, hotkey6 = gethotkeys()
    data = db.execute("SELECT * FROM squares WHERE id = :sid", sid=square_id)
    
    if not data:
        flash("Square not found", "error")
        return redirect("/squares")
    
    if data[0]['creator'] != session["user_id"]:
        flash("You do not have permission to edit this square", "error")
        return redirect(f"/square/{square_id}")
    
    if request.method == "GET":
        return render_template("square/edit.html", data=data[0], hotkey1=hotkey1, hotkey2=hotkey2, hotkey3=hotkey3, hotkey4=hotkey4, hotkey5=hotkey5, hotkey6=hotkey6)
    
    # Reached via POST
    
    current_name = data[0]["name"]
    new_name = request.form.get("square_name")
    new_preview = request.form.get("preview")
    new_description = request.form.get("description")
    new_privacy = request.form.get("privacy")
    new_meeting_code = request.form.get("meeting_code")
    new_image_type = int(request.form.get("image_type"))
    new_topic = request.form.get("topic")
    
    if not new_name or not new_description or not new_preview or not new_meeting_code:
        flash('Please enter all required fields', 'danger')
        return render_template("square/edit.html", data=data[0], hotkey1=hotkey1, hotkey2=hotkey2, hotkey3=hotkey3, hotkey4=hotkey4, hotkey5=hotkey5, hotkey6=hotkey6), 400

    # Ensure a square with this title does not exist already
    if db.execute("SELECT COUNT(*) AS cnt FROM squares WHERE name=?", new_name)[0]["cnt"] > 0 and new_name != current_name:
        flash('Square name already exists', 'danger')
        return render_template("square/edit.html", data=data[0], hotkey1=hotkey1, hotkey2=hotkey2, hotkey3=hotkey3, hotkey4=hotkey4, hotkey5=hotkey5, hotkey6=hotkey6), 400
    
    # Modify squares table
    db.execute(("UPDATE squares SET name = :name, preview = :preview, description = :description, public = :public, meeting_code = :meeting_code, image_type = :image_type, topic = :topic "
                "WHERE id = :sid"),
               name=new_name, preview=new_preview, description=new_description, public=bool(int(new_privacy)), meeting_code=new_meeting_code, image_type=new_image_type, topic=new_topic, sid=square_id)
        
    logger.info((f"User #{session['user_id']} ({session['username']}) edited "
                    f"square {square_id}"), extra={"section": "square"})
    flash('Square edited successfully!', 'success')
    return redirect(f"/square/{square_id}")


@api.route("/<square_id>/join", methods=["POST"])
def join_square(square_id):
    data = db.execute("SELECT * FROM squares WHERE id = :sid", sid=square_id)
    
    if not data:
        flash("Square not found", "error")
        return redirect("/squares")
    
    if session.get("user_id"):
        in_square = db.execute("SELECT COUNT(*) AS cnt FROM square_members WHERE square_id = :sid AND user_id = :uid", sid=square_id, uid=session.get("user_id", -1))[0]["cnt"]
        
        if in_square:
            return redirect(f"/square/{square_id}")
        db.execute("INSERT INTO square_members(square_id, user_id, join_date) VALUES(:sid, :uid, datetime('now'))", sid=square_id, uid=session["user_id"])
        db.execute("UPDATE users SET squares_joined = squares_joined + 1 WHERE id = :uid", uid=session["user_id"])
        db.execute("UPDATE squares SET members = members + 1 WHERE id = :sid", sid=square_id)
        db.execute("INSERT INTO square_join_log(user_id, square_id, square_title, square_creator_username) VALUES(:uid, :sid, :title, :creator)", uid=session["user_id"], sid=square_id, title=data[0]["name"], creator=db.execute("SELECT username FROM users WHERE id = :uid", uid=data[0]["creator"])[0]["username"])
    
    if session.get("user_id"):
        logger.info((f"User #{session['user_id']} ({session['username']}) joined "
                        f"square {square_id}"), extra={"section": "square"})
    else:
        logger.info((f"Guest joined square {square_id}"), extra={"section": "square"})
    flash('You have joined the square', 'success')
    return redirect(f"/square/{square_id}")

    
@api.route("/<square_id>/endsession", methods=["POST"])
def leave_square(square_id):
    data = db.execute("SELECT * FROM squares WHERE id = :sid", sid=square_id)
    
    if not data:
        flash("Square not found", "error")
        return redirect("/squares")
    
    if session.get("user_id"):
        in_square = db.execute("SELECT COUNT(*) AS cnt FROM square_members WHERE square_id = :sid AND user_id = :uid", sid=square_id, uid=session.get("user_id", -1))[0]["cnt"]
        
        if not in_square:
            flash("You are not in this square", "danger")
            return redirect(f"/square/{square_id}")
        join = db.execute("SELECT join_date FROM square_members WHERE square_id = :sid AND user_id = :uid", sid=square_id, uid=session["user_id"])[0]['join_date']
        time_taken = int((datetime.now(pytz.UTC) - pytz.utc.localize(datetime.strptime(join, "%Y-%m-%d %H:%M:%S"))).total_seconds())
        db.execute("UPDATE users SET total_seconds = total_seconds + :time WHERE id = :uid", time=time_taken, uid=session["user_id"])
        db.execute("UPDATE squares SET members = members - 1 WHERE id = :sid", sid=square_id)
        db.execute("DELETE FROM square_members WHERE square_id = :sid AND user_id = :uid", sid=square_id, uid=session["user_id"])
    
    if session.get("user_id"):
        logger.info((f"User #{session['user_id']} ({session['username']}) left "
                        f"square {square_id}"), extra={"section": "square"})
    else:
        logger.info((f"Guest left square {square_id}"), extra={"section": "square"})
    flash('You have left the square', 'success')
    return redirect("/squares")


@api.route("/<square_id>/ownerview")
@login_required
def ownerview(square_id):
    hotkey1, hotkey2, hotkey3, hotkey4, hotkey5, hotkey6 = gethotkeys()
    data = db.execute("SELECT * FROM squares WHERE id = :sid", sid=square_id)

    if not data:
        flash("Square not found", "error")
        return redirect("/squares")

    if data[0]['creator'] != session["user_id"]:
        flash("You do not have permission to view this page", "error")
        return redirect(f"/square/{square_id}")

    return render_template("square/ownerview.html", data=data[0], hotkey1=hotkey1, hotkey2=hotkey2, hotkey3=hotkey3, hotkey4=hotkey4, hotkey5=hotkey5, hotkey6=hotkey6)


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
        
    logger.info((f"User #{session['user_id']} ({session['username']}) deleted "
                    f"square {square_id}"), extra={"section": "square"})
    flash('Square deleted successfully!', 'success')
    return redirect("/squares")