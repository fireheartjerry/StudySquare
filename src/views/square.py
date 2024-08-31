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
@login_required
def square(square_id):
    data = db.execute("SELECT * FROM squares WHERE id = :sid", sid=square_id)
    
    if not data:
        flash("Square not found", "error")
        return redirect("/squares")