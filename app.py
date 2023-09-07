
import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime

from helpers import apology, login_required

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///future.db")

PARTS = [
    "Back",
    "Chest",
    "Leg",
    "Shoulder",
    "Tricep",
    "Bicep",
    "ABS",
    "Compound"
]



@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    user_id = session["user_id"]

    if request.method == "POST":
        part = request.form.get("body-name")
        exercise = request.form.get("exercise-name").upper()
        date = request.form.get("date")
        reverse = request.form.get("toggle")

        if not part and not exercise and not date and reverse == "on":
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE user_id = ?", user_id)
            tracksnum = db.execute("SELECT COUNT(*) FROM tracksnew WHERE user_id = ?", user_id)

            tracknum = tracksnum[0]

            if (tracknum["COUNT(*)"] == 0):
                return apology("There is nothing to be reversed")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)

        elif not part and not exercise and not date:
            return apology("You must enter at least one input to search")


        elif not part and not exercise and reverse == "on":
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE DATE(time) = ? AND user_id = ?",date, user_id)
            tracksnum = db.execute("SELECT  COUNT(*) FROM tracksnew WHERE DATE(time) = ? AND user_id = ?", date, user_id)

            tracknum = tracksnum[0]

            if (tracknum["COUNT(*)"] == 0):
                return apology("Not Found!")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)

        elif not part and not exercise:
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE DATE(time) = ? AND user_id = ? ORDER BY id DESC",date, user_id)
            tracksnum = db.execute("SELECT  COUNT(*) FROM tracksnew WHERE DATE(time) = ? AND user_id = ?", date, user_id)

            tracknum = tracksnum[0]

            if (tracknum["COUNT(*)"] == 0):
                return apology("Not Found!")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)


        elif not exercise and not date and reverse == "on":
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE body = ? AND user_id = ? GROUP BY time", part, user_id)
            tracksnum = db.execute("SELECT COUNT(*) FROM tracksnew WHERE body = ? AND user_id = ?",part, user_id)

            tracknum = tracksnum[0]
            if (tracknum["COUNT(*)"] == 0):
                return apology("Not Found")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)

        elif not exercise and not date:
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE body = ? AND user_id = ? GROUP BY time ORDER BY id DESC", part, user_id)
            tracksnum = db.execute("SELECT COUNT(*) FROM tracksnew WHERE body = ? AND user_id = ?",part, user_id)

            tracknum = tracksnum[0]
            if (tracknum["COUNT(*)"] == 0):
                return apology("Not Found")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)

        elif not part and not date and reverse == "on":
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE exercise = ? AND user_id = ? GROUP BY time",exercise, user_id)

            tracksnum = db.execute("SELECT COUNT(*) FROM tracksnew WHERE exercise = ? AND user_id = ?", exercise, user_id)

            tracknum = tracksnum[0]
            if (tracknum["COUNT(*)"] == 0):
                return apology("Not Found")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)

        elif not part and not date:
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE exercise = ? AND user_id = ? GROUP BY time ORDER BY id DESC",exercise, user_id)

            tracksnum = db.execute("SELECT COUNT(*) FROM tracksnew WHERE exercise = ? AND user_id = ?", exercise, user_id)

            tracknum = tracksnum[0]
            if (tracknum["COUNT(*)"] == 0):
                return apology("Not Found")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)

        elif not part and reverse == "on":
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE exercise = ? AND DATE(time) = ? AND user_id = ?", exercise, date, user_id)

            tracksnum = db.execute("SELECT COUNT(*) FROM tracksnew WHERE exercise = ? AND DATE(time) = ? AND user_id = ?", exercise, date, user_id)
            tracknum = tracksnum[0]

            if (tracknum["COUNT(*)"] == 0):
                return apology("Not Found")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)

        elif not part:
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE exercise = ? AND DATE(time) = ? AND user_id = ? ORDER BY id DESC", exercise, date, user_id)

            tracksnum = db.execute("SELECT COUNT(*) FROM tracksnew WHERE exercise = ? AND DATE(time) = ? AND user_id = ?", exercise, date, user_id)
            tracknum = tracksnum[0]

            if (tracknum["COUNT(*)"] == 0):
                return apology("Not Found")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)


        elif not exercise and reverse == "on":
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE body = ? AND DATE(time) = ? AND user_id = ?", part, date, user_id)
            tracksnum = db.execute("SELECT COUNT(*) FROM tracksnew WHERE body = ? AND DATE(time) = ? AND user_id = ?", part, date, user_id)
            tracknum = tracksnum[0]
            if (tracknum["COUNT(*)"] == 0):
                return apology("Not Found")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)

        elif not exercise:
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE body = ? AND DATE(time) = ? AND user_id = ? ORDER BY id DESC", part, date, user_id)
            tracksnum = db.execute("SELECT COUNT(*) FROM tracksnew WHERE body = ? AND DATE(time) = ? AND user_id = ?", part, date, user_id)
            tracknum = tracksnum[0]
            if (tracknum["COUNT(*)"] == 0):
                return apology("Not Found")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)


        elif not date and reverse == "on":
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE body = ? AND exercise = ? AND user_id = ? GROUP BY time", part, exercise,user_id)
            tracksnum = db.execute("SELECT COUNT(*) FROM tracksnew WHERE body = ? AND exercise = ? AND user_id = ?",part, exercise, user_id)
            tracknum = tracksnum[0]
            if ( tracknum["COUNT(*)"] == 0):
                return apology("Not Found")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)


        elif not date:
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE body = ? AND exercise = ? AND user_id = ? GROUP BY time ORDER BY id DESC", part, exercise,user_id)
            tracksnum = db.execute("SELECT COUNT(*) FROM tracksnew WHERE body = ? AND exercise = ? AND user_id = ?",part, exercise, user_id)
            tracknum = tracksnum[0]
            if ( tracknum["COUNT(*)"] == 0):
                return apology("Not Found")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)

        elif reverse == "on":
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg ,loadd, time FROM tracksnew WHERE DATE(time) = ? AND body = ? AND exercise = ? AND user_id = ? GROUP BY time", date, part, exercise, user_id)

            tracksnum = db.execute("SELECT COUNT(*) FROM tracksnew WHERE DATE(time) = ? AND body = ? AND exercise = ? AND user_id = ?", date, part, exercise, user_id)
            tracknum = tracksnum[0]
            if (tracknum["COUNT(*)"] == 0):
                return apology("Not Found")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)


        else:
            tracks = db.execute("SELECT id, body, exercise, sett, rep, kg ,loadd, time FROM tracksnew WHERE DATE(time) = ? AND body = ? AND exercise = ? AND user_id = ? GROUP BY time ORDER BY id DESC", date, part, exercise, user_id)

            tracksnum = db.execute("SELECT COUNT(*) FROM tracksnew WHERE DATE(time) = ? AND body = ? AND exercise = ? AND user_id = ?", date, part, exercise, user_id)
            tracknum = tracksnum[0]
            if (tracknum["COUNT(*)"] == 0):
                return apology("Not Found")
            else:
                return render_template("index.html", tracks=tracks, parts=PARTS)

    else:
        tracks = db.execute("SELECT id, body, exercise, sett, rep, kg, loadd, time FROM tracksnew WHERE user_id = ? GROUP BY time ORDER BY id DESC", user_id)
        return render_template("index.html", tracks=tracks, parts=PARTS)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username and not password and not confirmation:
           return apology("Why are they all empty?")
        elif not username:
            return apology("Username is required")
        elif not password:
            return apology("Password is required!")
        elif not confirmation:
            return apology("You must confirm your password!")

        if password != confirmation:
            return apology("Passwords don't match")

        try:
            hash = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username,hash)


        except:
            return apology("Username has already been registered!")

        return redirect("/")
    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 405)

        elif not request.form.get("password"):
            return apology("must provide password", 403)


        #query database for username

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        apology("bemr")



        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]

        return redirect("/")

    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/add", methods=["GET","POST"])
@login_required
def add():
    user_id = session["user_id"]

    if request.method == "POST":
        try:
            body = request.form.get("body-name")
        except:
            return apology("You didn't enter your body part",403)

        if body not in PARTS:
            return apology("There is no such body part")

        exercise = request.form.get("exercise-name")

        if not exercise:
            return apology("You forget to enter exercise name",403)

        try:
            set = int(request.form.get("sets"))
            rep = int(request.form.get("reps"))
            kg = float(request.form.get("kgs"))
        except:
            return apology("Must be an integer")
        if set <= 0 or rep <= 0 or kg < 0:
            return apology("Numbers must be a positive number")

        load = 0
        if kg == 0:
            load = set * rep
        else:
            load = set * rep * kg


        db.execute("INSERT INTO tracksnew (user_id, body, exercise, sett, rep, kg, loadd) VALUES (?, ?, ?, ?, ?, ?, ?)" , user_id, body, exercise.upper(), set, rep, kg, load)

        return redirect("/add")
    else:
        return render_template("add.html", parts=PARTS)

@app.route("/delete", methods=["GET","POST"])
@login_required
def delete():
    if request.method == "POST":
        user_id = session["user_id"]

        id = int(request.form.get("delete-id"))

        if id <= 0:
            return apology("Must be a positive number")

        try:
            db.execute("DELETE FROM tracksnew WHERE id = ? AND user_id = ?", id, user_id)
            return redirect("/")
        except:
            return apology("Id is not valid")

    else:
        return render_template("delete.html")


@app.route("/images")
@login_required
def images():
    return render_template("images.html")

@app.route("/motivation")
@login_required
def motivation():
    return render_template("motivation.html")

