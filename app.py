import os
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_session import Session
from helpers import login_required, apology


app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

conn = sqlite3.connect("deniyoruz.db")

cursor = conn.cursor()




@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    user_id = session["user_id"]

    tracks = cursor.execute("SELECT body, exercise, set, rep, kg, load as workout FROM tracks WHERE user_id = ?", user_id)
    conn.commit()
    conn.close()

    return render_template("index.html", tracks=tracks)


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
            cursor.execute("INSERT INTO users (username, hash) VALUES (?, ?)", ("ahmetbenim", "a12"))
            conn.commit()
            conn.close()

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
        try:
            cursor.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
            rows = cursor.fetchall()
        except:
            return apology("a")

        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or passowrd", 403)
        
        session["user_id"] = rows[0]["id"]
        
        return redirect("/")

    else:
        return render_template("login.html")
    
@app.route("/add", methods=["GET","POST"])
def add():
    user_id = session["user_id"]

    if request.method == "POST":
        body = request.form.get("body-name")
        exercise = request.form.get("exercise-name")

        if not body or not exercise or not set or not rep or not kg:
            apology("You forget to enter one of name or names",403)
        
        try:
            set = int(request.form.get("sets"))
            rep = int(request.form.get("reps"))
            kg = float(request.form.get("kgs"))
        except:
            return apology("Must be an integer")
        if set <= 0 or rep <= 0 or kg <= 0:
            return apology("Numbers must be a positive number")
        
        cursor.execute(
            "INSERT INTO tracks (body, exercise, set, rep, kg) VALUES (?, ?, ?, ?, ?)",
            body,
            exercise,
            set,
            rep,
            kg
        )
        conn.commit()
        conn.close()
    else:
        return render_template("add.html")


        

