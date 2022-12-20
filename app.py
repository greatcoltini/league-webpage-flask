import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///league.db")

# Make sure API key is set
# if not os.environ.get("API_KEY"):
#     raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/main", methods=["GET", "POST"])
@login_required
def account():
    return render_template("main.html")


@app.route("/change_password", methods=["POST"])
def change_password():
    """ route for changing the password -- in account """
    n_password = request.form.get("new_password")
    n_password_c = request.form.get("new_password_confirm")
    user = validify_login()

    if not n_password:
        return apology("must input a valid password")
    if not n_password_c:
        return apology("must confirm password")
    if n_password != n_password_c:
        return apology("passwords must be equal")

    new_password = generate_password_hash(n_password)

    db.execute("UPDATE users SET hash = ? WHERE username = ?", new_password, user["username"])

    return redirect("/account")

@app.route("/")
# @login_required
def index():
    return render_template("index.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    user = validify_login()
    transaction_history = db.execute(
        "SELECT * FROM purchase_history WHERE username = ? ORDER BY purchase_date DESC, purchase_time", user["username"])

    return render_template("history.html", transaction_history=transaction_history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif not request.form.get("confirmation"):
            return apology("must provide confirmation of password", 400)

        elif not request.form.get("confirmation") == request.form.get("password"):
            return apology("must provide identical password and password-confirmation", 400)

        username = request.form.get("username")

        existing_users = db.execute("SELECT username FROM users")

        for user in existing_users:
            if user["username"] == username:
                return apology("current username already present in database")

        password = generate_password_hash(request.form.get("password"))

        # Insert user into database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password)

        # Redirect user to home page
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

def validify_login():
    """ Verify user is logged in """
    if (session.get("user_id")):
        user_id = session.get("user_id")
        user = db.execute("SELECT username, cash, hash FROM users WHERE id = ?", user_id)[0]
        return user
    else:
        return redirect("/login")

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
    
