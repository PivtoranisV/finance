import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    transactions_db = db.execute(
        "SELECT symbol, name, SUM(shares) AS shares, price FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
    cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash = cash_db[0]["cash"]

    return render_template("index.html", database=transactions_db, cash=usd(cash))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # Render an apology if the input is blank or the symbol does not exist
        if not symbol:
            return apology("Please provide Symbol and try again.")

        stock = lookup(symbol.upper())
        if stock == None:
            return apology("Symbol Does Not Exist")

        # Render an apology if the input is not a positive integer.
        if shares < 0:
            return apology("Please provide more than 0 shares and try again.")

        # Render an apology if user does not have money.
        transaction_value = shares * stock["price"]
        user_id = session["user_id"]
        user_cash_db = db.execute(
            "SELECT cash FROM users WHERE id = ?", user_id)
        user_cash = user_cash_db[0]["cash"]

        if user_cash < transaction_value:
            return apology("Not Enough Money")

        # Update remaining cash
        new_cash=user_cash - transaction_value
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)

        date=datetime.datetime.now()

        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date, name) VALUES (?, ?, ?, ?, ?, ?)",
                   user_id, stock["symbol"], shares, usd(stock["price"]), date, stock["name"])

        flash("Bought!")

        return redirect("/")


@ app.route("/history")
@ login_required
def history():
    """Show history of transactions"""
    user_id=session["user_id"]
    transactions_db=db.execute(
        "SELECT * FROM transactions WHERE user_id = :id", id=user_id)
    return render_template("history.html", transactions=transactions_db)


# Allow users to add additional cash to their account.
@ app.route("/add_cash", methods=["GET", "POST"])
@ login_required
def add_cash():
    """Allow users to add additional cash to their account."""
    if request.method == "GET":
        return render_template("add_cash.html")
    else:
        add_cash=int(request.form.get("add_cash"))

        if not add_cash:
            return apology("Please add Amount and try again.")

        user_id=session["user_id"]
        user_cash_db=db.execute(
            "SELECT cash FROM users WHERE id = ?", user_id)
        user_cash=user_cash_db[0]["cash"]

        # Update remaining cash
        new_cash=user_cash + add_cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)

        return redirect("/")


@ app.route("/login", methods=["GET", "POST"])
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
        rows=db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"]=rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@ app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@ app.route("/quote", methods=["GET", "POST"])
@ login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol=request.form.get("symbol")

        if not symbol:
            return apology("Please provide Symbol and try again.")

        stock=lookup(symbol.upper())
        if stock == None:
            return apology("Symbol Does Not Exist")

        return render_template("quoted.html", name=stock["name"], price=usd(stock["price"]), symbol=stock["symbol"])


@ app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Render page with GET request
    if request.method == "GET":
        return render_template("register.html")
    # Render page with POS request
    else:
        username=request.form.get("username")
        password=request.form.get("password")
        confirmation=request.form.get("confirmation")

        # missing username
        if not username:
            return apology("Please provide Username and try again.")
        # missing password
        if not password:
            return apology("Please provide Password and try again.")
        # missing confirmation
        if not confirmation:
            return apology("Please provide Password Confirmation and try again.")
        # password and confirmation different
        if password != confirmation:
            return apology("Password Do Not Match.")

        # generate password hash
        hash=generate_password_hash(password)
        # add user tp Data base
        try:
            new_user=db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        except:
            return apology("User already exist")

        # redirect new user to the main page instead of login page
        session["user_id"]=new_user
        return redirect("/")


@ app.route("/sell", methods=["GET", "POST"])
@ login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        user_id=session["user_id"]
        symbols_user=db.execute(
            "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)
        return render_template("sell.html", symbols=[row["symbol"] for row in symbols_user])

    else:
        symbol=request.form.get("symbol")
        shares=int(request.form.get("shares"))

        # Render an apology if the input is blank or the symbol does not exist
        if not symbol:
            return apology("Please provide Symbol and try again.")

        stock=lookup(symbol.upper())
        if stock == None:
            return apology("Symbol Does Not Exist")

        # Render an apology if the input is not a positive integer.
        if shares < 0:
            return apology("Please provide more than 0 shares and try again.")

        # Render an apology if user does not have money.
        transaction_value=shares * stock["price"]
        user_id=session["user_id"]
        user_cash_db=db.execute(
            "SELECT cash FROM users WHERE id = ?", user_id)
        user_cash=user_cash_db[0]["cash"]

        user_shares=db.execute(
            "SELECT SUM(shares) AS shares FROM transactions WHERE user_id =:id AND symbol =:symbol", id=user_id, symbol=symbol)
        new_user_shares=user_shares[0]["shares"]

        if shares > new_user_shares:
            return apology("You Do not have this amount of shares")

        # Update remaining cash
        new_cash=user_cash + transaction_value
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)

        date=datetime.datetime.now()

        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date, name) VALUES (?, ?, ?, ?, ?, ?)",
                   user_id, stock["symbol"], (-1)*shares, usd(stock["price"]), date, stock["name"])

        flash("Sold!")

        return redirect("/")
