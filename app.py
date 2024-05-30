import os
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# configure application
app = Flask(__name__)

# custom filter
app.jinja_env.filters["usd"] = usd

# configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

def get_db_connection():
    return sqlite3.connect('finance.db')


def close_db_connection(conn, cursor):
    cursor.close()
    conn.close()


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/modify-password", methods=["GET", "POST"])
@login_required
def modify():
    if request.method == "POST":
        current_password = request.form.get("current-password")
        new_password = request.form.get("new-password")
        # ensure current password and new password provided are not empty
        if not current_password or not new_password:
            return apology("current password or/and new password are empty")
        # retrieve the hash for the current password
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT hash FROM users WHERE id = ?", (session["user_id"],))
        hash_password = cursor.fetchone()[0]
        # ensure current password provided is actually correct based on record
        if not check_password_hash(hash_password, current_password):
            close_db_connection(conn, cursor)
            return apology("input for current password is wrong")
        new_hash = generate_password_hash(new_password, method="pbkdf2", salt_length=16)
        # update record with new password's hash
        cursor.execute(
            "UPDATE users SET hash = ? WHERE id = ?", (new_hash, session["user_id"])
        )
        conn.commit()
        close_db_connection(conn, cursor)
        # redirect to login page
        return redirect("/login")
    else:
        # render modify password page
        return render_template("modify.html")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    conn = get_db_connection()
    cursor = conn.cursor()
    # retrieve record of user's owned stocks and shares
    cursor.execute(
        "SELECT stock, SUM(shares) AS sum FROM stock_record WHERE user_id = ? GROUP BY stock",
        (session["user_id"],)
    )
    stocks = cursor.fetchall()
    stocks_list = []
    grand_total = 0
    # for each owned stock in record
    for curr_stock in stocks:
        shares_owned = curr_stock[1]
        # if current stock examined is no longer owned, move to examine next stock
        if shares_owned < 1:
            continue
        symbol = curr_stock[0]
        stock_quote = lookup(symbol)
        total_price = stock_quote["price"] * shares_owned
        curr_stock_dict = {
            "symbol": symbol,
            "shares": shares_owned,
            "price": stock_quote["price"],
            "total": total_price,
        }
        stocks_list.append(curr_stock_dict)
        grand_total += total_price
    # retrieve user's cash balance
    cursor.execute("SELECT cash FROM users WHERE id = ? LIMIT 1", (session["user_id"],))
    cash_balance = cursor.fetchone()[0]
    grand_total += cash_balance
    close_db_connection(conn, cursor)
    # render homepage based on stocks currently owned
    return render_template(
        "index.html",
        stocks=stocks_list,
        cash_balance=cash_balance,
        grand_total=grand_total,
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        # ensure symbol is not empty
        if not symbol:
            return apology("symbol not provided")
        shares = request.form.get("shares")
        # ensure shares is not empty and a positive integer
        if not shares or not shares.isdigit():
            return apology("shares is not a positive integer")
        shares = int(shares)
        stock_quote = lookup(symbol)
        # ensure symbol provided is valid
        if not stock_quote:
            return apology("invalid symbol provided")
        total_stock_price = stock_quote["price"] * shares
        # retrieve record of user's current cash balance
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT cash FROM users WHERE id = ? LIMIT 1", (session["user_id"],)
        )
        available_cash = cursor.fetchone()[0]
        # ensure user has sufficient cash to afford purchase
        if available_cash < total_stock_price:
            close_db_connection(conn, cursor)
            return apology("user has insufficent cash available for purchase")
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # update record with user's purchase
        cursor.execute(
            "INSERT INTO stock_record (user_id, stock, shares, price, total_price, time) VALUES (?, ?, ?, ?, ?, ?)",
            (session["user_id"],
            stock_quote["symbol"],
            shares,
            stock_quote["price"],
            total_stock_price,
            current_time)
        )
        available_cash -= total_stock_price
        # update user's cash balance
        cursor.execute(
            "UPDATE users SET cash = ? WHERE id = ?", (available_cash, session["user_id"])
        )
        conn.commit()
        close_db_connection(conn, cursor)
        # redirect to homepage
        return redirect("/")
    else:
        # render buy page
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    conn = get_db_connection()
    cursor = conn.cursor()
    # retrieve record of user's owned stocks where latest history is displayed at the top of table
    cursor.execute("SELECT * FROM stock_record WHERE id = ? ORDER BY time DESC", (session["user_id"],))
    stocks = cursor.fetchall()
    close_db_connection(conn, cursor)
    # render history page
    return render_template("history.html", stocks=stocks)


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
        if not request.form.get("password"):
            return apology("must provide password", 403)
    
        # Query database for username
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ?", (request.form.get("username"),)
        )
        rows = cursor.fetchall()
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0][2], request.form.get("password")
        ):
            close_db_connection(conn, cursor)
            return apology("invalid username and/or password", 403)
        
        # Remember which user has logged in
        session["user_id"] = rows[0][0]
        close_db_connection(conn, cursor)
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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        # ensure symbol is provided
        if not symbol:
            return apology("symbol not provided")
        stock_quote = lookup(symbol)
        # ensure symbol provided is valid
        if not stock_quote:
            return apology(f"invalid symbol provided {symbol}")
        # render template for quoted page
        return render_template(
            "quoted.html", symbol=stock_quote["symbol"], value=stock_quote["price"]
        )
    else:
        # render template for quote page
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        # ensure username is provided
        if not username:
            return apology("must provide username")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        rows = cursor.fetchall()
        # ensure username isn't already being used according to record
        if len(rows) != 0:
            close_db_connection(conn, cursor)
            return apology("username is already taken")
        password = request.form.get("password")
        confirmation_password = request.form.get("confirmation")
        # ensure password and confirmation password aren't both empty
        if not password and not confirmation_password:
            close_db_connection(conn, cursor)
            return apology("password and confirmation password is empty")
        # ensure password and confirmation password match
        if password != confirmation_password:
            close_db_connection(conn, cursor)
            return apology("password and confirmation password don't match")
        password_hash = generate_password_hash(
            password, method="pbkdf2", salt_length=16
        )
        # add new user's login information to record
        cursor.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)", (username, password_hash)
        )
        conn.commit()
        close_db_connection(conn, cursor)
        # redirect to homepage
        return redirect("/")
    else:
        # render template for register page
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # retrieve input stock symbol and shares
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        # ensure symbol is selected
        if not symbol:
            return apology("symbol was not selected")
        # ensure shares is provided and it only contains integers
        if not shares or not shares.isdigit():
            return apology("shares is not a positive integer")
        shares = int(shares)
        # retrieve user's owned stocks and shares
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT stock, SUM(shares) AS sum FROM stock_record WHERE user_id = ? AND stock = ? GROUP BY stock",
            (session["user_id"],
            symbol)
        )
        rows = cursor.fetchall()
        # ensure data retrieved is not empty
        if len(rows) == 0:
            close_db_connection(conn, cursor)
            return apology("no shares of this stock are owned")
        # ensure user owns at least the number of shares inputted
        owned_shares = rows[0][1]
        if owned_shares < shares:
            close_db_connection(conn, cursor)
            return apology("less shares are owned")
        stock_quote = lookup(symbol)
        sold_price = stock_quote["price"] * shares
        # update record based on shares sold
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        shares *= -1
        cursor.execute(
            "INSERT INTO stock_record (user_id, stock, shares, price, total_price, time) VALUES (?, ?, ?, ?, ?, ?)",
            (session["user_id"],
            stock_quote["symbol"],
            shares,
            stock_quote["price"],
            sold_price,
            current_time)
        )
        # update cash balance
        cursor.execute(
            "SELECT cash FROM users WHERE id = ? LIMIT 1", (session["user_id"],)
        )
        cash_balance = cursor.fetchone()[0]
        cash_balance += sold_price
        cursor.execute(
            "UPDATE users SET cash = ? WHERE id = ?", (cash_balance, session["user_id"])
        )
        conn.commit()
        close_db_connection(conn, cursor)
        # redirect to homepage
        return redirect("/")
    else:
        # retrieve record of user's owned stocks and shares
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT stock, SUM(shares) AS sum FROM stock_record WHERE user_id = ? GROUP BY stock",
            (session["user_id"],)
        )
        stocks = cursor.fetchall()
        close_db_connection(conn, cursor)
        symbols = []
        # for each owned stock in record
        for curr_stock in stocks:
            # if current stock examined is no longer owned, move to examine next stock
            if curr_stock[1] < 1:
                continue
            # add symbol of currently owned stock to list
            symbols.append(curr_stock[0])
        # render template for sell page with the symbols of stocks currently owned
        return render_template("sell.html", symbols=symbols)
