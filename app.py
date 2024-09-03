#Booky Bookstore Web Application
#Developed By: Seif Hamdy

import datetime
from cs50 import SQL
from flask import Flask,redirect,render_template,request,session
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash

from assists import sorry, login_required, usd

#from assists import sorry, login_required, usd

#creating the application
app=Flask(__name__)

#reload templates
app.config["TEMPLATES_AUTO_RELOAD"]=True


app.jinja_env.filters["usd"] = usd
#Session
app.config["SESSION_PERMANENT"]=False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

#Database configuration
db= SQL("sqlite:///project.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/",methods=["GET", "POST"])
@login_required
def index():
    #main page
    return render_template("index.html")

@app.route("/register",methods=["GET", "POST"])
def register():

    if request.method=="POST":
        #getting username and passwords
        username=request.form.get("username")
        #making sure user has inputted a username checked
        if not username:
            return sorry("No username submitted!")
        usernames=db.execute("SELECT username FROM users")
        #checking if username isn't already in use
        for user in usernames:
            if username == user['username']:
                return sorry("Username already in use!")
        password=request.form.get("password")
        confirmation=request.form.get("confirmation")
        #making sure the user inputted a password checked
        if not password or not confirmation:
            return sorry("Passwords Missing!")
        #checking the password is well confirmed checked
        if not password==confirmation:
            return sorry("Passwords don't match!")

        #making sure password has a number or a symbol
        okay=False
        valid=["0","1","2","4","5","6","7","8","9",".",",","?","!","@","$","#","%","&","*","^"]
        for letter in password:
            for i in range(0,len(valid)):
                if letter==valid[i]:
                    okay=True
        if okay==False:
            return sorry("Password must contain a number or a symbol!")
        #cash
        cash=request.form.get("amount")
        cash=int(cash)
        #making sure there is a valid amount of money
        if cash<1:
            return sorry("No enough cash!")
        hash=generate_password_hash(password)
        #updating the database
        db.execute(f"INSERT INTO users (username,hash,cash) VALUES (?,?,?)",username,hash,cash)
        id=db.execute("SELECT id FROM users WHERE username=?",username)
        for i in id:
            session['user_id']=i['id']
        return redirect("/")
    else:
        return render_template("register.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return sorry("Must provide username!", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return sorry("Must provide password!", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return sorry("Invalid username and/or password!", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/chpass", methods=["GET", "POST"])
@login_required
def change():
    """Changing Password"""
    if request.method == "POST":
        new=request.form.get("newpass")
        # Ensure username was submitted
        if not request.form.get("username"):
            return sorry("Must provide username!", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return sorry("Must provide password!", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return sorry("Invalid Account!", 403)
        if not new:
            return sorry("Must enter a new password!")
        if new==request.form.get("password"):
            return sorry("New password can't be same as old!")
        hash=generate_password_hash(new)
        #updating users table in database
        db.execute("UPDATE users SET hash=? WHERE username=?", hash,request.form.get("username"))
        return redirect("/")
    else:
        return render_template("chpass.html")

@app.route("/shop", methods=["GET","POST"])
@login_required
def shop():
    #getting cash from table
    cash=db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])[0]['cash']
    books=db.execute("SELECT * FROM books")
    #getting the list length for the for loop in jinja
    length=len(books)
    return render_template("shop.html",cash=cash,books=books,length=length)

@app.route("/search", methods=["GET","POST"])
@login_required
def search():
    given=request.form.get("search")
    #making sure there are no extra whitespaces and that it is also accepted if inputted in lowercase
    given=given.title()
    given=given.strip()
    books=db.execute("SELECT * FROM books WHERE title =? ",given)
    #error if more than one match or no matches at all
    if not len(books) == 1:
        return sorry("No Such Book!")
    else:
        cash=db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])[0]['cash']
        length=len(books)
        return render_template("shop.html",cash=cash,books=books,length=length)

@app.route("/horror", methods=["GET","POST"])
@login_required
def horror():
    """showing on horror books"""
    books=db.execute("SELECT * FROM books WHERE genre=?","Horror")
    cash=db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])[0]['cash']
    length=len(books)
    return render_template("shop.html",cash=cash,books=books,length=length)

@app.route("/romance", methods=["GET","POST"])
@login_required
def romance():
    """showing on romance books"""
    books=db.execute("SELECT * FROM books WHERE genre=?","Romance")
    cash=db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])[0]['cash']
    length=len(books)
    return render_template("shop.html",cash=cash,books=books,length=length)

@app.route("/mystery", methods=["GET","POST"])
@login_required
def mystery():
    """showing on mystery books"""
    books=db.execute("SELECT * FROM books WHERE genre=?","Mystery")
    cash=db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])[0]['cash']
    length=len(books)
    return render_template("shop.html",cash=cash,books=books,length=length)

@app.route("/preview", methods=["GET","POST"])
@login_required
def preview():
    #getting book details from given id
    id=request.form.get("id")
    book=db.execute("SELECT * FROM books WHERE id=?", id)[0]
    return render_template("preview.html",book=book)

@app.route("/addcash", methods=["GET","POST"])
@login_required
def add():
    if request.method=="POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return sorry("Must provide username!", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return sorry("Must provide password!", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return sorry("Invalid Account!", 403)
        #changing cash
        oldcash=db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])[0]['cash']
        additional=int(request.form.get("amount"))
        #making sure the amount is more than 0
        if additional<1:
            return sorry("Add a sufficient amount of money!")
        totalcash=oldcash+additional
        db.execute("UPDATE users SET cash=? WHERE id=?",totalcash,session["user_id"])
        return render_template("index.html")
    else:
        return render_template("addcash.html")

@app.route("/cart", methods=["GET","POST"])
@login_required
def cart():
    cash=db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])[0]['cash']
    username=db.execute("SELECT username FROM users WHERE id=?", session["user_id"])[0]["username"]
    if request.method=="POST":
        bookid=request.form.get("cart")
        details=db.execute("SELECT * FROM books WHERE id =?",bookid)[0]
        #getting book details
        title=details["title"]
        author=details['author']
        genre=details['genre']
        price=details['price']
        cover=details['source']
        #adding book to cart table
        #making sure it doesn't already exist in cart
        bnames=db.execute("SELECT bookname FROM cart WHERE username=?", username)
        for bname in bnames:
            if title==bname['bookname']:
                return sorry("Book already in cart!")
        #making sure it doesn't already exist in library
        lnames=db.execute("SELECT booktitle FROM library WHERE username=?", username)
        for lname in lnames:
            if title==lname['booktitle']:
                return sorry("Book already in library!")
        #updating database
        db.execute("INSERT INTO cart (username,bookname,bookid,price,genre,author,bookcover) VALUES (?,?,?,?,?,?,?)", username,title,bookid,price,genre,author,cover)
        books=db.execute("SELECT * FROM cart WHERE username=?",username)
        Tprice=db.execute("SELECT SUM(price) AS Tprice FROM cart WHERE username=?",username)[0]["Tprice"]
        if Tprice==None:
            Tprice=0
        return render_template("cart.html",cash=cash,books=books,Tprice=Tprice)
    else:
        #books details
        books=db.execute("SELECT * FROM cart WHERE username=?",username)
        Tprice=db.execute("SELECT SUM(price) AS Tprice FROM cart WHERE username=?",username)[0]["Tprice"]
        if Tprice==None:
            Tprice=0
        return render_template("cart.html",cash=cash,books=books,Tprice=Tprice)

@app.route("/remove", methods=["GET","POST"])
@login_required
def remove():
    id=request.form.get("remove")
    #removing it from database
    db.execute("DELETE FROM cart WHERE bookid=?",id)
    return redirect("/cart")


@app.route("/purchase", methods=["GET","POST"])
@login_required
def purchase():
    username=db.execute("SELECT username FROM users WHERE id=?", session["user_id"])[0]["username"]
    books=db.execute("SELECT * FROM cart WHERE username=?",username)
    #making sure there are books in cart
    if len(books)==0:
        return sorry("No books in cart!")
    #adding to library table
    for book in books:
        bookcover=book["bookcover"]
        booktitle=book["bookname"]
        author=book['author']
        genre=book['genre']
        date=datetime.datetime.now()
        db.execute("INSERT INTO library (username,bookcover,booktitle,author,genre,status,date) VALUES (?,?,?,?,?,?,?)",username,bookcover,booktitle,author,genre,"To Be Delivered",date)

    #modifying cash in users
    Tprice=db.execute("SELECT SUM(price) AS Tprice FROM cart WHERE username=?",username)[0]["Tprice"]
    oldcash=db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])[0]['cash']
    #making sure the user has enough money
    if Tprice>oldcash:
        return sorry("Not enough money")
    newcash=oldcash-Tprice
    db.execute("UPDATE users SET cash=? WHERE username=?",newcash,username)

    #modifying the cart table
    db.execute("DELETE FROM cart WHERE username=?",username)
    return redirect("/library")

@app.route("/library", methods=["GET","POST"])
@login_required
def library():
    cash=db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])[0]['cash']
    username=db.execute("SELECT username FROM users WHERE id=?", session["user_id"])[0]["username"]
    #getting books details
    books=db.execute("SELECT * FROM library WHERE username=?",username)
    return render_template("library.html",books=books,cash=cash)

@app.route("/cancel", methods=["GET","POST"])
@login_required
def cancel():
    title=request.form.get("cancel")
    #refund process
    username=db.execute("SELECT username FROM users WHERE id=?", session["user_id"])[0]["username"]
    cash=db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])[0]['cash']
    refund=db.execute("SELECT price FROM books WHERE title=?",title)[0]['price']
    newcash=cash+refund
    db.execute("UPDATE users SET cash =? WHERE username=?",newcash,username)
    #removing from library table
    db.execute("DELETE FROM library WHERE booktitle=?",title)
    return redirect("/library")