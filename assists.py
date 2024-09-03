from flask import redirect, render_template, session
from functools import wraps

def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def sorry(message, code=400):
    """Render message as an apology to user."""
    return render_template("sorry.html",message=message), code