from flask import (
    Flask, render_template, request,
    redirect, url_for, session, g, flash
)
from database import get_db
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-this-secret-key-later"

    # --------- Load logged-in user before each request ----------
    @app.before_request
    def load_logged_in_user():
        user_id = session.get("user_id")
        if user_id is None:
            g.user = None
        else:
            db = get_db()
            user = db.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            g.user = user

    # --------- Home page ----------
    @app.route("/")
    def index():
        if g.user:
            return render_template("index.html")
        return redirect(url_for("login"))

    # --------- Register ----------
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")

            errors = []

            if not username:
                errors.append("Username is required.")
            if not email:
                errors.append("Email is required.")
            if not password:
                errors.append("Password is required.")
            if password != confirm:
                errors.append("Passwords do not match.")

            if errors:
                for e in errors:
                    flash(e, "error")
                return render_template("register.html")

            db = get_db()
            try:
                db.execute(
                    """
                    INSERT INTO users (username, email, password_hash, role)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username, email, generate_password_hash(password), "user"),
                )
                db.commit()
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username or email already exists.", "error")
                return render_template("register.html")

        return render_template("register.html")

    # --------- Login ----------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            db = get_db()
            user = db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

            if user is None or not check_password_hash(user["password_hash"], password):
                flash("Invalid username or password.", "error")
                return render_template("login.html")

            # login success
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))

        return render_template("login.html")

    # --------- Logout ----------
    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    return app
