from flask import (
    Flask, render_template, request,
    redirect, url_for, session, g, flash, abort
)
from database import get_db
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets
from datetime import datetime, timedelta


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-this-secret-key-later"

    # --------- CSRF token helpers ----------
    @app.before_request
    def ensure_csrf_token():
        # Create token for this session if missing
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)

        # For POST requests, verify CSRF token
        if request.method == "POST":
            form_token = request.form.get("csrf_token")
            if not form_token or form_token != session.get("csrf_token"):
                abort(400)  # Bad Request if token missing/invalid

    @app.context_processor
    def inject_csrf_token():
        # Allows {{ csrf_token }} inside all templates
        return dict(csrf_token=session.get("csrf_token", ""))

    # --------- Simple login rate limit (per session) ----------
    def is_login_blocked():
        max_attempts = 5          # allow 5 tries
        block_minutes = 2         # block for 2 minutes

        attempts = session.get("login_attempts", 0)
        last_attempt_str = session.get("last_login_attempt")

        if last_attempt_str:
            last_attempt = datetime.fromisoformat(last_attempt_str)
        else:
            last_attempt = None

        now = datetime.utcnow()

        # If too many attempts recently -> block
        if attempts >= max_attempts and last_attempt:
            if now - last_attempt < timedelta(minutes=block_minutes):
                return True

        return False

    def record_login_attempt(success: bool):
        now = datetime.utcnow().isoformat()

        if success:
            # reset on successful login
            session["login_attempts"] = 0
            session["last_login_attempt"] = now
        else:
            attempts = session.get("login_attempts", 0) + 1
            session["login_attempts"] = attempts
            session["last_login_attempt"] = now

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
            # Check if this session is currently blocked
            if is_login_blocked():
                flash("Too many login attempts. Please try again in a few minutes.", "error")
                return render_template("login.html")

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            db = get_db()
            user = db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

            if user is None or not check_password_hash(user["password_hash"], password):
                # failed attempt
                record_login_attempt(success=False)
                flash("Invalid username or password.", "error")
                return render_template("login.html")

            # login success
            record_login_attempt(success=True)
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

    # --------- Tasks - list ----------
    @app.route("/tasks")
    def tasks():
        if g.user is None:
            return redirect(url_for("login"))

        db = get_db()
        if g.user["role"] == "admin":
            rows = db.execute(
                """
                SELECT tasks.*, users.username
                FROM tasks
                JOIN users ON tasks.user_id = users.id
                ORDER BY tasks.created_at DESC
                """
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT tasks.*, users.username
                FROM tasks
                JOIN users ON tasks.user_id = users.id
                WHERE tasks.user_id = ?
                ORDER BY tasks.created_at DESC
                """,
                (g.user["id"],),
            ).fetchall()

        return render_template("tasks.html", tasks=rows)

    # --------- Tasks - create ----------
    @app.route("/tasks/create", methods=["GET", "POST"])
    def create_task():
        if g.user is None:
            return redirect(url_for("login"))

        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()

            if not title or not description:
                flash("Title and description are required.", "error")
                return render_template("task_form.html", mode="create")

            db = get_db()
            db.execute(
                """
                INSERT INTO tasks (user_id, title, description, status)
                VALUES (?, ?, ?, ?)
                """,
                (g.user["id"], title, description, "pending"),
            )
            db.commit()
            flash("Task created successfully.", "success")
            return redirect(url_for("tasks"))

        return render_template("task_form.html", mode="create")

    # --------- Tasks - edit ----------
    @app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
    def edit_task(task_id):
        if g.user is None:
            return redirect(url_for("login"))

        db = get_db()
        task = db.execute(
            """
            SELECT * FROM tasks WHERE id = ?
            """,
            (task_id,),
        ).fetchone()

        if task is None:
            flash("Task not found.", "error")
            return redirect(url_for("tasks"))

        # Only owner or admin can edit
        if g.user["role"] != "admin" and task["user_id"] != g.user["id"]:
            flash("You are not allowed to edit this task.", "error")
            return redirect(url_for("tasks"))

        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            status = request.form.get("status", "pending")

            if not title or not description:
                flash("Title and description are required.", "error")
                return render_template("task_form.html", mode="edit", task=task)

            db.execute(
                """
                UPDATE tasks
                SET title = ?, description = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (title, description, status, task_id),
            )
            db.commit()
            flash("Task updated successfully.", "success")
            return redirect(url_for("tasks"))

        return render_template("task_form.html", mode="edit", task=task)

    # --------- Tasks - delete ----------
    @app.route("/tasks/<int:task_id>/delete", methods=["POST"])
    def delete_task(task_id):
        if g.user is None:
            return redirect(url_for("login"))

        db = get_db()
        task = db.execute(
            "SELECT * FROM tasks WHERE id = ?",
            (task_id,),
        ).fetchone()

        if task is None:
            flash("Task not found.", "error")
            return redirect(url_for("tasks"))

        # Only owner or admin can delete
        if g.user["role"] != "admin" and task["user_id"] != g.user["id"]:
            flash("You are not allowed to delete this task.", "error")
            return redirect(url_for("tasks"))

        db.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        db.commit()
        flash("Task deleted.", "success")
        return redirect(url_for("tasks"))

    return app
