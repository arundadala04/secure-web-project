import sqlite3
from werkzeug.security import generate_password_hash


def main():
    # Connect to the same database used by the app
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    username = "admin"
    email = "admin@example.com"
    password = "Admin123"

    password_hash = generate_password_hash(password)

    try:
        cur.execute(
            """
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
            """,
            (username, email, password_hash, "admin"),
        )
        conn.commit()
        print("✅ Admin user created:")
        print("   username: admin")
        print("   password: Admin123")
    except sqlite3.IntegrityError:
        print("⚠️ Admin user already exists. No new admin created.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
