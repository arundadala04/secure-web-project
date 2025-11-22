# Secure Web Project – Secure Task Manager

This project is a small **secure web-based task management application** built with **Flask** and **SQLite**.

Users can register, log in, and manage their own tasks. The focus of the project is on **secure coding practices**, not on fancy UI.

---

## Features

- User registration with unique username and email
- Secure login and logout
- Passwords stored using **hashed passwords** (no plain text)
- Session-based authentication
- Two roles:
  - **user** – can only see and manage their own tasks
  - **admin** – can view tasks from all users (for management / audit)
- Task management (CRUD):
  - Create a task
  - View tasks
  - Edit a task (including status)
  - Delete a task
- All task operations are protected – only the owner (or admin) can edit/delete

---

## Security Controls Implemented

- **Password hashing** using `werkzeug.security.generate_password_hash`
- **Session management**:
  - only logged-in users can access `/`, `/tasks`, `/tasks/create`, `/tasks/<id>/edit`, `/tasks/<id>/delete`
  - logout clears the session
- **CSRF protection**:
  - custom CSRF token stored in the session
  - all forms (`login`, `register`, `create/edit task`, `delete task`) include a hidden CSRF token field
  - POST requests without a valid token are rejected with HTTP 400
- **Input validation**:
  - required fields for registration (username, email, password)
  - required fields for tasks (title, description)
- **Authorization checks**:
  - normal users can only access their own tasks
  - admin role can view all tasks via the same `/tasks` endpoint
- **Simple login rate limiting**:
  - after several failed login attempts, further attempts are temporarily blocked for a short time
  - helps mitigate brute-force attacks

---

## Technology Stack

- **Python 3**
- **Flask** (web framework)
- **SQLite** (lightweight database)
- HTML templates using **Jinja2**

---

## How to Run the Project

1. **Clone the repository**

   ```bash
   git clone https://github.com/arundadala04/secure-web-project.git
   cd secure-web-project
