from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from database1 import initialize_db, get_user, DB_NAME, hash_password
from watcher import start_session, end_session, get_session, SIMULATED_FILES, FLAT_FILES
import sqlite3

# ── APP SETUP ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "anomalyfi_secret_key"


# ── ROUTE 1: Login Page ──────────────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = get_user(username, password)

        if user:
            # user row = (id, username, password, role, is_blocked)
            session.permanent  = True   # keep session for 24 hours
            session["username"] = user[1]
            session["role"]     = user[3]

            # ── Start watcher session for this user ───────────────────────
            if user[3] == "user":
                start_session(user[1])

            if user[3] == "admin":
                return redirect(url_for("dashboard"))
            else:
                return redirect(url_for("user_home"))

        else:
            # Check if blocked or just wrong password
            conn   = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT is_blocked FROM users WHERE username=? AND password=?",
                (username, hash_password(password))
            )
            row = cursor.fetchone()
            conn.close()

            if row and row[0] == 1:
                error = "ACCESS DENIED — Your account has been blocked by the system."
            else:
                error = "Invalid username or password."

    return render_template("login.html", error=error)


# ── ROUTE 2: Admin Dashboard ─────────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session.get("username"))


# ── ROUTE 3: User Home (File System) ─────────────────────────────────────────
@app.route("/user_home")
def user_home():
    if "username" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "user":
        return redirect(url_for("login"))

    # Pass folder structure to template
    return render_template("user_home.html",
                           username=session.get("username"),
                           folders=SIMULATED_FILES)


# ── ROUTE 4: File Actions (called by JS buttons) ─────────────────────────────
@app.route("/file_action", methods=["POST"])
def file_action():
    """
    JS calls this route when user clicks Open / Copy / Delete.
    Returns JSON so page updates without reloading.
    """
    if "username" not in session:
        return jsonify({"error": "Not logged in"}), 401

    username = session["username"]
    action   = request.json.get("action")    # "open", "copy", "delete"
    filename = request.json.get("filename")

    user_session = get_session(username)
    if not user_session:
        return jsonify({"error": "No active session"}), 400

    # Perform the action and get updated counters
    content = None
    if action == "open":
        content = user_session.open_file(filename)
    elif action == "copy":
        user_session.copy_file(filename)
    elif action == "delete":
        user_session.delete_file(filename)

    # Return updated session summary to JS
    summary = user_session.get_summary()
    return jsonify({
        "success" : True,
        "content" : content,           # file text (only for open)
        "accessed": summary["files_accessed"],
        "deleted" : summary["files_deleted"],
        "copied"  : summary["files_copied"]
    })


# ── ROUTE 5: Logout ──────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    username = session.get("username")
    role     = session.get("role")

    # Finalize watcher session for regular users
    result = None
    if role == "user" and username:
        result = end_session(username)

    session.clear()

    # If user was blocked → send to login with message
    if result and result["was_blocked"]:
        return render_template("login.html",
                               error=f"⚠ Session flagged. Your account has been blocked. ITS Score: {result['its_score']}")

    return redirect(url_for("login"))


# ── ROUTE 6: Session Stats (for live counter on user page) ───────────────────
@app.route("/session_stats")
def session_stats():
    """
    Called by JS every few seconds to update live counters on user page.
    Returns current session file action counts.
    """
    username     = session.get("username")
    user_session = get_session(username)

    if not user_session:
        return jsonify({"error": "No session"})

    summary = user_session.get_summary()
    return jsonify({
        "accessed": summary["files_accessed"],
        "deleted" : summary["files_deleted"],
        "copied"  : summary["files_copied"],
        "duration": summary["session_duration"]
    })


# ── ROUTE 7: Admin API — fetch all ITS scores for dashboard ──────────────────
@app.route("/api/its_scores")
def api_its_scores():
    """
    Admin dashboard JS calls this to get latest ITS scores for all users.
    Returns JSON list of users with their latest score and risk level.
    """
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn   = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Get all users with role=user
    cursor.execute("SELECT username, is_blocked FROM users WHERE role='user'")
    all_users = cursor.fetchall()

    # Get latest score per user
    cursor.execute("""
        SELECT username, score, updated
        FROM its_scores
        WHERE id IN (
            SELECT MAX(id) FROM its_scores GROUP BY username
        )
    """)
    score_rows = cursor.fetchall()
    conn.close()

    score_map = {row[0]: (row[1], row[2]) for row in score_rows}

    users = []
    for username, is_blocked in all_users:
        if username in score_map:
            score, updated = score_map[username]
        else:
            # User exists but no session yet — show with 0 score
            score, updated = 0.0, "No sessions yet"

        if score >= 70:
            risk = "HIGH"
        elif score >= 40:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        # Blocked users always show as HIGH regardless of score
        if is_blocked:
            risk = "HIGH"

        users.append({
            "username"  : username,
            "score"     : score,
            "risk"      : risk,
            "updated"   : updated,
            "is_blocked": is_blocked
        })

    users.sort(key=lambda u: u["score"], reverse=True)
    return jsonify(users)


# ── ROUTE 8: Admin API — ITS score history for graph ─────────────────────────
@app.route("/api/score_history")
def api_score_history():
    """
    Returns score history per user for the line graph on admin dashboard.
    Converts timestamps to day numbers automatically.
    """
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn   = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT username, score, updated
        FROM its_scores
        ORDER BY updated ASC
    """)
    rows = cursor.fetchall()
    conn.close()

    # Build score history per user
    # Each session = one point, numbered sequentially per user
    result = {}
    user_session_count = {}

    for username, score, updated in rows:
        if username not in result:
            result[username] = []
            user_session_count[username] = 0

        user_session_count[username] += 1
        session_num = user_session_count[username]

        result[username].append({
            "day"      : session_num,   # Session 1, 2, 3... per user
            "score"    : score,
            "timestamp": updated
        })

    return jsonify(result)




# ── ROUTE 9: Per-user activity details ──────────────────────────────────────
@app.route("/api/user_activity/<username>")
def api_user_activity(username):
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn   = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT login_time, files_accessed, files_deleted,
               files_copied, session_duration, is_anomalous, timestamp
        FROM activity_logs
        WHERE username = ?
        ORDER BY timestamp ASC
    """, (username,))
    rows = cursor.fetchall()
    conn.close()

    total_accessed = sum(r[1] for r in rows)
    total_deleted  = sum(r[2] for r in rows)
    total_copied   = sum(r[3] for r in rows)

    return jsonify({
        "sessions"      : len(rows),
        "total_accessed": total_accessed,
        "total_deleted" : total_deleted,
        "total_copied"  : total_copied,
        "session_count" : len(rows)
    })




# ── ROUTE 10: Login hour activity for analytics chart ────────────────────────
@app.route("/api/login_hours")
def api_login_hours():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn   = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT login_time FROM activity_logs")
    rows = cursor.fetchall()
    conn.close()

    # Count sessions per hour (0-23)
    hour_counts = [0] * 24
    for row in rows:
        hour = row[0]
        if hour is not None and 0 <= hour <= 23:
            hour_counts[hour] += 1

    return jsonify(hour_counts)


# ── RUN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    initialize_db()
    app.run(debug=True, host="0.0.0.0", port=5000)