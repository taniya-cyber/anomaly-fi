import sqlite3
import hashlib
import os

# ── CONFIG ──────────────────────────────────────────────────────────────────
DB_NAME = "anomaly_fi.db"
CSV_LOG = "activity_logs.csv"


# ── HELPER ──────────────────────────────────────────────────────────────────
def hash_password(password):
    """Converts plain password into SHA-256 hash. Never store plain passwords."""
    return hashlib.sha256(password.encode()).hexdigest()


# ── MAIN SETUP ──────────────────────────────────────────────────────────────
def initialize_db():
    conn   = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # ── TABLE 1: users ───────────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            password    TEXT    NOT NULL,
            role        TEXT    NOT NULL CHECK(role IN ('admin', 'user')),
            is_blocked  INTEGER DEFAULT 0
        )
    """)

    # ── TABLE 2: activity_logs ───────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            username         TEXT    NOT NULL,
            login_time       INTEGER,
            files_accessed   INTEGER DEFAULT 0,
            files_deleted    INTEGER DEFAULT 0,
            files_copied     INTEGER DEFAULT 0,
            session_duration INTEGER DEFAULT 0,
            is_anomalous     INTEGER DEFAULT 0,
            timestamp        TEXT    NOT NULL
        )
    """)

    # ── TABLE 3: its_scores ──────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS its_scores (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT NOT NULL,
            score     REAL DEFAULT 0.0,
            updated   TEXT NOT NULL
        )
    """)

    conn.commit()

    # ── SEED USERS ───────────────────────────────────────────────────────────
    seed_users = [
        ("admin",   hash_password("admin123"),   "admin"),
        ("aman",    hash_password("aman123"),    "user"),
        ("ramita",  hash_password("ramita123"),  "user"),
        ("sucheta", hash_password("sucheta123"), "user"),
        ("arjun",   hash_password("arjun123"),   "user"),
        ("priya",   hash_password("priya123"),   "user"),
        ("vikram",  hash_password("vikram123"),  "user"),
    ]

    for username, password, role in seed_users:
        try:
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, password, role)
            )
        except sqlite3.IntegrityError:
            pass    # already exists, skip

    conn.commit()
    conn.close()

    # ── CSV HEADER ───────────────────────────────────────────────────────────
    if not os.path.exists(CSV_LOG):
        with open(CSV_LOG, "w") as f:
            f.write("username,login_time,files_accessed,files_deleted,files_copied,session_duration,is_anomalous,timestamp\n")

    print(f"[OK] Database ready : {DB_NAME}")
    print(f"[OK] CSV log ready  : {CSV_LOG}")


# ── AUTH HELPER ──────────────────────────────────────────────────────────────
def get_user(username, password):
    conn   = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=? AND is_blocked=0",
        (username, hash_password(password))
    )
    user = cursor.fetchone()
    conn.close()
    return user


# ── LOG HELPER ───────────────────────────────────────────────────────────────
def log_activity(username, login_time, files_accessed,
                 files_deleted, files_copied, session_duration,
                 is_anomalous=0):
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn   = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO activity_logs
        (username, login_time, files_accessed, files_deleted,
         files_copied, session_duration, is_anomalous, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (username, login_time, files_accessed, files_deleted,
          files_copied, session_duration, is_anomalous, timestamp))
    conn.commit()
    conn.close()

    with open(CSV_LOG, "a") as f:
        f.write(f"{username},{login_time},{files_accessed},{files_deleted},"
                f"{files_copied},{session_duration},{is_anomalous},{timestamp}\n")


# ── ITS SCORE HELPER ─────────────────────────────────────────────────────────
def update_its_score(username, score):
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn   = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO its_scores (username, score, updated) VALUES (?, ?, ?)",
        (username, score, timestamp)
    )
    conn.commit()
    conn.close()


# ── BLOCK USER ───────────────────────────────────────────────────────────────
def block_user(username):
    conn   = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET is_blocked=1 WHERE username=?",
        (username,)
    )
    conn.commit()
    conn.close()
    print(f"[ALERT] User '{username}' has been BLOCKED.")


# ── RUN TO INITIALIZE ────────────────────────────────────────────────────────
if __name__ == "__main__":
    initialize_db()
    print("\nAll accounts:")
    print("  admin   / admin123")
    print("  aman    / aman123")
    print("  ramita  / ramita123")
    print("  sucheta / sucheta123")
    print("  arjun   / arjun123")
    print("  priya   / priya123")
    print("  vikram  / vikram123")