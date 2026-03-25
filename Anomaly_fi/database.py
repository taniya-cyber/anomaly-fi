import sqlite3
import hashlib
import os

# CONFIG 
DB_NAME = "anomaly_fi.db"          # Single file = entire database
CSV_LOG = "activity_logs.csv"      # Flat file backup of every action

# ── HELPER 
def hash_password(password: str) -> str:
    """Never store plain text passwords. SHA-256 turns 'abc' into a long hash."""
    return hashlib.sha256(password.encode()).hexdigest()


# ── MAIN SETUP 
def initialize_db():
    """
    Creates all tables if they don't exist yet.
    Safe to call multiple times — won't overwrite existing data.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # TABLE 1: users 
    # Stores everyone who can log in (both admins and regular users)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            password    TEXT    NOT NULL,
            role        TEXT    NOT NULL CHECK(role IN ('admin', 'user')),
            is_blocked  INTEGER DEFAULT 0   -- 0 = active, 1 = blocked by system
        )
    """)

    # ── TABLE 2: activity_logs 
    # Every action a user takes gets recorded here by the Watcher
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT    NOT NULL,
            action       TEXT    NOT NULL,   -- e.g. 'file_access', 'file_delete'
            target       TEXT,               -- which file was touched
            timestamp    TEXT    NOT NULL,   -- when it happened
            is_anomalous INTEGER DEFAULT 0   -- 0 = normal, 1 = flagged by AI
        )
    """)

    # ── TABLE 3: its_scores 
    # Insider Threat Score per user — updated live by ML module later
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS its_scores (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT    NOT NULL,
            score     REAL    DEFAULT 0.0,   -- 0.0 (safe) to 100.0 (critical)
            updated   TEXT    NOT NULL
        )
    """)

    conn.commit()

    # ── SEED DEFAULT USERS 
    # Creates 1 admin + 3 users only if they don't already exist
    seed_users = [
        ("admin",  hash_password("admin123"),  "admin"),
        ("aman",  hash_password("aman123"),  "user"),
        ("ramita",    hash_password("ramita123"),    "user"),
        ("sucheta",hash_password("sucheta123"),"user"),
    ]

    for username, password, role in seed_users:
        try:
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, password, role)
            )
        except sqlite3.IntegrityError:
            pass    # User already exists, skip silently

    conn.commit()
    conn.close()

    # ── CREATE CSV HEADER (if file doesn't exist yet) 
    if not os.path.exists(CSV_LOG):
        with open(CSV_LOG, "w") as f:
            f.write("username,action,target,timestamp,is_anomalous\n")

    print(f"[✓] Database ready → {DB_NAME}")
    print(f"[✓] CSV log ready  → {CSV_LOG}")


# ── AUTH HELPER (used by login module later) 
def get_user(username: str, password: str):
    """
    Returns user row if credentials match, None otherwise.
    Also checks if user is blocked.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=? AND is_blocked=0",
        (username, hash_password(password))
    )
    user = cursor.fetchone()
    conn.close()
    return user     # None if wrong credentials or blocked


# ── RUN DIRECTLY TO INITIALIZE 
if __name__ == "__main__":
    initialize_db()
    print("\nDefault accounts created:")
    print("  admin   / admin123  (role: admin)")
    print("  aman   / aman123  (role: user)")
    print("  ramita     / ramita123    (role: user)")
    print("  sucheta / sucheta123(role: user)")