import sqlite3
import os

DB_NAME = "anomaly_fi.db"
CSV_LOG = "activity_logs.csv"

def reset_demo():
    conn   = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # ── 1. Unblock all users ──────────────────────────────────────────────────
    cursor.execute("UPDATE users SET is_blocked = 0 WHERE role = 'user'")
    print("[OK] All users unblocked")

    # ── 2. Clear ITS scores ───────────────────────────────────────────────────
    cursor.execute("DELETE FROM its_scores")
    print("[OK] ITS scores cleared")

    # ── 3. Clear activity logs from DB ───────────────────────────────────────
    cursor.execute("DELETE FROM activity_logs")
    print("[OK] Activity logs cleared from database")

    conn.commit()
    conn.close()

    # ── 4. Reset CSV to header only ───────────────────────────────────────────
    with open(CSV_LOG, "w") as f:
        f.write("username,login_time,files_accessed,files_deleted,files_copied,session_duration,is_anomalous,timestamp\n")
    print("[OK] CSV log reset")

    # ── 5. Delete model.pkl so it retrains fresh ──────────────────────────────
    if os.path.exists("model.pkl"):
        os.remove("model.pkl")
        print("[OK] model.pkl deleted — will retrain on next run")

    print("\n✓ Demo reset complete. All users active, all scores cleared.")
    print("\nCurrent user status:")
    conn   = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT username, role, is_blocked FROM users")
    for row in cursor.fetchall():
        status = "BLOCKED" if row[2] == 1 else "ACTIVE"
        print(f"  {row[0]:12} | {row[1]:6} | {status}")
    conn.close()

if __name__ == "__main__":
    reset_demo()