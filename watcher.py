from datetime import datetime
import sqlite3
from database1 import log_activity, update_its_score, block_user, DB_NAME
from ml_model import get_its_score

# ── FILE GENERATOR ───────────────────────────────────────────────────────────
def generate_files():
    files = {
        "Reports": {},
        "Confidential": {},
        "System": {}
    }

    departments = ["Finance", "HR", "Engineering", "Marketing", "Operations",
                   "Legal", "IT", "Sales", "Procurement", "Admin"]
    quarters    = ["Q1 2024", "Q2 2024", "Q3 2024", "Q4 2024",
                   "Q1 2025", "Q2 2025"]

    for i in range(1, 61):
        dept    = departments[i % len(departments)]
        quarter = quarters[i % len(quarters)]
        name    = f"report_{i:02d}.pdf"
        files["Reports"][name] = f"""DEPARTMENT REPORT — {dept}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Period     : {quarter}
Department : {dept}
Prepared by: System
Report ID  : RPT-{1000 + i}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary:
Total tasks completed : {20 + i * 3}
Pending items         : {i % 8}
Performance index     : {75 + (i % 20)}%
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INTERNAL USE ONLY"""

    categories = ["Financial", "Employee", "Strategic", "Legal",
                  "Client", "Product"]
    for i in range(1, 31):
        cat  = categories[i % len(categories)]
        name = f"confidential_{i:02d}.docx"
        files["Confidential"][name] = f"""⚠ CONFIDENTIAL DOCUMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Classification : STRICTLY CONFIDENTIAL
Category       : {cat} Data
Document ID    : CONF-{2000 + i}
Access Level   : RESTRICTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Content:
Record entries    : {50 + i * 7}
Last modified     : 2026-03-{(i % 28) + 1:02d}
Authorized users  : Admin only
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
UNAUTHORIZED ACCESS IS PROHIBITED"""

    sys_types = ["Network", "Database", "Security", "Backup",
                 "Firewall", "Auth", "Monitor", "Proxy", "DNS", "VPN"]
    for i in range(1, 11):
        stype = sys_types[i - 1]
        name  = f"sys_config_{i:02d}.txt"
        files["System"][name] = f"""SYSTEM CONFIGURATION — {stype}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[RESTRICTED — IT DEPARTMENT ONLY]
Config ID  : SYS-{3000 + i}
Module     : {stype} Configuration
Version    : 2.{i}.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Parameters:
Host       : 192.168.1.{100 + i}
Port       : {5000 + i * 10}
Timeout    : {30 + i}s
Retry      : {i % 5 + 1}"""

    return files


SIMULATED_FILES = generate_files()

FLAT_FILES = {}
for folder, files in SIMULATED_FILES.items():
    for filename, content in files.items():
        FLAT_FILES[filename] = content


# ── SESSION CLASS ─────────────────────────────────────────────────────────────
class UserSession:
    def __init__(self, username):
        self.username         = username
        self.login_hour       = datetime.now().hour
        self.login_time       = datetime.now()
        self.files_accessed   = 0
        self.files_deleted    = 0
        self.files_copied     = 0
        self.action_log       = []
        self.deleted_files    = set()
        print(f"[SESSION] Started for '{username}' at hour {self.login_hour}")

    def open_file(self, filename):
        if filename in self.deleted_files:
            return None
        self.files_accessed += 1
        self._record(f"Opened '{filename}'")
        return FLAT_FILES.get(filename, "File content unavailable.")

    def copy_file(self, filename):
        if filename in self.deleted_files:
            return
        self.files_copied += 1
        self._record(f"Copied '{filename}'")

    def delete_file(self, filename):
        if filename in self.deleted_files:
            return
        self.files_deleted += 1
        self.deleted_files.add(filename)
        self._record(f"Deleted '{filename}'")

    def _record(self, action):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry     = f"[{timestamp}] {action}"
        self.action_log.append(entry)
        print(f"[WATCHER] {self.username} → {entry}")

    def get_summary(self):
        duration = int((datetime.now() - self.login_time).total_seconds() / 60)
        return {
            "username"        : self.username,
            "login_hour"      : self.login_hour,
            "files_accessed"  : self.files_accessed,
            "files_deleted"   : self.files_deleted,
            "files_copied"    : self.files_copied,
            "session_duration": max(1, duration),
            "action_log"      : self.action_log
        }

    def finalize(self):
        summary  = self.get_summary()
        duration = summary["session_duration"]

        print(f"\n[WATCHER] Finalizing session for '{self.username}'")
        print(f"  Login hour      : {self.login_hour}")
        print(f"  Files accessed  : {self.files_accessed}")
        print(f"  Files deleted   : {self.files_deleted}")
        print(f"  Files copied    : {self.files_copied}")
        print(f"  Session duration: {duration} min")

        # ── SAFE FEATURE ENGINEERING (no division errors) ──
        copy_rate = self.files_copied / duration if duration > 0 else 0
        delete_rate = self.files_deleted / duration if duration > 0 else 0
        access_rate = self.files_accessed / duration if duration > 0 else 0
        activity_rate = (
            self.files_accessed + self.files_deleted + self.files_copied
        ) / duration if duration > 0 else 0

        is_idle = 1 if activity_rate == 0 and duration > 60 else 0

        print(f"  Copy Rate   : {round(copy_rate, 2)}")
        print(f"  Delete Rate : {round(delete_rate, 2)}")
        print(f"  Access Rate : {round(access_rate, 2)}")
        print(f"  Activity Rate: {round(activity_rate, 2)}")
        print(f"  Idle Flag   : {is_idle}")

        # ── ML CALL (UNCHANGED) ──
        its_score, risk = get_its_score(
            login_time       = self.login_hour,
            files_accessed   = self.files_accessed,
            files_deleted    = self.files_deleted,
            files_copied     = self.files_copied,
            session_duration = duration
        )

        print(f"  ITS Score : {its_score}")
        print(f"  Risk Level: {risk}")

        is_anomalous = 1 if risk == "HIGH" else 0

        log_activity(
            username         = self.username,
            login_time       = self.login_hour,
            files_accessed   = self.files_accessed,
            files_deleted    = self.files_deleted,
            files_copied     = self.files_copied,
            session_duration = duration,
            is_anomalous     = is_anomalous
        )

        update_its_score(self.username, its_score)

        was_blocked = False
        if risk == "HIGH":
            block_user(self.username)
            was_blocked = True
            print(f"[ALERT] '{self.username}' BLOCKED — ITS Score {its_score}")

        return its_score, risk, was_blocked


# ── ACTIVE SESSIONS ───────────────────────────────────────────────────────────
active_sessions = {}

def start_session(username):
    active_sessions[username] = UserSession(username)

def end_session(username):
    if username not in active_sessions:
        return None
    session = active_sessions.pop(username)
    its_score, risk, was_blocked = session.finalize()
    return {
        "its_score"  : its_score,
        "risk"       : risk,
        "was_blocked": was_blocked,
        "summary"    : session.get_summary()
    }

def get_session(username):
    return active_sessions.get(username)