"""
StateLock - SQLite Database Manager
Handles user accounts, secure encryption/hashing, passcode changes,
complete character-by-character DFA authentication history, and
security enhancements (failed attempt limit, 60s lockout, security events).
"""

import sqlite3
import os
import re
import json
import time
import hashlib
import secrets
import base64
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Any
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "statelock.db")
SECRET_KEY = os.environ.get("SECRET_KEY", "statelock_master_key_toc_2026_dfa")

# Allowed passcode regex: exactly 4 characters from 0-9, a-z, A-Z, @ # $ % * !
PASSCODE_REGEX = re.compile(r"^[0-9a-zA-Z@#$%*!]{4}$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,24}$")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 60


def _get_path(db_path: Optional[str] = None) -> str:
    """Returns the provided db_path or the active DB_PATH module variable."""
    return db_path if db_path is not None else DB_PATH


def _encrypt_passcode(passcode: str, secret: str = SECRET_KEY) -> str:
    """Encrypts a passcode using PBKDF2 keystream encryption (no plaintext in DB)."""
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, 10000, len(passcode.encode("utf-8")))
    ct = bytes([b ^ k for b, k in zip(passcode.encode("utf-8"), key)])
    return base64.b64encode(salt + ct).decode("utf-8")


def _decrypt_passcode(token: str, secret: str = SECRET_KEY) -> str:
    """Decrypts a passcode token."""
    raw = base64.b64decode(token.encode("utf-8"))
    salt, ct = raw[:16], raw[16:]
    key = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, 10000, len(ct))
    return bytes([b ^ k for b, k in zip(ct, key)]).decode("utf-8")


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Creates a database connection with row factory enabled and a busy timeout."""
    conn = sqlite3.connect(_get_path(db_path), timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initializes the database schema if tables do not exist, and applies migrations."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        
        # 1. Users Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                passcode_encrypted TEXT,
                failed_attempts INTEGER DEFAULT 0,
                locked_until REAL DEFAULT NULL,
                last_failed_at TIMESTAMP DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Migrations for users table
        cursor.execute("PRAGMA table_info(users)")
        user_columns = [row["name"] for row in cursor.fetchall()]
        if "passcode_encrypted" not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN passcode_encrypted TEXT")
        if "failed_attempts" not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
        if "locked_until" not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN locked_until REAL DEFAULT NULL")
        if "last_failed_at" not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN last_failed_at TIMESTAMP DEFAULT NULL")

        # 2. Authentication & Security History Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT NOT NULL,
                input_sequence TEXT,
                status TEXT NOT NULL,
                final_state TEXT NOT NULL,
                state_path TEXT NOT NULL,
                transitions_json TEXT,
                event_type TEXT DEFAULT 'AUTH_ATTEMPT',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)

        # Migrations for auth_history table
        cursor.execute("PRAGMA table_info(auth_history)")
        hist_columns = [row["name"] for row in cursor.fetchall()]
        if "input_sequence" not in hist_columns:
            cursor.execute("ALTER TABLE auth_history ADD COLUMN input_sequence TEXT")
        if "transitions_json" not in hist_columns:
            cursor.execute("ALTER TABLE auth_history ADD COLUMN transitions_json TEXT")
        if "event_type" not in hist_columns:
            cursor.execute("ALTER TABLE auth_history ADD COLUMN event_type TEXT DEFAULT 'AUTH_ATTEMPT'")

        conn.commit()
    finally:
        conn.close()


def register_user(username: str, passcode: str, db_path: Optional[str] = None) -> Tuple[bool, str, Optional[int]]:
    """
    Registers a new user with a unique username and 4-character passcode.
    Hashed securely and stored as encrypted DFA pattern (never plaintext).
    """
    clean_username = (username or "").strip()
    clean_passcode = (passcode or "").strip()

    # 1. Validate Username
    if not clean_username:
        return False, "Username cannot be empty.", None
    if not USERNAME_REGEX.match(clean_username):
        return False, "Username must be 3-24 characters (letters, numbers, underscores, hyphens).", None

    # 2. Validate Passcode
    if " " in passcode:
        return False, "Spaces are not allowed in the passcode.", None
    if len(clean_passcode) != 4:
        return False, "Passcode must be exactly 4 characters.", None
    if not PASSCODE_REGEX.match(clean_passcode):
        return False, "Passcode can only contain 0-9, a-z, A-Z, and @ # $ % * !", None

    # 3. Check if username already exists prior to insertion
    user_exists = get_user_by_username(clean_username, db_path)
    if user_exists:
        return False, "Username already exists. Please choose another username.", None

    # 4. Hash and Encrypt Passcode securely
    hashed_passcode = generate_password_hash(clean_passcode, method="pbkdf2:sha256")
    encrypted_passcode = _encrypt_passcode(clean_passcode)

    # 5. Save to Database
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, passcode_encrypted, failed_attempts, locked_until)
            VALUES (?, ?, ?, 0, NULL)
            """,
            (clean_username, hashed_passcode, encrypted_passcode)
        )
        user_id = cursor.lastrowid
        conn.commit()
        return True, f"User '{clean_username}' registered successfully!", user_id
    except sqlite3.IntegrityError:
        return False, "Username already exists. Please choose another username.", None
    except Exception:
        return False, "Registration error occurred. Please try again.", None
    finally:
        conn.close()


def get_user_by_username(username: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves a user by username (case-insensitive)."""
    if not username:
        return None
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, username, password_hash, passcode_encrypted, failed_attempts, locked_until, last_failed_at, created_at
            FROM users WHERE LOWER(username) = LOWER(?)
            """,
            (username.strip(),)
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    except Exception:
        return None
    finally:
        conn.close()


def verify_user_passcode(user: Optional[Dict[str, Any]], passcode: str) -> bool:
    """
    Verifies an input passcode against the user's stored cryptographic password_hash.
    Uses PBKDF2:SHA256 comparison via Werkzeug.
    """
    if not user or not user.get("password_hash") or not passcode:
        return False
    try:
        return check_password_hash(user["password_hash"], str(passcode).strip())
    except Exception:
        return False


def get_user_by_id(user_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves a user by ID."""
    if not user_id:
        return None
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, username, password_hash, passcode_encrypted, failed_attempts, locked_until, last_failed_at, created_at
            FROM users WHERE id = ?
            """,
            (user_id,)
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    except Exception:
        return None
    finally:
        conn.close()


def get_user_target_sequence(user: Dict[str, Any]) -> Optional[str]:
    """Decrypts and returns the target sequence for the user's DFA machine."""
    if not user or not user.get("passcode_encrypted"):
        return None
    try:
        return _decrypt_passcode(user["passcode_encrypted"])
    except Exception:
        return None


def check_user_lockout(user: Dict[str, Any], db_path: Optional[str] = None) -> Tuple[bool, int]:
    """
    Checks if a user's account is currently locked.
    If the lockout duration has expired, automatically clears the lockout and records 'Lockout ended' in security history.
    
    Returns:
        (is_locked: bool, remaining_seconds: int)
    """
    if not user:
        return False, 0

    locked_until = user.get("locked_until")
    if locked_until is None:
        return False, 0

    try:
        lock_time = float(locked_until)
    except (ValueError, TypeError):
        return False, 0

    now = time.time()
    if now < lock_time:
        remaining = max(1, int(lock_time - now) + 1)
        return True, remaining
    else:
        # Lockout expired: reset failed_attempts and clear locked_until
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],)
            )
            conn.commit()
            
            # Record 'Lockout ended' in security history
            log_auth_attempt(
                user_id=user["id"],
                username=user["username"],
                input_sequence="",
                is_success=True,
                final_state="q0",
                state_path=["q0"],
                transitions=[],
                event_type="Lockout ended",
                status_override="LOCKOUT ENDED",
                db_path=db_path
            )
        except Exception:
            pass
        finally:
            conn.close()

        return False, 0


def record_failed_attempt(
    user_id: int,
    username: str,
    db_path: Optional[str] = None,
    lockout_duration: int = LOCKOUT_DURATION_SECONDS
) -> Dict[str, Any]:
    """
    Increments consecutive failed authentication attempts for a user.
    If failed attempts reach MAX_FAILED_ATTEMPTS (5), triggers temporary account lockout for 60 seconds
    and logs an 'Account locked' security event.
    
    Returns:
        Dictionary with lockout status, failed attempt count, and remaining lockout seconds.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        current_attempts = row["failed_attempts"] if row and row["failed_attempts"] is not None else 0
        
        new_attempts = current_attempts + 1

        if new_attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = time.time() + lockout_duration
            cursor.execute(
                """
                UPDATE users 
                SET failed_attempts = ?, locked_until = ?, last_failed_at = datetime('now', 'localtime')
                WHERE id = ?
                """,
                (new_attempts, locked_until, user_id)
            )
            conn.commit()

            # Record 'Account locked' in security history
            log_auth_attempt(
                user_id=user_id,
                username=username,
                input_sequence="",
                is_success=False,
                final_state="DEAD",
                state_path=["q0", "DEAD"],
                transitions=[],
                event_type="Account locked",
                status_override="ACCOUNT LOCKED",
                db_path=db_path
            )

            return {
                "is_locked": True,
                "failed_attempts": new_attempts,
                "max_attempts": MAX_FAILED_ATTEMPTS,
                "lockout_remaining": lockout_duration
            }
        else:
            cursor.execute(
                """
                UPDATE users 
                SET failed_attempts = ?, last_failed_at = datetime('now', 'localtime')
                WHERE id = ?
                """,
                (new_attempts, user_id)
            )
            conn.commit()

            return {
                "is_locked": False,
                "failed_attempts": new_attempts,
                "max_attempts": MAX_FAILED_ATTEMPTS,
                "lockout_remaining": 0
            }
    except Exception:
        return {
            "is_locked": False,
            "failed_attempts": 1,
            "max_attempts": MAX_FAILED_ATTEMPTS,
            "lockout_remaining": 0
        }
    finally:
        conn.close()


def reset_failed_attempts(user_id: int, db_path: Optional[str] = None) -> None:
    """
    Resets failed attempts to 0 and clears any lock status on successful authentication.
    """
    if not user_id:
        return
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_id,)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def update_user_passcode(
    user_id: int,
    current_passcode: str,
    new_passcode: str,
    confirm_passcode: str,
    db_path: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Updates the passcode for a logged-in user after verifying the current passcode.
    """
    user = get_user_by_id(user_id, db_path)
    if not user:
        return False, "User not found."

    clean_curr = (current_passcode or "").strip()
    clean_new = (new_passcode or "").strip()
    clean_conf = (confirm_passcode or "").strip()

    # 1. Verify current passcode via password hash
    if not check_password_hash(user["password_hash"], clean_curr):
        return False, "Current passcode is incorrect."

    # 2. Check new passcode match
    if clean_new != clean_conf:
        return False, "New passcode and confirmation do not match."

    # 3. Validate new passcode rules
    if " " in new_passcode:
        return False, "Spaces are not allowed in the passcode."
    if len(clean_new) != 4:
        return False, "New passcode must be exactly 4 characters."
    if not PASSCODE_REGEX.match(clean_new):
        return False, "New passcode can only contain 0-9, a-z, A-Z, and @ # $ % * !"

    # 4. Hash and encrypt new passcode
    new_hash = generate_password_hash(clean_new, method="pbkdf2:sha256")
    new_encrypted = _encrypt_passcode(clean_new)

    # 5. Update in database
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash = ?, passcode_encrypted = ? WHERE id = ?",
            (new_hash, new_encrypted, user_id)
        )
        conn.commit()
        return True, "Passcode updated successfully!"
    except Exception:
        return False, "Failed to update passcode. Please try again."
    finally:
        conn.close()


def log_auth_attempt(
    user_id: Optional[int],
    username: str,
    input_sequence: str,
    is_success: bool,
    final_state: str,
    state_path: List[str],
    transitions: List[Dict[str, Any]],
    event_type: str = "AUTH_ATTEMPT",
    status_override: Optional[str] = None,
    db_path: Optional[str] = None
) -> int:
    """Logs an authentication attempt or security event with full transition details to the database."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        path_str = " ➔ ".join(state_path) if state_path else "q0"
        
        if status_override:
            status_str = status_override
        else:
            status_str = "ACCESS GRANTED" if is_success else "ACCESS DENIED"

        transitions_json = json.dumps(transitions) if transitions else "[]"

        cursor.execute(
            """
            INSERT INTO auth_history (
                user_id, username, input_sequence, status, final_state, state_path, 
                transitions_json, event_type, timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
            """,
            (
                user_id,
                (username or "").strip(),
                input_sequence or "",
                status_str,
                final_state or "q0",
                path_str,
                transitions_json,
                event_type
            )
        )
        history_id = cursor.lastrowid
        conn.commit()
        return history_id
    except Exception:
        return 0
    finally:
        conn.close()


def get_user_history(user_id: int, limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves authentication and security event history with transition breakdown for a specific user."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, user_id, username, input_sequence, status, final_state, state_path, 
                   transitions_json, event_type, timestamp
            FROM auth_history
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (user_id, limit)
        )
        rows = cursor.fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["transitions"] = json.loads(item["transitions_json"]) if item.get("transitions_json") else []
            except Exception:
                item["transitions"] = []
            result.append(item)
        return result
    except Exception:
        return []
    finally:
        conn.close()


def get_user_dashboard_stats(user_id: int, db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Computes real authentication analytics and account status for a user directly from SQLite.
    Includes KPI metrics, visual analytics chart data, and recent attempts.
    """
    user = get_user_by_id(user_id, db_path)
    if not user:
        return {
            "success": False,
            "error": "User not found"
        }

    # Evaluate lockout status (automatically unlocks if time expired)
    is_locked, lockout_remaining = check_user_lockout(user, db_path)
    # Refresh user record in case lockout was cleared
    if not is_locked and user.get("locked_until") is not None:
        user = get_user_by_id(user_id, db_path) or user

    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()

        # 1. Total Successful Attempts
        cursor.execute(
            """
            SELECT COUNT(*) 
            FROM auth_history 
            WHERE user_id = ? AND (status IN ('ACCESS GRANTED', 'SUCCESS') OR event_type = 'Successful login')
            """,
            (user_id,)
        )
        successful_attempts = cursor.fetchone()[0] or 0

        # 2. Total Failed Attempts (excluding notification events like 'Account locked')
        cursor.execute(
            """
            SELECT COUNT(*) 
            FROM auth_history 
            WHERE user_id = ? AND (event_type = 'Failed login' OR (status IN ('ACCESS DENIED', 'FAILURE') AND event_type != 'Account locked'))
            """,
            (user_id,)
        )
        failed_attempts = cursor.fetchone()[0] or 0

        total_attempts = successful_attempts + failed_attempts
        success_rate = round((successful_attempts / total_attempts * 100), 1) if total_attempts > 0 else 0.0

        # 3. Activity Over Time (grouped by date) - REAL data from auth_history
        cursor.execute(
            """
            SELECT 
                substr(timestamp, 1, 10) AS day,
                COUNT(*) AS total,
                SUM(CASE WHEN status IN ('ACCESS GRANTED', 'SUCCESS') OR event_type = 'Successful login' THEN 1 ELSE 0 END) AS successful,
                SUM(CASE WHEN event_type = 'Failed login' OR (status IN ('ACCESS DENIED', 'FAILURE') AND event_type != 'Account locked') THEN 1 ELSE 0 END) AS failed
            FROM auth_history
            WHERE user_id = ? AND (event_type IN ('Successful login', 'Failed login') OR (status IN ('ACCESS GRANTED', 'ACCESS DENIED', 'SUCCESS', 'FAILURE') AND event_type != 'Account locked'))
            GROUP BY day
            ORDER BY day ASC
            """,
            (user_id,)
        )
        activity_rows = cursor.fetchall()
        activity_over_time = [
            {
                "date": row["day"],
                "total": row["total"],
                "successful": row["successful"] or 0,
                "failed": row["failed"] or 0
            }
            for row in activity_rows
        ]

        # 4. Recent Authentication Activity (up to 10 latest attempts)
        cursor.execute(
            """
            SELECT id, timestamp, input_sequence, status, final_state, state_path, event_type
            FROM auth_history
            WHERE user_id = ? AND (event_type IN ('Successful login', 'Failed login') OR status IN ('ACCESS GRANTED', 'ACCESS DENIED', 'SUCCESS', 'FAILURE'))
            ORDER BY id DESC
            LIMIT 10
            """,
            (user_id,)
        )
        recent_rows = cursor.fetchall()
        recent_activity = []
        for r in recent_rows:
            is_success = r["status"] in ("ACCESS GRANTED", "SUCCESS") or r["event_type"] == "Successful login"
            recent_activity.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "input_sequence": r["input_sequence"],
                "status": r["status"],
                "final_state": r["final_state"],
                "is_success": is_success,
                "state_path": r["state_path"],
                "event_type": r["event_type"]
            })

        # Latest attempt timestamp
        last_attempt_at = recent_activity[0]["timestamp"] if recent_activity else None

        # 5. Security Status assessment
        failed_count = user.get("failed_attempts") or 0
        if is_locked:
            security_status = f"Temporarily Locked ({lockout_remaining}s remaining)"
            security_level = "danger"
        elif failed_count >= 3:
            security_status = f"Elevated Risk ({failed_count}/{MAX_FAILED_ATTEMPTS} failed attempts)"
            security_level = "warning"
        elif failed_count > 0:
            security_status = f"Active ({failed_count}/{MAX_FAILED_ATTEMPTS} failed attempt)"
            security_level = "attention"
        else:
            security_status = "Active & Secure"
            security_level = "normal"

        return {
            "success": True,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "created_at": user.get("created_at"),
            },
            "account_status": {
                "is_locked": is_locked,
                "lockout_remaining": lockout_remaining,
                "failed_attempts": failed_count,
                "max_failed_attempts": MAX_FAILED_ATTEMPTS,
                "security_status": security_status,
                "security_level": security_level
            },
            "statistics": {
                "total_attempts": total_attempts,
                "successful_attempts": successful_attempts,
                "failed_attempts": failed_attempts,
                "success_rate": success_rate,
                "last_attempt_at": last_attempt_at
            },
            "chart_data": {
                "success_vs_failed": {
                    "successful": successful_attempts,
                    "failed": failed_attempts
                },
                "activity_over_time": activity_over_time
            },
            "recent_activity": recent_activity
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
    finally:
        conn.close()

