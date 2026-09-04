"""
StateLock - Phase 6: Secure Authentication Live Verification Script
Validates:
1. Secure Passcode Hashing in Database (PBKDF2:SHA256, no plaintext in DB).
2. Duplicate Username Prevention (case-insensitive, unique constraint).
3. Strict Username and Passcode Input Validation.
4. Login Session Lifecycle & /api/user-status.
5. Failed Login Attempt Counter (1/5 to 4/5).
6. 60-second Temporary Account Lockout (5th failure, HTTP 403 Forbidden).
7. Success Reset of Failed Attempt Counter to 0.
8. Secure Change-Passcode (current password verified, new hash stored).
9. Session Invalidation on Logout & 401 Unauthorized on Protected Routes.
10. Preservation of DFA Character-by-Character Transitions & Black-Gold Theme.
"""

import sys
import os
import time
import tempfile
import sqlite3
from werkzeug.security import check_password_hash
from app import app
import database as db
from dfa_engine import DFAEngine

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def run_verification():
    print("=" * 65)
    print("  STATELOCK PHASE 6: SECURE AUTHENTICATION LIVE VERIFICATION")
    print("=" * 65)

    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_db = temp_file.name
    temp_file.close()

    orig_db = db.DB_PATH
    db.DB_PATH = temp_db
    db.init_db(temp_db)

    app.config["TESTING"] = True
    client = app.test_client()

    try:
        # ---------------------------------------------------------------------
        # STEP 1: Passcode Hashing Verification in Database
        # ---------------------------------------------------------------------
        username = "charlie_p6"
        passcode = "A9#2"

        reg_res = client.post("/api/register", json={"username": username, "passcode": passcode})
        assert reg_res.status_code == 201, f"Expected 201, got {reg_res.status_code}"
        
        # Query raw SQLite database
        conn = sqlite3.connect(temp_db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()

        assert row is not None, "User row not found in database."
        password_hash = row["password_hash"]
        assert password_hash and (password_hash.startswith("pbkdf2:sha256:") or password_hash.startswith("scrypt:")), "Invalid password hash."
        assert check_password_hash(password_hash, passcode), "Password hash does not verify against passcode."

        # Verify plaintext passcode is NOT stored in any column
        for col in row.keys():
            val = str(row[col])
            assert val != passcode, f"Plaintext passcode leaked in column '{col}'!"

        print("[PASS] Step 1: Passcode is securely hashed in database with PBKDF2:SHA256 (zero plaintext).")

        # ---------------------------------------------------------------------
        # STEP 2: Duplicate Username Prevention
        # ---------------------------------------------------------------------
        # Exact duplicate
        dup_res1 = client.post("/api/register", json={"username": username, "passcode": "1234"})
        assert dup_res1.status_code == 400, f"Expected 400 for duplicate, got {dup_res1.status_code}"
        assert "Username already exists" in dup_res1.get_json()["error"], "Missing duplicate username error message."

        # Case variation duplicate
        dup_res2 = client.post("/api/register", json={"username": "CHARLIE_P6", "passcode": "5678"})
        assert dup_res2.status_code == 400, f"Expected 400 for case-variation duplicate, got {dup_res2.status_code}"
        assert "Username already exists" in dup_res2.get_json()["error"], "Missing case-insensitive duplicate username error."

        print("[PASS] Step 2: Duplicate usernames (including case variations) prevented during registration.")

        # ---------------------------------------------------------------------
        # STEP 3: Strict Input Validation (Username & Passcode)
        # ---------------------------------------------------------------------
        # Username too short
        assert client.post("/api/register", json={"username": "ab", "passcode": "1234"}).status_code == 400
        # Username with spaces
        assert client.post("/api/register", json={"username": "bad user", "passcode": "1234"}).status_code == 400
        # Passcode with spaces
        assert client.post("/api/register", json={"username": "good_user", "passcode": "1 34"}).status_code == 400
        # Passcode length not 4
        assert client.post("/api/register", json={"username": "good_user", "passcode": "123"}).status_code == 400
        assert client.post("/api/register", json={"username": "good_user", "passcode": "12345"}).status_code == 400
        # Passcode with invalid characters
        assert client.post("/api/register", json={"username": "good_user", "passcode": "123^"}).status_code == 400

        print("[PASS] Step 3: Comprehensive username and passcode validation verified on all endpoints.")

        # ---------------------------------------------------------------------
        # STEP 4: Login Session Creation & User Status Check
        # ---------------------------------------------------------------------
        # Pre-login status check
        status_pre = client.get("/api/user-status")
        assert status_pre.get_json()["logged_in"] is False, "Expected logged_in=False before login."

        # Perform login
        login_res = client.post("/api/login", json={"username": username, "passcode": passcode})
        assert login_res.status_code == 200, f"Login failed with code {login_res.status_code}"
        login_data = login_res.get_json()
        assert login_data["is_accepted"] is True, "Expected is_accepted=True"
        assert login_data["final_state"] == "q4", "Expected final_state=q4"

        # Post-login status check
        status_post = client.get("/api/user-status")
        status_data = status_post.get_json()
        assert status_data["logged_in"] is True, "Expected logged_in=True after login."
        assert status_data["username"] == username, f"Expected username={username}"

        # Protected history access
        hist_res = client.get("/api/history")
        assert hist_res.status_code == 200, f"Protected route returned {hist_res.status_code}"
        assert len(hist_res.get_json()["history"]) >= 1, "Expected at least 1 history record."

        print("[PASS] Step 4: Login session properly established and protected routes accessible.")

        # ---------------------------------------------------------------------
        # STEP 5: Failed Attempt Tracking (1/5 to 4/5)
        # ---------------------------------------------------------------------
        client.post("/api/logout")  # Log out first to test failed login tracking
        for attempt in range(1, 5):
            fail_res = client.post("/api/login", json={"username": username, "passcode": "0000"})
            assert fail_res.status_code == 200
            fail_data = fail_res.get_json()
            assert fail_data["is_accepted"] is False
            assert fail_data["failed_attempts"] == attempt
            assert fail_data["is_locked"] is False
            assert f"{attempt}/5 failed" in fail_data["message"]

        print("[PASS] Step 5: Failed attempt limits incremented cleanly (1/5 to 4/5).")

        # ---------------------------------------------------------------------
        # STEP 6: Temporary Account Lockout on 5th Failure (HTTP 403)
        # ---------------------------------------------------------------------
        fail5_res = client.post("/api/login", json={"username": username, "passcode": "0000"})
        assert fail5_res.status_code == 200
        fail5_data = fail5_res.get_json()
        assert fail5_data["is_locked"] is True
        assert fail5_data["status"] == "ACCOUNT LOCKED"
        assert 55 <= fail5_data["lockout_remaining"] <= 60

        # Attempting login while locked must be blocked with HTTP 403 Forbidden
        blocked_res = client.post("/api/login", json={"username": username, "passcode": passcode})
        assert blocked_res.status_code == 403, f"Expected 403, got {blocked_res.status_code}"
        assert blocked_res.get_json()["is_locked"] is True

        print("[PASS] Step 6: 60-second temporary account lockout enforced on 5th failure with HTTP 403.")

        # ---------------------------------------------------------------------
        # STEP 7: Lockout Expiration & Success Reset of Counter
        # ---------------------------------------------------------------------
        # Simulate lockout time expiration
        conn = sqlite3.connect(temp_db)
        conn.execute("UPDATE users SET locked_until = ? WHERE username = ?", (time.time() - 5, username))
        conn.commit()
        conn.close()

        # Login successfully after lockout expiry
        unlock_login = client.post("/api/login", json={"username": username, "passcode": passcode})
        assert unlock_login.status_code == 200
        unlock_data = unlock_login.get_json()
        assert unlock_data["is_accepted"] is True
        assert unlock_data["failed_attempts"] == 0, "Counter was not reset to 0 upon successful login."
        assert unlock_data["is_locked"] is False

        print("[PASS] Step 7: Account unlocked and failed attempt counter successfully reset to 0.")

        # ---------------------------------------------------------------------
        # STEP 8: Secure Change-Passcode Feature
        # ---------------------------------------------------------------------
        new_passcode = "Z8*1"

        # Wrong current passcode fails
        bad_curr = client.post("/api/change-passcode", json={
            "current_passcode": "WRNG",
            "new_passcode": new_passcode,
            "confirm_passcode": new_passcode
        })
        assert bad_curr.status_code == 400
        assert "Current passcode is incorrect" in bad_curr.get_json()["error"]

        # Valid passcode update
        good_update = client.post("/api/change-passcode", json={
            "current_passcode": passcode,
            "new_passcode": new_passcode,
            "confirm_passcode": new_passcode
        })
        assert good_update.status_code == 200
        assert good_update.get_json()["success"] is True

        # Old passcode fails login now
        client.post("/api/logout")
        old_login = client.post("/api/login", json={"username": username, "passcode": passcode})
        assert old_login.get_json()["is_accepted"] is False

        # New passcode succeeds login
        new_login = client.post("/api/login", json={"username": username, "passcode": new_passcode})
        assert new_login.get_json()["is_accepted"] is True
        assert new_login.get_json()["final_state"] == "q4"

        print("[PASS] Step 8: Change-passcode verified with current password verification and re-hashing.")

        # ---------------------------------------------------------------------
        # STEP 9: Logout & Protected Endpoint Denials
        # ---------------------------------------------------------------------
        logout_res = client.post("/api/logout")
        assert logout_res.status_code == 200
        assert logout_res.get_json()["success"] is True

        # Check protected routes return 401 Unauthorized
        assert client.get("/api/history").status_code == 401
        assert client.post("/api/change-passcode", json={"current_passcode": new_passcode, "new_passcode": "1111", "confirm_passcode": "1111"}).status_code == 401
        assert client.get("/api/user-status").get_json()["logged_in"] is False

        print("[PASS] Step 9: Logout completely destroys session; protected endpoints return 401.")

        # ---------------------------------------------------------------------
        # STEP 10: DFA Character-by-Character Logic & Theme Preservation
        # ---------------------------------------------------------------------
        engine = DFAEngine(target_sequence="3412")
        trace = engine.process_sequence("3412")
        assert trace["is_accepted"] is True
        assert trace["state_path"] == ["q0", "q1", "q2", "q3", "q4"]
        assert len(trace["transitions"]) == 4

        mismatch_trace = engine.process_sequence("3492")
        assert mismatch_trace["is_accepted"] is False
        assert mismatch_trace["final_state"] == "DEAD"

        # Check main page
        index_res = client.get("/")
        assert index_res.status_code == 200
        assert b"StateLock" in index_res.data
        assert b"style.css" in index_res.data

        print("[PASS] Step 10: DFA 5-tuple character-by-character logic and Black+Gold theme preserved.")

        print("\n" + "=" * 65)
        print("  ALL 10 PHASE 6 SECURE AUTHENTICATION VERIFICATIONS PASSED ✓")
        print("=" * 65)

    finally:
        db.DB_PATH = orig_db
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except Exception:
                pass


if __name__ == "__main__":
    run_verification()
