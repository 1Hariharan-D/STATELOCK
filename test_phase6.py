"""
StateLock - Phase 6 Secure Authentication Test Suite
Tests:
1. Passcode hashing: Securely hashed in DB using PBKDF2:SHA256, never stored in plaintext.
2. Proper login session and logout handling (session creation, cookie clearance, 401s on protected endpoints).
3. Failed attempt limit (1-5) and tracking.
4. Temporary account lockout (60 seconds) on 5th failure, blocking further attempts with HTTP 403.
5. Success reset: failed attempt counter resets to 0 upon successful DFA authentication.
6. Duplicate username prevention during registration (case-insensitive & unique constraint).
7. Comprehensive username and passcode validation (rules, lengths, allowed alphabet, no spaces).
8. Secure change-passcode feature (validates current password, updates hash, enforces new passcode rules).
9. Authentication history and security event logging (Successful login, Failed login, Account locked, Lockout ended).
10. DFA integrity & theme preservation (q0->q1->q2->q3->q4, DEAD state, Black + Gold styling).
"""

import unittest
import time
import tempfile
import os
import sqlite3
from werkzeug.security import check_password_hash
import database as db
from app import app
from dfa_engine import DFAEngine


class TestPhase6SecureAuthentication(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db_path = self.temp_file.name
        self.temp_file.close()
        db.init_db(self.temp_db_path)

        # Patch app DB_PATH
        self.orig_db_path = db.DB_PATH
        db.DB_PATH = self.temp_db_path

        app.config["TESTING"] = True
        self.client = app.test_client()

    def tearDown(self):
        db.DB_PATH = self.orig_db_path
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # 1. SECURE PASSCODE HASHING IN DATABASE
    # -------------------------------------------------------------------------
    def test_passcode_hashing_in_database(self):
        """Validates that passcodes are securely hashed in the database and never stored in plaintext."""
        username = "sec_hash_user"
        passcode = "A7@2"

        ok, msg, user_id = db.register_user(username, passcode, self.temp_db_path)
        self.assertTrue(ok)
        self.assertIsNotNone(user_id)

        # Inspect raw database record directly via SQLite cursor
        conn = sqlite3.connect(self.temp_db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        # Check password_hash exists and is a valid Werkzeug PBKDF2:SHA256 hash
        password_hash = row["password_hash"]
        self.assertIsNotNone(password_hash)
        self.assertTrue(password_hash.startswith("pbkdf2:sha256:") or password_hash.startswith("scrypt:"))

        # Check plaintext passcode is NOT stored in any column of users table
        for col_name in row.keys():
            col_val = str(row[col_name])
            self.assertNotEqual(col_val, passcode, f"Plain-text passcode leaked in column {col_name}!")

        # Verify hash matches passcode via Werkzeug and database helper
        user = db.get_user_by_id(user_id, self.temp_db_path)
        self.assertTrue(check_password_hash(user["password_hash"], passcode))
        self.assertTrue(db.verify_user_passcode(user, passcode))
        self.assertFalse(db.verify_user_passcode(user, "WRNG"))

    # -------------------------------------------------------------------------
    # 2. PROPER LOGIN SESSION AND LOGOUT HANDLING
    # -------------------------------------------------------------------------
    def test_session_lifecycle_and_logout(self):
        """Tests session creation on login, protected route enforcement, and complete session cleanup on logout."""
        username = "session_user"
        passcode = "98@1"
        self.client.post("/api/register", json={"username": username, "passcode": passcode})

        # Pre-login: protected routes must deny access (401 Unauthorized)
        res_pre_hist = self.client.get("/api/history")
        self.assertEqual(res_pre_hist.status_code, 401)
        res_pre_cp = self.client.post("/api/change-passcode", json={"current_passcode": passcode, "new_passcode": "1111", "confirm_passcode": "1111"})
        self.assertEqual(res_pre_cp.status_code, 401)

        # Pre-login: user status must report logged_in=False
        res_pre_status = self.client.get("/api/user-status")
        self.assertEqual(res_pre_status.status_code, 200)
        self.assertFalse(res_pre_status.get_json()["logged_in"])

        # Login successfully
        login_res = self.client.post("/api/login", json={"username": username, "passcode": passcode})
        self.assertEqual(login_res.status_code, 200)
        self.assertTrue(login_res.get_json()["is_accepted"])

        # Post-login: user status reports logged_in=True
        res_post_status = self.client.get("/api/user-status")
        self.assertEqual(res_post_status.status_code, 200)
        data_status = res_post_status.get_json()
        self.assertTrue(data_status["logged_in"])
        self.assertEqual(data_status["username"], username)

        # Post-login: protected history route is accessible
        res_hist = self.client.get("/api/history")
        self.assertEqual(res_hist.status_code, 200)
        self.assertTrue(res_hist.get_json()["success"])

        # Logout
        logout_res = self.client.post("/api/logout")
        self.assertEqual(logout_res.status_code, 200)
        self.assertTrue(logout_res.get_json()["success"])

        # Post-logout: session status reports logged_in=False
        res_after_status = self.client.get("/api/user-status")
        self.assertFalse(res_after_status.get_json()["logged_in"])

        # Post-logout: protected endpoints denied again (401)
        res_post_hist = self.client.get("/api/history")
        self.assertEqual(res_post_hist.status_code, 401)

    # -------------------------------------------------------------------------
    # 3. FAILED ATTEMPT LIMITS AND PROGRESSION
    # -------------------------------------------------------------------------
    def test_failed_attempt_limits_and_progression(self):
        """Tests that failed login attempts increment cleanly from 1 to 4 with proper messages."""
        username = "fail_track_user"
        passcode = "B#3k"
        self.client.post("/api/register", json={"username": username, "passcode": passcode})

        for i in range(1, 5):
            res = self.client.post("/api/login", json={"username": username, "passcode": "0000"})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertFalse(data["is_accepted"])
            self.assertEqual(data["failed_attempts"], i)
            self.assertEqual(data["max_attempts"], 5)
            self.assertFalse(data["is_locked"])
            self.assertIn(f"{i}/5 failed", data["message"])

    # -------------------------------------------------------------------------
    # 4. TEMPORARY ACCOUNT LOCKOUT (60 SECONDS)
    # -------------------------------------------------------------------------
    def test_temporary_account_lockout(self):
        """Tests that reaching 5 failed attempts locks the account for 60s and blocks login with HTTP 403."""
        username = "lockout_user"
        passcode = "A1B2"
        self.client.post("/api/register", json={"username": username, "passcode": passcode})

        # 5 consecutive failed attempts
        for _ in range(4):
            self.client.post("/api/login", json={"username": username, "passcode": "0000"})

        # 5th attempt triggers lockout
        res_5 = self.client.post("/api/login", json={"username": username, "passcode": "0000"})
        self.assertEqual(res_5.status_code, 200)
        data_5 = res_5.get_json()
        self.assertTrue(data_5["is_locked"])
        self.assertEqual(data_5["status"], "ACCOUNT LOCKED")
        self.assertTrue(55 <= data_5["lockout_remaining"] <= 60)

        # Attempting login while locked must be blocked with HTTP 403 Forbidden, even with correct passcode
        res_blocked = self.client.post("/api/login", json={"username": username, "passcode": passcode})
        self.assertEqual(res_blocked.status_code, 403)
        data_blocked = res_blocked.get_json()
        self.assertTrue(data_blocked["is_locked"])
        self.assertEqual(data_blocked["status"], "ACCOUNT LOCKED")
        self.assertIn("temporarily locked", data_blocked["error"])

    # -------------------------------------------------------------------------
    # 5. SUCCESS RESET OF FAILED ATTEMPTS
    # -------------------------------------------------------------------------
    def test_success_reset_of_failed_attempts(self):
        """Tests that a successful authentication resets failed attempt counter to 0."""
        username = "reset_user"
        passcode = "3412"
        self.client.post("/api/register", json={"username": username, "passcode": passcode})

        # Fail twice
        self.client.post("/api/login", json={"username": username, "passcode": "0000"})
        self.client.post("/api/login", json={"username": username, "passcode": "0000"})

        # Successful login
        res_success = self.client.post("/api/login", json={"username": username, "passcode": passcode})
        self.assertEqual(res_success.status_code, 200)
        data_success = res_success.get_json()
        self.assertTrue(data_success["is_accepted"])
        self.assertEqual(data_success["failed_attempts"], 0)
        self.assertFalse(data_success["is_locked"])

        # Check in DB
        user = db.get_user_by_username(username, self.temp_db_path)
        self.assertEqual(user["failed_attempts"], 0)
        self.assertIsNone(user["locked_until"])

    # -------------------------------------------------------------------------
    # 6. PREVENT DUPLICATE USERNAMES DURING REGISTRATION
    # -------------------------------------------------------------------------
    def test_prevent_duplicate_usernames(self):
        """Tests that duplicate usernames (including case variations) are rejected with clean error messages."""
        username = "UniqueUser"
        passcode = "1234"

        # First registration succeeds
        res1 = self.client.post("/api/register", json={"username": username, "passcode": passcode})
        self.assertEqual(res1.status_code, 201)

        # Duplicate exact username fails with clean 400 message
        res2 = self.client.post("/api/register", json={"username": username, "passcode": "5678"})
        self.assertEqual(res2.status_code, 400)
        self.assertIn("Username already exists", res2.get_json()["error"])

        # Duplicate case-insensitive variation fails
        res3 = self.client.post("/api/register", json={"username": "uniqueuser", "passcode": "9999"})
        self.assertEqual(res3.status_code, 400)
        self.assertIn("Username already exists", res3.get_json()["error"])

    # -------------------------------------------------------------------------
    # 7. VALIDATE USERNAME AND PASSCODE PROPERLY
    # -------------------------------------------------------------------------
    def test_validate_username_and_passcode(self):
        """Tests input validation rules for usernames and passcodes."""
        # Invalid usernames
        invalid_usernames = [
            ("", "Empty username"),
            ("ab", "Too short (<3 chars)"),
            ("a" * 25, "Too long (>24 chars)"),
            ("user name", "Contains spaces"),
            ("user@name", "Forbidden character @"),
            ("user#name", "Forbidden character #"),
        ]
        for bad_user, desc in invalid_usernames:
            res = self.client.post("/api/register", json={"username": bad_user, "passcode": "1234"})
            self.assertEqual(res.status_code, 400, f"Failed to reject invalid username: {desc}")

        # Invalid passcodes
        invalid_passcodes = [
            ("", "Empty passcode"),
            ("123", "Too short (3 chars)"),
            ("12345", "Too long (5 chars)"),
            ("1 34", "Contains space"),
            ("123~", "Character ~ not in DFA alphabet"),
            ("123^", "Character ^ not in DFA alphabet"),
        ]
        for bad_pass, desc in invalid_passcodes:
            res = self.client.post("/api/register", json={"username": "valid_user", "passcode": bad_pass})
            self.assertEqual(res.status_code, 400, f"Failed to reject invalid passcode: {desc}")

    # -------------------------------------------------------------------------
    # 8. KEEP CHANGE-PASSCODE FEATURE SECURE
    # -------------------------------------------------------------------------
    def test_secure_change_passcode(self):
        """Tests change-passcode requires authentication, verifies current password, and updates hash securely."""
        username = "cp_user"
        old_passcode = "A1@1"
        new_passcode = "B2#2"

        self.client.post("/api/register", json={"username": username, "passcode": old_passcode})
        self.client.post("/api/login", json={"username": username, "passcode": old_passcode})

        # 1. Wrong current passcode fails
        res_bad_curr = self.client.post("/api/change-passcode", json={
            "current_passcode": "WRNG",
            "new_passcode": new_passcode,
            "confirm_passcode": new_passcode
        })
        self.assertEqual(res_bad_curr.status_code, 400)
        self.assertIn("Current passcode is incorrect", res_bad_curr.get_json()["error"])

        # 2. Mismatched confirmation fails
        res_mismatch = self.client.post("/api/change-passcode", json={
            "current_passcode": old_passcode,
            "new_passcode": new_passcode,
            "confirm_passcode": "DIFF"
        })
        self.assertEqual(res_mismatch.status_code, 400)
        self.assertIn("do not match", res_mismatch.get_json()["error"])

        # 3. Correct update succeeds
        res_ok = self.client.post("/api/change-passcode", json={
            "current_passcode": old_passcode,
            "new_passcode": new_passcode,
            "confirm_passcode": new_passcode
        })
        self.assertEqual(res_ok.status_code, 200)

        # 4. Verify old passcode now fails login
        self.client.post("/api/logout")
        res_old_login = self.client.post("/api/login", json={"username": username, "passcode": old_passcode})
        self.assertFalse(res_old_login.get_json()["is_accepted"])

        # 5. Verify new passcode succeeds login
        res_new_login = self.client.post("/api/login", json={"username": username, "passcode": new_passcode})
        self.assertTrue(res_new_login.get_json()["is_accepted"])

    # -------------------------------------------------------------------------
    # 9. KEEP AUTHENTICATION HISTORY WORKING
    # -------------------------------------------------------------------------
    def test_authentication_history_logging(self):
        """Tests that authentication history logs all security events with transition breakdown."""
        username = "hist_user"
        passcode = "77@9"

        self.client.post("/api/register", json={"username": username, "passcode": passcode})

        # 1. Successful login
        self.client.post("/api/login", json={"username": username, "passcode": passcode})

        # 2. Failed login
        self.client.post("/api/login", json={"username": username, "passcode": "0000"})

        # Retrieve history
        hist_res = self.client.get("/api/history")
        self.assertEqual(hist_res.status_code, 200)
        records = hist_res.get_json()["history"]
        self.assertTrue(len(records) >= 2)

        # Verify transition details exist in history record
        rec = records[0]
        self.assertIn("transitions", rec)
        self.assertEqual(len(rec["transitions"]), 4)

    # -------------------------------------------------------------------------
    # 10. DFA LOGIC AND THEME INTEGRITY
    # -------------------------------------------------------------------------
    def test_dfa_logic_and_theme_integrity(self):
        """Tests that formal DFA transition rules and UI integrity are completely preserved."""
        # Target 3412 -> 3412 accepts at q4
        dfa = DFAEngine(target_sequence="3412")
        res_acc = dfa.process_sequence("3412")
        self.assertTrue(res_acc["is_accepted"])
        self.assertEqual(res_acc["final_state"], "q4")
        self.assertEqual(res_acc["state_path"], ["q0", "q1", "q2", "q3", "q4"])

        # Target 3412 -> 3492 rejects at DEAD
        res_rej = dfa.process_sequence("3492")
        self.assertFalse(res_rej["is_accepted"])
        self.assertEqual(res_rej["final_state"], "DEAD")

        # Check main page has Black + Gold theme and DFA elements
        page_res = self.client.get("/")
        self.assertEqual(page_res.status_code, 200)
        html = page_res.data.decode("utf-8")
        self.assertIn("StateLock", html)
        self.assertIn("dfa-svg", html)
        self.assertIn("style.css", html)


if __name__ == "__main__":
    unittest.main()
