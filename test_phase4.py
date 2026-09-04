"""
StateLock - Phase 4 Security Enhancements Test Suite
Validates:
1. Correct login -> Access Granted -> failed attempts reset to 0
2. Wrong login 1-4 times -> failed attempt counter increases (1/5, 2/5, 3/5, 4/5)
3. Wrong login 5th time -> account locked with 60-second lockout
4. Try login while locked -> authentication blocked & lockout remaining returned
5. After 60 seconds (or expired lockout) -> account becomes available again and logs 'Lockout ended'
6. Successful login -> counter resets to 0
7. Logout -> completely ends session & protected pages (/api/history, /api/change-passcode) denied
8. Server-side input validation and error sanitization (no internal leaks)
9. Anti-caching and security headers
"""

import unittest
import time
import tempfile
import os
import database as db
from app import app


class TestPhase4DatabaseSecurity(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db_path = self.temp_file.name
        self.temp_file.close()
        db.init_db(self.temp_db_path)

    def tearDown(self):
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except Exception:
                pass

    def test_failed_attempt_increment_and_lockout(self):
        """Tests failed attempts incrementing up to 5 and triggering 60-second lockout."""
        ok, msg, user_id = db.register_user("sec_user_1", "3412", self.temp_db_path)
        self.assertTrue(ok)

        # 1-4 failed attempts
        for i in range(1, 5):
            res = db.record_failed_attempt(user_id, "sec_user_1", self.temp_db_path, lockout_duration=60)
            self.assertFalse(res["is_locked"])
            self.assertEqual(res["failed_attempts"], i)
            self.assertEqual(res["lockout_remaining"], 0)

        # 5th failed attempt -> LOCKOUT
        res5 = db.record_failed_attempt(user_id, "sec_user_1", self.temp_db_path, lockout_duration=60)
        self.assertTrue(res5["is_locked"])
        self.assertEqual(res5["failed_attempts"], 5)
        self.assertEqual(res5["lockout_remaining"], 60)

        # Check lockout
        user = db.get_user_by_id(user_id, self.temp_db_path)
        is_locked, remaining = db.check_user_lockout(user, self.temp_db_path)
        self.assertTrue(is_locked)
        self.assertTrue(50 <= remaining <= 60)

    def test_success_reset(self):
        """Tests that reset_failed_attempts clears failed attempts and lockout."""
        ok, _, user_id = db.register_user("sec_user_2", "A1B2", self.temp_db_path)
        self.assertTrue(ok)

        # Fail 3 times
        for _ in range(3):
            db.record_failed_attempt(user_id, "sec_user_2", self.temp_db_path)

        user = db.get_user_by_id(user_id, self.temp_db_path)
        self.assertEqual(user["failed_attempts"], 3)

        # Reset on success
        db.reset_failed_attempts(user_id, self.temp_db_path)
        user_after = db.get_user_by_id(user_id, self.temp_db_path)
        self.assertEqual(user_after["failed_attempts"], 0)
        self.assertIsNone(user_after["locked_until"])

    def test_lockout_expiration(self):
        """Tests that when lockout duration passes, account unlocks and logs 'Lockout ended'."""
        ok, _, user_id = db.register_user("sec_user_3", "9999", self.temp_db_path)
        self.assertTrue(ok)

        # Set lockout duration to 1 second
        for _ in range(5):
            db.record_failed_attempt(user_id, "sec_user_3", self.temp_db_path, lockout_duration=1)

        user = db.get_user_by_id(user_id, self.temp_db_path)
        is_locked, remaining = db.check_user_lockout(user, self.temp_db_path)
        self.assertTrue(is_locked)

        # Sleep past the 1s lockout
        time.sleep(1.2)

        # Check lockout again - should auto-unlock and log 'Lockout ended'
        user = db.get_user_by_id(user_id, self.temp_db_path)
        is_locked_after, rem_after = db.check_user_lockout(user, self.temp_db_path)
        self.assertFalse(is_locked_after)
        self.assertEqual(rem_after, 0)

        # Verify security history records
        history = db.get_user_history(user_id, limit=10, db_path=self.temp_db_path)
        event_types = [h["event_type"] for h in history]
        self.assertIn("Account locked", event_types)
        self.assertIn("Lockout ended", event_types)


class TestPhase4FlaskAPISecurity(unittest.TestCase):
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

    def test_full_phase4_security_lifecycle(self):
        """
        Executes all 7 Phase 4 verification requirements:
        1. Correct login -> Access Granted -> failed attempts reset to 0
        2. Wrong login 1-4 times -> counter increases (1/5, 2/5, 3/5, 4/5)
        3. Wrong login 5th time -> account locked with 60s countdown
        4. Try login while locked -> authentication blocked (HTTP 403)
        5. After lockout expires -> account becomes available again
        6. Successful login -> counter resets
        7. Logout -> protected pages cannot be accessed without login
        """
        username = "sec_test_user"
        passcode = "2311"

        # Register user
        reg_res = self.client.post("/api/register", json={"username": username, "passcode": passcode})
        self.assertEqual(reg_res.status_code, 201)

        # 1. Correct login -> Access Granted -> failed attempts = 0
        login_ok = self.client.post("/api/login", json={"username": username, "passcode": passcode})
        self.assertEqual(login_ok.status_code, 200)
        data_ok = login_ok.get_json()
        self.assertTrue(data_ok["is_accepted"])
        self.assertEqual(data_ok["final_state"], "q4")
        self.assertEqual(data_ok["failed_attempts"], 0)
        self.assertFalse(data_ok["is_locked"])

        # 2. Wrong login 1-4 times -> counter increases
        for attempt in range(1, 5):
            res_wrong = self.client.post("/api/login", json={"username": username, "passcode": "0000"})
            self.assertEqual(res_wrong.status_code, 200)
            data_wrong = res_wrong.get_json()
            self.assertFalse(data_wrong["is_accepted"])
            self.assertEqual(data_wrong["final_state"], "DEAD")
            self.assertEqual(data_wrong["failed_attempts"], attempt)
            self.assertFalse(data_wrong["is_locked"])
            self.assertIn(f"{attempt}/5 failed", data_wrong["message"])

        # 3. Wrong login 5th time -> account locked
        res_5th = self.client.post("/api/login", json={"username": username, "passcode": "0000"})
        self.assertEqual(res_5th.status_code, 200)
        data_5th = res_5th.get_json()
        self.assertFalse(data_5th["is_accepted"])
        self.assertTrue(data_5th["is_locked"])
        self.assertEqual(data_5th["failed_attempts"], 5)
        self.assertEqual(data_5th["status"], "ACCOUNT LOCKED")
        self.assertTrue(55 <= data_5th["lockout_remaining"] <= 60)

        # 4. Try login while locked -> authentication prevented (403 Forbidden)
        res_locked_attempt = self.client.post("/api/login", json={"username": username, "passcode": passcode})
        self.assertEqual(res_locked_attempt.status_code, 403)
        data_locked = res_locked_attempt.get_json()
        self.assertTrue(data_locked["is_locked"])
        self.assertEqual(data_locked["status"], "ACCOUNT LOCKED")
        self.assertIn("temporarily locked", data_locked["error"])

        # Lockout status endpoint check
        lock_stat = self.client.get(f"/api/lockout-status?username={username}")
        self.assertEqual(lock_stat.status_code, 200)
        self.assertTrue(lock_stat.get_json()["is_locked"])

        # 5. After lockout expires -> account available again (mock lockout expiration)
        user = db.get_user_by_username(username, self.temp_db_path)
        # Manually set locked_until in past to simulate 60s elapsed
        conn = db.get_db_connection(self.temp_db_path)
        conn.execute("UPDATE users SET locked_until = ? WHERE id = ?", (time.time() - 5, user["id"]))
        conn.commit()
        conn.close()

        # Check lockout status again -> should be unlocked
        lock_stat_after = self.client.get(f"/api/lockout-status?username={username}")
        self.assertEqual(lock_stat_after.status_code, 200)
        self.assertFalse(lock_stat_after.get_json()["is_locked"])

        # 6. Successful login after unlock -> counter resets
        login_after_lock = self.client.post("/api/login", json={"username": username, "passcode": passcode})
        self.assertEqual(login_after_lock.status_code, 200)
        data_after = login_after_lock.get_json()
        self.assertTrue(data_after["is_accepted"])
        self.assertEqual(data_after["final_state"], "q4")
        self.assertEqual(data_after["failed_attempts"], 0)
        self.assertFalse(data_after["is_locked"])

        # History should contain all security events: Successful login, Failed login, Account locked, Lockout ended
        hist_res = self.client.get("/api/history")
        self.assertEqual(hist_res.status_code, 200)
        hist = hist_res.get_json()["history"]
        events = [h.get("event_type") for h in hist]
        self.assertIn("Successful login", events)
        self.assertIn("Failed login", events)
        self.assertIn("Account locked", events)
        self.assertIn("Lockout ended", events)

        # 7. Logout -> protected pages cannot be accessed
        logout_res = self.client.post("/api/logout")
        self.assertEqual(logout_res.status_code, 200)

        # Protected pages check after logout
        hist_after_logout = self.client.get("/api/history")
        self.assertEqual(hist_after_logout.status_code, 401)

        passcode_after_logout = self.client.post("/api/change-passcode", json={
            "current_passcode": "2311",
            "new_passcode": "A7@2",
            "confirm_passcode": "A7@2"
        })
        self.assertEqual(passcode_after_logout.status_code, 401)

    def test_input_validation_and_error_sanitization(self):
        """Tests that malformed or invalid inputs produce clean error responses without crashing."""
        # Empty inputs
        res1 = self.client.post("/api/register", json={})
        self.assertEqual(res1.status_code, 400)
        self.assertFalse(res1.get_json()["success"])

        # Invalid username
        res2 = self.client.post("/api/register", json={"username": "ab", "passcode": "1234"})
        self.assertEqual(res2.status_code, 400)

        # Passcode with spaces
        res3 = self.client.post("/api/register", json={"username": "test_user", "passcode": "1 34"})
        self.assertEqual(res3.status_code, 400)

        # Non-string data types
        res4 = self.client.post("/api/login", json={"username": 12345, "passcode": ["a", "b"]})
        self.assertEqual(res4.status_code, 400)

    def test_security_headers(self):
        """Tests that response headers include anti-cache and security policies."""
        res = self.client.get("/")
        self.assertIn("no-store", res.headers.get("Cache-Control", ""))
        self.assertEqual(res.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")


if __name__ == "__main__":
    unittest.main()
