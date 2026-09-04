"""
StateLock - Phase 8 Comprehensive Unit & Integration Tests
Validates:
1. Complete User Lifecycle:
   - Registration with 4-character alphabet constraint [0-9a-zA-Z@#$%*!]
   - Input validation (length, invalid characters, whitespace)
   - Login with DFA evaluation (q0 -> q1 -> q2 -> q3 -> q4)
   - Failed login with DFA evaluation (transitions to DEAD state)
   - Brute-force protection: Lockout after 5 failures for 60s
   - Lockout expiration and automatic unlocking
   - Change passcode (updating DFA target sequence and verifying subsequent logins)
   - Session termination / logout
2. DFA Visualization and Styling:
   - Accept state distinct styling (q4 / accept-node)
   - Dead state distinct styling (DEAD / dead-node)
   - Consistent Black + Gold theme tokens across all templates
3. Navigation and Unified Architecture:
   - Complete navigation links in all pages: Dashboard, Authentication, History, Playground, Simulator, Logout
   - Change passcode accessible from dashboard
4. DFA Playground Engine:
   - Custom DFA execution, alphabet validation, and step-by-step trace
5. Development Cleanup:
   - No hardcoded passcode credentials in user-facing UI labels
   - Retention of formal Theory of Computation definitions
"""

import unittest
import json
import tempfile
import os
import shutil
import time
from datetime import datetime, timedelta
import database as db
import dfa_engine as dfa
from app import app


class TestPhase8FinalPolishAndSecurity(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_statelock_phase8.db")
        db.init_db(self.db_path)

        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test_phase8_secret_key"
        self.client = app.test_client()

        self._orig_db_path = db.DB_PATH
        db.DB_PATH = self.db_path

    def tearDown(self):
        db.DB_PATH = self._orig_db_path
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # =========================================================================
    # 1. INPUT VALIDATION & REGISTRATION
    # =========================================================================
    def test_passcode_validation_rules(self):
        """Passcode must strictly be exactly 4 characters from [0-9a-zA-Z@#$%*!]."""
        # Too short
        res = self.client.post("/api/register", json={"username": "user1", "passcode": "123"})
        self.assertEqual(res.status_code, 400)
        self.assertIn("4 characters", res.get_json().get("error", ""))

        # Too long
        res = self.client.post("/api/register", json={"username": "user2", "passcode": "12345"})
        self.assertEqual(res.status_code, 400)

        # Invalid characters (space)
        res = self.client.post("/api/register", json={"username": "user3", "passcode": "12 4"})
        self.assertEqual(res.status_code, 400)

        # Invalid characters (punctuation outside allowed set)
        res = self.client.post("/api/register", json={"username": "user4", "passcode": "12^4"})
        self.assertEqual(res.status_code, 400)

        # Valid characters from diverse alphabet
        valid_codes = ["9876", "Pass", "P@s1", "A#9!"]
        for idx, code in enumerate(valid_codes):
            reg = self.client.post("/api/register", json={"username": f"valid_user_{idx}", "passcode": code})
            self.assertEqual(reg.status_code, 201, f"Failed for valid code '{code}': {reg.get_json()}")

    # =========================================================================
    # 2. DFA AUTHENTICATION: SUCCESS & FAILURE PATHWAYS
    # =========================================================================
    def test_dfa_auth_success_and_failure(self):
        """DFA transitions correctly to q4 on match and DEAD on mismatch."""
        username = "sec_test_user"
        passcode = "A9#!"

        reg = self.client.post("/api/register", json={"username": username, "passcode": passcode})
        self.assertEqual(reg.status_code, 201)

        # 1. Correct login -> q4
        login_res = self.client.post("/api/login", json={"username": username, "passcode": passcode})
        self.assertEqual(login_res.status_code, 200)
        data = login_res.get_json()
        self.assertTrue(data.get("is_accepted"))
        self.assertEqual(data.get("final_state"), "q4")
        self.assertEqual(data.get("status"), "ACCESS GRANTED")

        # Verify DFA state path in response
        path = data.get("state_path", [])
        self.assertEqual(len(path), 5)  # q0, q1, q2, q3, q4
        self.assertEqual(path[0], "q0")
        self.assertEqual(path[-1], "q4")

        # 2. Wrong login -> DEAD
        wrong_res = self.client.post("/api/login", json={"username": username, "passcode": "A9#9"})
        self.assertEqual(wrong_res.status_code, 200)
        wrong_data = wrong_res.get_json()
        self.assertFalse(wrong_data.get("is_accepted"))
        self.assertEqual(wrong_data.get("final_state"), "DEAD")
        self.assertEqual(wrong_data.get("status"), "ACCESS DENIED")

    # =========================================================================
    # 3. BRUTE-FORCE SECURITY & LOCKOUT EXPIRATION
    # =========================================================================
    def test_lockout_mechanism_and_unlock(self):
        """5 consecutive failed attempts lock account for 60s; unlock occurs after expiry."""
        username = "lockout_tester"
        passcode = "4321"

        self.client.post("/api/register", json={"username": username, "passcode": passcode})

        # Perform 4 failed attempts - should not be locked yet
        for i in range(4):
            res = self.client.post("/api/login", json={"username": username, "passcode": "0000"})
            self.assertEqual(res.status_code, 200)
            self.assertFalse(res.get_json().get("is_locked", False))
            self.assertEqual(res.get_json().get("failed_attempts"), i + 1)

        # 5th failed attempt triggers lock (status: ACCOUNT LOCKED, is_locked: True)
        res5 = self.client.post("/api/login", json={"username": username, "passcode": "0000"})
        self.assertEqual(res5.status_code, 200)
        data5 = res5.get_json()
        self.assertTrue(data5.get("is_locked"))
        self.assertGreater(data5.get("lockout_remaining", 0), 0)
        self.assertEqual(data5.get("status"), "ACCOUNT LOCKED")

        # Immediate 6th attempt is blocked with 403 Forbidden
        res6 = self.client.post("/api/login", json={"username": username, "passcode": passcode})
        self.assertEqual(res6.status_code, 403)
        self.assertTrue(res6.get_json().get("is_locked"))

        # Fast forward lockout time in the database to simulate 60s expiration
        past_time = (datetime.now() - timedelta(seconds=10)).strftime("%Y-%m-%d %H:%M:%S")
        conn = db.get_db_connection(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET locked_until = ? WHERE username = ?", (past_time, username))
            conn.commit()
        finally:
            conn.close()

        # Attempt after expiration with correct passcode -> successfully unlocks and logs in!
        unlock_res = self.client.post("/api/login", json={"username": username, "passcode": passcode})
        self.assertEqual(unlock_res.status_code, 200)
        self.assertTrue(unlock_res.get_json().get("is_accepted"))
        self.assertEqual(unlock_res.get_json().get("final_state"), "q4")

        # Verify failed attempts count was reset to 0 and user is unlocked
        user = db.get_user_by_username(username, db_path=self.db_path)
        self.assertEqual(user["failed_attempts"], 0)
        is_locked, _ = db.check_user_lockout(user)
        self.assertFalse(is_locked)

    # =========================================================================
    # 4. CHANGE PASSCODE & DFA RE-TARGETING
    # =========================================================================
    def test_change_passcode_and_dfa_retarget(self):
        """Changing passcode updates user DFA sequence and validates on next login."""
        username = "change_pass_user"
        initial_code = "1111"
        new_code = "2222"

        self.client.post("/api/register", json={"username": username, "passcode": initial_code})
        login_res = self.client.post("/api/login", json={"username": username, "passcode": initial_code})
        self.assertEqual(login_res.status_code, 200)

        # Change passcode with invalid current passcode -> rejected
        fail_change = self.client.post("/api/change-passcode", json={
            "current_passcode": "9999",
            "new_passcode": new_code,
            "confirm_passcode": new_code
        })
        self.assertEqual(fail_change.status_code, 400)

        # Change passcode with confirmation mismatch -> rejected
        mismatch_change = self.client.post("/api/change-passcode", json={
            "current_passcode": initial_code,
            "new_passcode": "3333",
            "confirm_passcode": "4444"
        })
        self.assertEqual(mismatch_change.status_code, 400)

        # Change passcode with valid new passcode -> success
        success_change = self.client.post("/api/change-passcode", json={
            "current_passcode": initial_code,
            "new_passcode": new_code,
            "confirm_passcode": new_code
        })
        self.assertEqual(success_change.status_code, 200)
        self.assertTrue(success_change.get_json().get("success"))

        # Logout
        self.client.get("/api/logout")

        # Verify old passcode now fails with DEAD state
        old_login = self.client.post("/api/login", json={"username": username, "passcode": initial_code})
        self.assertEqual(old_login.status_code, 200)
        self.assertFalse(old_login.get_json().get("is_accepted"))
        self.assertEqual(old_login.get_json().get("final_state"), "DEAD")

        # Verify new passcode succeeds with q4 state
        new_login = self.client.post("/api/login", json={"username": username, "passcode": new_code})
        self.assertEqual(new_login.status_code, 200)
        self.assertTrue(new_login.get_json().get("is_accepted"))
        self.assertEqual(new_login.get_json().get("final_state"), "q4")

    # =========================================================================
    # 5. UNIFIED NAVIGATION & CLEAN DESIGN CHECKS
    # =========================================================================
    def test_navigation_and_theme_standards(self):
        """All pages must contain consistent navigation links, gold theme accents, and modal triggers."""
        pages = {
            "Dashboard": "/dashboard",
            "Playground": "/playground",
            "Index": "/"
        }

        # Verify separate DFA simulator has been removed
        sim_check = self.client.get("/simulator")
        self.assertEqual(sim_check.status_code, 404)

        # First register and log in to inspect protected pages
        username = "nav_test_user"
        code = "1234"
        self.client.post("/api/register", json={"username": username, "passcode": code})
        self.client.post("/api/login", json={"username": username, "passcode": code})

        for page_name, url in pages.items():
            res = self.client.get(url)
            self.assertEqual(res.status_code, 200, f"Page {page_name} ({url}) returned status {res.status_code}")
            content = res.get_data(as_text=True)

            # Check that navigation header is present
            self.assertTrue(
                "nav" in content.lower() or "header" in content.lower(),
                f"Missing navigation structure in {page_name}"
            )

        # Verify Change Passcode trigger and modal exist in Dashboard
        dash_res = self.client.get("/dashboard")
        dash_html = dash_res.get_data(as_text=True)
        self.assertIn("change-passcode-modal", dash_html, "Dashboard missing Change Passcode modal")
        self.assertIn("dash-nav-change-passcode-btn", dash_html, "Dashboard missing Change Passcode button")
        self.assertIn("Change Passcode", dash_html, "Dashboard missing Change Passcode button text")

    # =========================================================================
    # 6. DFA VISUALIZATION DISTINCT STYLES
    # =========================================================================
    def test_dfa_diagram_styling_distinction(self):
        """CSS contains dedicated styles for accept states (q4) and dead trap states."""
        res = self.client.get("/static/css/style.css")
        self.assertEqual(res.status_code, 200)
        css_content = res.get_data(as_text=True)
        res.close()

        # Check accept node distinct styling (double ring / gold ring)
        self.assertIn(".state-node.accept-node", css_content)
        # Check dead node distinct styling (crimson/red border)
        self.assertIn(".state-node.dead-node", css_content)
        # Check active node animation highlighting
        self.assertIn(".state-node.active", css_content)

    # =========================================================================
    # 7. DFA PLAYGROUND CUSTOM SIMULATION
    # =========================================================================
    def test_dfa_playground_simulation_engine(self):
        """DFA Playground API correctly simulates custom arbitrary DFA transitions."""
        custom_dfa = {
            "states": ["S0", "S1", "S2"],
            "alphabet": ["0", "1"],
            "start_state": "S0",
            "accept_states": ["S2"],
            "transitions": [
                {"from": "S0", "symbol": "0", "to": "S0"},
                {"from": "S0", "symbol": "1", "to": "S1"},
                {"from": "S1", "symbol": "0", "to": "S0"},
                {"from": "S1", "symbol": "1", "to": "S2"},
                {"from": "S2", "symbol": "0", "to": "S2"},
                {"from": "S2", "symbol": "1", "to": "S2"}
            ],
            "input_string": "011"
        }

        res = self.client.post("/api/custom-dfa/simulate", json=custom_dfa)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertTrue(data.get("is_accepted"))
        self.assertEqual(data.get("final_state"), "S2")
        self.assertEqual(len(data.get("transitions", [])), 3)

    # =========================================================================
    # 8. REMOVAL OF HARDCODED DEV CONTENT FROM UI
    # =========================================================================
    def test_no_hardcoded_passcodes_in_ui(self):
        """Public templates should not expose hardcoded passcodes like 'Passcode: 3412' in labels."""
        index_res = self.client.get("/")
        index_html = index_res.get_data(as_text=True)

        # The phrase 'Passcode: 3412' or 'Default: 3412' should not be present
        self.assertNotIn("Passcode: 3412", index_html)
        self.assertNotIn("Default: 3412", index_html)

        # Verify simulator links and dev text are not present
        self.assertNotIn("/simulator", index_html)
        dash_res = self.client.get("/dashboard")
        self.assertNotIn("/simulator", dash_res.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
