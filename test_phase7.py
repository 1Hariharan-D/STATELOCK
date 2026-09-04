"""
StateLock - Phase 7 Unit Tests: Professional Dashboard & Analytics
Validates:
1. SQLite data extraction for KPI statistics (total, success, failed, success_rate).
2. Protection of /dashboard and /api/dashboard-stats (401 for unauthenticated users).
3. Real-time updates to statistics when new authentication events occur.
4. Visual analytics chart data structures (distribution & activity over time).
5. Recent activity records with timestamp, status, and DFA states.
6. Account and security status reflection (active vs locked).
7. Session logout and security termination.
"""

import unittest
import json
import tempfile
import os
import shutil
import database as db
from app import app


class TestPhase7DashboardAnalytics(unittest.TestCase):
    def setUp(self):
        # Create isolated temporary database for test run
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_statelock_phase7.db")
        db.init_db(self.db_path)

        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test_phase7_secret_key"
        self.client = app.test_client()

        # Patch DB_PATH in database module
        self._orig_db_path = db.DB_PATH
        db.DB_PATH = self.db_path

    def tearDown(self):
        db.DB_PATH = self._orig_db_path
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_unauthenticated_access_denied(self):
        """Unauthenticated requests to /dashboard and /api/dashboard-stats must be rejected with 401."""
        # 1. Direct page access
        dash_res = self.client.get("/dashboard")
        self.assertEqual(dash_res.status_code, 401)
        self.assertIn(b"data-unauthorized-dashboard", dash_res.data)

        # 2. API endpoint access
        api_res = self.client.get("/api/dashboard-stats")
        self.assertEqual(api_res.status_code, 401)
        data = api_res.get_json()
        self.assertFalse(data.get("success", False))

    def test_initial_dashboard_stats_zero(self):
        """A newly registered user must start with zero attempts and clean analytics."""
        username = "new_analyst"
        passcode = "3412"

        # Register user
        reg_res = self.client.post("/api/register", json={"username": username, "passcode": passcode})
        self.assertEqual(reg_res.status_code, 201)
        user = db.get_user_by_username(username, self.db_path)
        user_id = user["id"]

        # Check database function directly
        stats = db.get_user_dashboard_stats(user_id, self.db_path)
        self.assertTrue(stats["success"])
        self.assertEqual(stats["statistics"]["total_attempts"], 0)
        self.assertEqual(stats["statistics"]["successful_attempts"], 0)
        self.assertEqual(stats["statistics"]["failed_attempts"], 0)
        self.assertEqual(stats["statistics"]["success_rate"], 0.0)
        self.assertEqual(len(stats["recent_activity"]), 0)
        self.assertEqual(len(stats["chart_data"]["activity_over_time"]), 0)
        self.assertEqual(stats["account_status"]["security_status"], "Active & Secure")

    def test_authenticated_dashboard_page_and_api(self):
        """Authenticated users can access /dashboard and /api/dashboard-stats with accurate real data."""
        username = "sec_officer"
        passcode = "A1B2"

        self.client.post("/api/register", json={"username": username, "passcode": passcode})
        # Log in
        login_res = self.client.post("/api/login", json={"username": username, "passcode": passcode})
        self.assertEqual(login_res.status_code, 200)

        # 1. Access /dashboard
        dash_res = self.client.get("/dashboard")
        self.assertEqual(dash_res.status_code, 200)
        self.assertIn(b"Welcome back,", dash_res.data)
        self.assertIn(b"sec_officer", dash_res.data)
        self.assertIn(b"kpi-total-attempts", dash_res.data)
        self.assertIn(b"donut-chart-container", dash_res.data)

        # 2. Access /api/dashboard-stats
        api_res = self.client.get("/api/dashboard-stats")
        self.assertEqual(api_res.status_code, 200)
        stats = api_res.get_json()
        self.assertTrue(stats["success"])
        self.assertEqual(stats["user"]["username"], username)
        # Login itself is recorded as 1 successful attempt
        self.assertEqual(stats["statistics"]["total_attempts"], 1)
        self.assertEqual(stats["statistics"]["successful_attempts"], 1)
        self.assertEqual(stats["statistics"]["failed_attempts"], 0)
        self.assertEqual(stats["statistics"]["success_rate"], 100.0)
        self.assertEqual(len(stats["recent_activity"]), 1)
        self.assertEqual(stats["recent_activity"][0]["final_state"], "q4")

    def test_statistics_real_time_update(self):
        """Verifies that authentication attempts increment statistics in real time."""
        username = "metric_tester"
        passcode = "3412"

        self.client.post("/api/register", json={"username": username, "passcode": passcode})
        # Initial login (Success #1)
        self.client.post("/api/login", json={"username": username, "passcode": passcode})

        stats_1 = self.client.get("/api/dashboard-stats").get_json()["statistics"]
        self.assertEqual(stats_1["total_attempts"], 1)
        self.assertEqual(stats_1["successful_attempts"], 1)
        self.assertEqual(stats_1["failed_attempts"], 0)
        self.assertEqual(stats_1["success_rate"], 100.0)

        # Perform 2 failed attempts
        self.client.post("/api/login", json={"username": username, "passcode": "0000"})
        self.client.post("/api/login", json={"username": username, "passcode": "9999"})

        stats_2 = self.client.get("/api/dashboard-stats").get_json()["statistics"]
        self.assertEqual(stats_2["total_attempts"], 3)
        self.assertEqual(stats_2["successful_attempts"], 1)
        self.assertEqual(stats_2["failed_attempts"], 2)
        # 1 / 3 = 33.3%
        self.assertEqual(stats_2["success_rate"], 33.3)

        # Perform another successful attempt
        self.client.post("/api/login", json={"username": username, "passcode": passcode})

        stats_3 = self.client.get("/api/dashboard-stats").get_json()["statistics"]
        self.assertEqual(stats_3["total_attempts"], 4)
        self.assertEqual(stats_3["successful_attempts"], 2)
        self.assertEqual(stats_3["failed_attempts"], 2)
        # 2 / 4 = 50.0%
        self.assertEqual(stats_3["success_rate"], 50.0)

    def test_recent_activity_fields_and_limit(self):
        """Recent activity records must include timestamp, result, final_state, and state_path."""
        username = "activity_user"
        passcode = "WXYZ"

        self.client.post("/api/register", json={"username": username, "passcode": passcode})
        self.client.post("/api/login", json={"username": username, "passcode": passcode})
        self.client.post("/api/login", json={"username": username, "passcode": "FAIL"})

        stats = self.client.get("/api/dashboard-stats").get_json()
        recents = stats["recent_activity"]
        self.assertEqual(len(recents), 2)

        # Most recent first: failed attempt
        first = recents[0]
        self.assertFalse(first["is_success"])
        self.assertIn("DENIED", first["status"])
        self.assertEqual(first["final_state"], "DEAD")
        self.assertTrue(len(first["timestamp"]) > 0)
        self.assertTrue(len(first["state_path"]) > 0)

        # Second record: successful attempt
        second = recents[1]
        self.assertTrue(second["is_success"])
        self.assertIn("GRANTED", second["status"])
        self.assertEqual(second["final_state"], "q4")

    def test_account_status_and_lockout_reflection(self):
        """When an account is locked after 5 failures, dashboard metrics reflect locked state and elevated danger."""
        username = "locked_user"
        passcode = "1234"

        self.client.post("/api/register", json={"username": username, "passcode": passcode})
        # Log in first so we have a valid session
        self.client.post("/api/login", json={"username": username, "passcode": passcode})

        # Trigger 5 failed attempts
        for _ in range(5):
            self.client.post("/api/login", json={"username": username, "passcode": "9999"})

        # Query stats from active session
        res = self.client.get("/api/dashboard-stats")
        data = res.get_json()
        account = data["account_status"]

        self.assertTrue(account["is_locked"])
        self.assertTrue(account["lockout_remaining"] > 0)
        self.assertEqual(account["failed_attempts"], 5)
        self.assertEqual(account["security_level"], "danger")
        self.assertIn("Temporarily Locked", account["security_status"])

    def test_chart_data_accuracy(self):
        """Chart data structures must match real database numbers and format."""
        username = "chart_user"
        passcode = "7890"

        self.client.post("/api/register", json={"username": username, "passcode": passcode})
        self.client.post("/api/login", json={"username": username, "passcode": passcode})
        self.client.post("/api/login", json={"username": username, "passcode": "0000"})

        stats = self.client.get("/api/dashboard-stats").get_json()
        charts = stats["chart_data"]

        # 1. Success vs Failed
        self.assertEqual(charts["success_vs_failed"]["successful"], 1)
        self.assertEqual(charts["success_vs_failed"]["failed"], 1)

        # 2. Activity over time
        over_time = charts["activity_over_time"]
        self.assertEqual(len(over_time), 1)
        self.assertEqual(over_time[0]["total"], 2)
        self.assertEqual(over_time[0]["successful"], 1)
        self.assertEqual(over_time[0]["failed"], 1)

    def test_logout_terminates_dashboard_access(self):
        """Logging out must terminate session and revoke access to /dashboard and /api/dashboard-stats."""
        username = "logout_user"
        passcode = "4567"

        self.client.post("/api/register", json={"username": username, "passcode": passcode})
        self.client.post("/api/login", json={"username": username, "passcode": passcode})

        # Check access before logout
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/api/dashboard-stats").status_code, 200)

        # Logout
        logout_res = self.client.post("/api/logout")
        self.assertEqual(logout_res.status_code, 200)

        # Access after logout must be 401
        self.assertEqual(self.client.get("/dashboard").status_code, 401)
        self.assertEqual(self.client.get("/api/dashboard-stats").status_code, 401)


if __name__ == "__main__":
    unittest.main()
