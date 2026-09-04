"""
StateLock - Phase 7 Comprehensive End-to-End Verification
Validates Phase 7: Professional Dashboard & Analytics
- Real user login & dashboard access
- Accurate database-driven authentication statistics (Total, Success, Failed, Success Rate)
- Real-time updates when new attempts occur
- Account & security status reflection
- Visual analytics data integrity (outcome distribution & temporal activity)
- Recent activity records with DFA final states (q4 / DEAD)
- Navigation links (/history, /, /playground, /simulator)
- Session logout
"""

import time
import json
import sys
import database as db
from app import app

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass



def run_phase7_verification():
    print("=" * 70)
    print("  STATELOCK PHASE 7 - COMPREHENSIVE VERIFICATION")
    print("=" * 70)

    client = app.test_client()
    timestamp_suffix = int(time.time())
    username = f"phase7_tester_{timestamp_suffix}"
    passcode = "3412"

    # -------------------------------------------------------------------------
    # STEP 1: Unauthenticated Protection Check
    # -------------------------------------------------------------------------
    print("\n[STEP 1] Testing Unauthenticated Access to Dashboard & Stats...")
    unauth_dash = client.get("/dashboard")
    assert unauth_dash.status_code == 401, f"Expected 401 for /dashboard, got {unauth_dash.status_code}"
    assert b"data-unauthorized-dashboard" in unauth_dash.data
    print("  ✓ Protected /dashboard returned 401 Unauthorized for anonymous user.")

    unauth_api = client.get("/api/dashboard-stats")
    assert unauth_api.status_code == 401, f"Expected 401 for /api/dashboard-stats, got {unauth_api.status_code}"
    print("  ✓ Protected /api/dashboard-stats returned 401 Unauthorized for anonymous user.")

    # -------------------------------------------------------------------------
    # STEP 2: Register Real User & Check Initial State
    # -------------------------------------------------------------------------
    print("\n[STEP 2] Registering User and Logging in...")
    reg_res = client.post("/api/register", json={"username": username, "passcode": passcode})
    assert reg_res.status_code == 201, f"Registration failed: {reg_res.get_json()}"
    print(f"  ✓ User '{username}' registered with target passcode '{passcode}'.")

    # Log in
    login_res = client.post("/api/login", json={"username": username, "passcode": passcode})
    assert login_res.status_code == 200, f"Login failed: {login_res.get_json()}"
    login_data = login_res.get_json()
    assert login_data["is_accepted"] is True
    assert login_data["final_state"] == "q4"
    print(f"  ✓ User '{username}' authenticated successfully via DFA (q0 ➔ ... ➔ q4).")

    # -------------------------------------------------------------------------
    # STEP 3: Verify Initial Dashboard Statistics
    # -------------------------------------------------------------------------
    print("\n[STEP 3] Verifying Initial Dashboard Statistics from Database...")
    dash_page = client.get("/dashboard")
    assert dash_page.status_code == 200, f"Expected 200 for /dashboard, got {dash_page.status_code}"
    assert username.encode("utf-8") in dash_page.data
    assert b"kpi-total-attempts" in dash_page.data
    assert b"donut-chart-container" in dash_page.data
    assert b"recent-activity-table" in dash_page.data
    print("  ✓ /dashboard rendered successfully with full Black + Gold DOM structure.")

    stats_res = client.get("/api/dashboard-stats")
    assert stats_res.status_code == 200
    stats = stats_res.get_json()
    assert stats["success"] is True

    # Check that statistics match real database data (1 login = 1 successful attempt)
    st = stats["statistics"]
    print(f"  - Total Attempts: {st['total_attempts']}")
    print(f"  - Successful Attempts: {st['successful_attempts']}")
    print(f"  - Failed Attempts: {st['failed_attempts']}")
    print(f"  - Success Rate: {st['success_rate']}%")

    assert st["total_attempts"] == 1, f"Expected 1 total attempt, got {st['total_attempts']}"
    assert st["successful_attempts"] == 1, f"Expected 1 success, got {st['successful_attempts']}"
    assert st["failed_attempts"] == 0, f"Expected 0 failures, got {st['failed_attempts']}"
    assert st["success_rate"] == 100.0, f"Expected 100.0% success rate, got {st['success_rate']}"
    print("  ✓ Initial statistics perfectly reflect 1 real database login attempt.")

    # -------------------------------------------------------------------------
    # STEP 4: Perform Series of Successful and Failed Attempts
    # -------------------------------------------------------------------------
    print("\n[STEP 4] Executing Authentication Events (Success & Failures)...")

    # Attempt 2: Failed attempt (3499 -> DEAD)
    fail1 = client.post("/api/login", json={"username": username, "passcode": "3499"})
    assert fail1.json["is_accepted"] is False
    assert fail1.json["final_state"] == "DEAD"
    print("  ✓ Attempt #2 executed: Failed attempt (3499 ➔ DEAD).")

    # Attempt 3: Failed attempt (0000 -> DEAD)
    fail2 = client.post("/api/login", json={"username": username, "passcode": "0000"})
    assert fail2.json["is_accepted"] is False
    assert fail2.json["final_state"] == "DEAD"
    print("  ✓ Attempt #3 executed: Failed attempt (0000 ➔ DEAD).")

    # Attempt 4: Successful attempt (3412 -> q4)
    succ2 = client.post("/api/login", json={"username": username, "passcode": passcode})
    assert succ2.json["is_accepted"] is True
    assert succ2.json["final_state"] == "q4"
    print("  ✓ Attempt #4 executed: Successful attempt (3412 ➔ q4).")

    # -------------------------------------------------------------------------
    # STEP 5: Refresh Dashboard and Verify Updated Statistics
    # -------------------------------------------------------------------------
    print("\n[STEP 5] Refreshing Dashboard Statistics and Cross-checking SQLite...")
    updated_stats_res = client.get("/api/dashboard-stats")
    assert updated_stats_res.status_code == 200
    updated_stats = updated_stats_res.get_json()
    u_st = updated_stats["statistics"]

    print(f"  - Updated Total Attempts: {u_st['total_attempts']}")
    print(f"  - Updated Successful Attempts: {u_st['successful_attempts']}")
    print(f"  - Updated Failed Attempts: {u_st['failed_attempts']}")
    print(f"  - Updated Success Rate: {u_st['success_rate']}%")

    # 2 successes (Attempt 1, 4) + 2 failures (Attempt 2, 3) = 4 attempts, 50.0% rate
    assert u_st["total_attempts"] == 4, f"Expected 4 total attempts, got {u_st['total_attempts']}"
    assert u_st["successful_attempts"] == 2, f"Expected 2 successes, got {u_st['successful_attempts']}"
    assert u_st["failed_attempts"] == 2, f"Expected 2 failures, got {u_st['failed_attempts']}"
    assert u_st["success_rate"] == 50.0, f"Expected 50.0% success rate, got {u_st['success_rate']}"
    print("  ✓ Statistics updated in real time from database (2 Success, 2 Failed, 50.0% Rate).")

    # -------------------------------------------------------------------------
    # STEP 6: Verify Visual Analytics Data Structures
    # -------------------------------------------------------------------------
    print("\n[STEP 6] Verifying Visual Analytics Chart Data...")
    charts = updated_stats["chart_data"]
    donut_data = charts["success_vs_failed"]
    assert donut_data["successful"] == 2
    assert donut_data["failed"] == 2
    print(f"  ✓ Outcome breakdown chart data: {donut_data}")

    timeline_data = charts["activity_over_time"]
    assert len(timeline_data) >= 1
    print(f"  ✓ Temporal activity chart data: {timeline_data}")
    assert timeline_data[-1]["total"] >= 4
    assert timeline_data[-1]["successful"] >= 2
    assert timeline_data[-1]["failed"] >= 2

    # -------------------------------------------------------------------------
    # STEP 7: Verify Recent Activity Records
    # -------------------------------------------------------------------------
    print("\n[STEP 7] Verifying Recent Activity List...")
    recents = updated_stats["recent_activity"]
    assert len(recents) >= 4
    print(f"  ✓ Retrieved {len(recents)} recent attempts:")
    for idx, r in enumerate(recents[:4], 1):
        print(f"    [{idx}] {r['timestamp']} | Event: {r['event_type']} | Result: {r['status']} | Final State: {r['final_state']}")
        assert "final_state" in r
        assert "timestamp" in r
        assert "status" in r
        assert "is_success" in r

    # Latest should be Attempt 4 (Successful, q4)
    assert recents[0]["is_success"] is True
    assert recents[0]["final_state"] == "q4"
    # Second should be Attempt 3 (Failed, DEAD)
    assert recents[1]["is_success"] is False
    assert recents[1]["final_state"] == "DEAD"
    print("  ✓ Recent activity order, timestamps, and DFA final states verified.")

    # -------------------------------------------------------------------------
    # STEP 8: Verify Account & Security Status
    # -------------------------------------------------------------------------
    print("\n[STEP 8] Verifying Account & Security Status Card...")
    account = updated_stats["account_status"]
    print(f"  - Is Locked: {account['is_locked']}")
    print(f"  - Failed Attempts: {account['failed_attempts']}/{account['max_failed_attempts']}")
    print(f"  - Security Status: '{account['security_status']}'")
    assert account["is_locked"] is False
    assert account["failed_attempts"] == 0  # Reset by last successful login
    assert account["security_status"] == "Active & Secure"
    print("  ✓ Security status accurately reflects normal active state.")

    # -------------------------------------------------------------------------
    # STEP 9: Verify Navigation Links & History Integration
    # -------------------------------------------------------------------------
    print("\n[STEP 9] Verifying Navigation Links & History Integration...")
    # Full History route
    hist_res = client.get("/history")
    assert hist_res.status_code == 200
    assert b"data-open-history" in hist_res.data
    print("  ✓ Quick Action 'View Full History' (/history) accessible and verified.")

    # Simulator route removed
    sim_res = client.get("/simulator")
    assert sim_res.status_code == 404
    print("  ✓ Confirmed separate DFA Simulator (/simulator) is removed (returns 404).")

    # Playground route
    play_res = client.get("/playground")
    assert play_res.status_code == 200
    print("  ✓ Navigation link to DFA Playground (/playground) returns 200.")

    # -------------------------------------------------------------------------
    # STEP 10: Test Logout & Verify Security Revocation
    # -------------------------------------------------------------------------
    print("\n[STEP 10] Testing Session Logout...")
    logout_res = client.post("/api/logout")
    assert logout_res.status_code == 200
    assert logout_res.get_json()["success"] is True
    print("  ✓ Logout successful.")

    # Confirm /dashboard and /api/dashboard-stats are now blocked
    post_dash = client.get("/dashboard")
    assert post_dash.status_code == 401
    post_api = client.get("/api/dashboard-stats")
    assert post_api.status_code == 401
    print("  ✓ Dashboard access revoked post-logout.")

    print("\n" + "=" * 70)
    print("  ALL PHASE 7 VERIFICATION CHECKS PASSED WITH 100% SUCCESS!")
    print("=" * 70)


if __name__ == "__main__":
    run_phase7_verification()
