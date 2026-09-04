"""
StateLock - Phase 8 Comprehensive End-to-End Verification
Executes the full 14-step user journey:
1. User Registration with custom 4-character passcode from [0-9a-zA-Z@#$%*!]
2. DFA Authentication (q0 -> q1 -> q2 -> q3 -> q4, ACCESS GRANTED)
3. Dashboard Analytics & Real SQLite Stats verification
4. History & Transition Inspection verification
5. Passcode Change via /api/change-passcode (updates DFA target sequence)
6. Old passcode rejection & DFA trap transition (DEAD state)
7. Input validation rules (rejection of spaces, wrong lengths, invalid symbols)
8. Consecutive failed attempts tracking (1 -> 5)
9. Brute-force account lockout enforcement (60s timer, status: ACCOUNT LOCKED)
10. Active lockout block enforcement (HTTP 403 Forbidden)
11. Lockout expiration & automatic account unlock upon correct authentication
12. Independent DFA Playground simulation trace
13. Session termination / logout & protected resource security
14. Black + Gold theme & clean UI verification (no hardcoded dev passcodes)
"""

import sys
import time
from datetime import datetime, timedelta
import database as db
import dfa_engine as dfa
from app import app

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def run_phase8_verification():
    print("=" * 75)
    print("  STATELOCK PHASE 8 - COMPREHENSIVE END-TO-END VERIFICATION")
    print("  Final Polish, Security Testing, DFA Verification, & Cleanup")
    print("=" * 75)

    client = app.test_client()
    ts = int(time.time())
    username = f"phase8_user_{ts}"
    passcode = "P@s1"
    new_passcode = "9#W2"

    # -------------------------------------------------------------------------
    # STEP 1: Registration with Custom 4-Character Passcode
    # -------------------------------------------------------------------------
    print(f"\n[STEP 1] Registering User '{username}' with passcode '{passcode}'...")
    reg_res = client.post("/api/register", json={"username": username, "passcode": passcode})
    assert reg_res.status_code == 201, f"Registration failed: {reg_res.get_json()}"
    print(f"  ✓ User '{username}' successfully registered.")

    # -------------------------------------------------------------------------
    # STEP 2: DFA Authentication with Correct Passcode
    # -------------------------------------------------------------------------
    print("\n[STEP 2] Authenticating via DFA Engine with Correct Passcode...")
    login_res = client.post("/api/login", json={"username": username, "passcode": passcode})
    assert login_res.status_code == 200, f"Login failed: {login_res.get_json()}"
    login_data = login_res.get_json()
    assert login_data.get("is_accepted") is True, "Expected is_accepted=True"
    assert login_data.get("final_state") == "q4", f"Expected final_state='q4', got {login_data.get('final_state')}"
    assert login_data.get("status") == "ACCESS GRANTED"
    state_path = login_data.get("state_path", [])
    assert state_path == ["q0", "q1", "q2", "q3", "q4"], f"Unexpected path: {state_path}"
    print(f"  ✓ DFA processed '{passcode}': {' ➔ '.join(state_path)} [ACCESS GRANTED]")

    # -------------------------------------------------------------------------
    # STEP 3: Dashboard Analytics & Real SQLite Stats
    # -------------------------------------------------------------------------
    print("\n[STEP 3] Verifying Dashboard & Real Database Statistics...")
    dash_page = client.get("/dashboard")
    assert dash_page.status_code == 200, f"Dashboard access failed: {dash_page.status_code}"
    dash_html = dash_page.get_data(as_text=True)
    assert "change-passcode-modal" in dash_html, "Missing change-passcode-modal in dashboard"
    assert "dash-nav-change-passcode-btn" in dash_html, "Missing change-passcode button in dashboard"

    stats_res = client.get("/api/dashboard-stats")
    assert stats_res.status_code == 200, f"Stats retrieval failed: {stats_res.get_json()}"
    stats_data = stats_res.get_json()
    assert stats_data["success"] is True
    st = stats_data["statistics"]
    assert st.get("total_attempts") >= 1, "Total attempts should be >= 1"
    assert st.get("successful_attempts") >= 1, "Successful attempts should be >= 1"
    assert st.get("success_rate") == 100.0, "Initial success rate should be 100%"
    assert len(stats_data.get("recent_activity", [])) >= 1, "Recent activity table should have rows"
    recent_entry = stats_data["recent_activity"][0]
    assert recent_entry["final_state"] == "q4"
    print(f"  ✓ Dashboard Statistics verified: Total={st['total_attempts']}, Success={st['successful_attempts']}, Rate={st['success_rate']}%")

    # -------------------------------------------------------------------------
    # STEP 4: History & Transition Inspection
    # -------------------------------------------------------------------------
    print("\n[STEP 4] Verifying History Records...")
    hist_res = client.get("/api/history")
    assert hist_res.status_code == 200, f"History retrieval failed: {hist_res.get_json()}"
    hist_records = hist_res.get_json().get("history", [])
    assert len(hist_records) >= 1, "History records should contain at least 1 record"
    latest_hist = hist_records[0]
    assert latest_hist["final_state"] == "q4"
    assert latest_hist["status"] == "ACCESS GRANTED"
    print(f"  ✓ Full History verified: Found {len(hist_records)} logged records for '{username}'.")

    # -------------------------------------------------------------------------
    # STEP 5: Change Passcode & DFA Target Sequence Update
    # -------------------------------------------------------------------------
    print(f"\n[STEP 5] Updating Passcode to '{new_passcode}' via /api/change-passcode...")
    change_res = client.post("/api/change-passcode", json={
        "current_passcode": passcode,
        "new_passcode": new_passcode,
        "confirm_passcode": new_passcode
    })
    assert change_res.status_code == 200, f"Change passcode failed: {change_res.get_json()}"
    assert change_res.get_json().get("success") is True
    print(f"  ✓ Passcode successfully changed to '{new_passcode}'.")

    # Logout to test authentication with old and new passcodes
    client.get("/api/logout")

    # -------------------------------------------------------------------------
    # STEP 6: Old Passcode Rejection & DEAD Trap State
    # -------------------------------------------------------------------------
    print("\n[STEP 6] Testing Old Passcode Rejection by DFA...")
    old_res = client.post("/api/login", json={"username": username, "passcode": passcode})
    assert old_res.status_code == 200, f"Unexpected status: {old_res.status_code}"
    old_data = old_res.get_json()
    assert old_data.get("is_accepted") is False, "Old passcode should be rejected"
    assert old_data.get("final_state") == "DEAD", f"Expected DEAD state, got {old_data.get('final_state')}"
    assert old_data.get("status") == "ACCESS DENIED"
    print(f"  ✓ Old passcode '{passcode}' rejected: Final State = DEAD [ACCESS DENIED]")

    # -------------------------------------------------------------------------
    # STEP 7: Input Validation Rules
    # -------------------------------------------------------------------------
    print("\n[STEP 7] Testing Input Validation Constraints...")
    # Spaces not allowed
    v_space = client.post("/api/login", json={"username": username, "passcode": "9 #W"})
    assert v_space.status_code == 400
    # Length < 4
    v_short = client.post("/api/login", json={"username": username, "passcode": "9#W"})
    assert v_short.status_code == 400
    # Length > 4
    v_long = client.post("/api/login", json={"username": username, "passcode": "9#W21"})
    assert v_long.status_code == 400
    # Invalid symbol outside alphabet
    v_sym = client.post("/api/login", json={"username": username, "passcode": "9#W~"})
    assert v_sym.status_code == 400
    print("  ✓ Server input validation successfully rejected spaces, non-4 lengths, and disallowed characters.")

    # -------------------------------------------------------------------------
    # STEP 8 & 9: Consecutive Failed Attempts Tracking & Lockout (5th failure)
    # -------------------------------------------------------------------------
    print("\n[STEP 8 & 9] Testing Consecutive Failed Attempts & Account Lockout...")
    # Currently 1 failed attempt (from step 6). We perform 3 more failed attempts (total 4).
    for attempt in range(2, 5):
        f_res = client.post("/api/login", json={"username": username, "passcode": "0000"})
        f_data = f_res.get_json()
        assert f_data.get("failed_attempts") == attempt
        assert f_data.get("is_locked") is False
    print("  ✓ 4 consecutive failures tracked correctly without lock.")

    # 5th failed attempt triggers account lock
    f5_res = client.post("/api/login", json={"username": username, "passcode": "0000"})
    f5_data = f5_res.get_json()
    assert f5_data.get("failed_attempts") == 5
    assert f5_data.get("is_locked") is True
    assert f5_data.get("status") == "ACCOUNT LOCKED"
    assert f5_data.get("lockout_remaining") > 0
    print(f"  ✓ 5th consecutive failure locked account: Remaining = {f5_data.get('lockout_remaining')}s [ACCOUNT LOCKED]")

    # -------------------------------------------------------------------------
    # STEP 10: Active Lockout Enforcement (HTTP 403)
    # -------------------------------------------------------------------------
    print("\n[STEP 10] Testing Active Lockout Enforcement...")
    locked_res = client.post("/api/login", json={"username": username, "passcode": new_passcode})
    assert locked_res.status_code == 403, f"Expected 403 Forbidden, got {locked_res.status_code}"
    assert locked_res.get_json().get("is_locked") is True
    print("  ✓ Immediate subsequent login attempts blocked with HTTP 403 Forbidden while locked.")

    # -------------------------------------------------------------------------
    # STEP 11: Lockout Expiration & Automatic Unlock
    # -------------------------------------------------------------------------
    print("\n[STEP 11] Fast-forwarding Lockout Expiration & Authenticating...")
    past_time = (datetime.now() - timedelta(seconds=10)).strftime("%Y-%m-%d %H:%M:%S")
    conn = db.get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET locked_until = ? WHERE username = ?", (past_time, username))
        conn.commit()
    finally:
        conn.close()

    # Now login with the correct new passcode
    unlock_res = client.post("/api/login", json={"username": username, "passcode": new_passcode})
    assert unlock_res.status_code == 200, f"Unlock login failed: {unlock_res.get_json()}"
    unlock_data = unlock_res.get_json()
    assert unlock_data.get("is_accepted") is True
    assert unlock_data.get("final_state") == "q4"
    assert unlock_data.get("status") == "ACCESS GRANTED"

    # Verify user record has failed_attempts reset to 0
    user_rec = db.get_user_by_username(username)
    assert user_rec["failed_attempts"] == 0
    is_locked, _ = db.check_user_lockout(user_rec)
    assert is_locked is False
    print("  ✓ Account automatically unlocked on valid authentication; failed attempts reset to 0.")

    # -------------------------------------------------------------------------
    # STEP 12: Independent DFA Playground Custom Simulation
    # -------------------------------------------------------------------------
    print("\n[STEP 12] Testing DFA Playground Custom Simulation Engine...")
    custom_dfa = {
        "states": ["A", "B", "C"],
        "alphabet": ["0", "1"],
        "start_state": "A",
        "accept_states": ["C"],
        "transitions": [
            {"from": "A", "symbol": "0", "to": "A"},
            {"from": "A", "symbol": "1", "to": "B"},
            {"from": "B", "symbol": "0", "to": "A"},
            {"from": "B", "symbol": "1", "to": "C"},
            {"from": "C", "symbol": "0", "to": "C"},
            {"from": "C", "symbol": "1", "to": "C"}
        ],
        "input_string": "011"
    }
    sim_res = client.post("/api/custom-dfa/simulate", json=custom_dfa)
    assert sim_res.status_code == 200, f"Playground simulation failed: {sim_res.get_json()}"
    sim_data = sim_res.get_json()
    assert sim_data.get("is_accepted") is True
    assert sim_data.get("final_state") == "C"
    assert len(sim_data.get("transitions", [])) == 3
    print(f"  ✓ Custom DFA Simulation verified: String '011' ➔ State Path {' ➔ '.join(sim_data.get('state_path', []))} [ACCEPTED]")

    # -------------------------------------------------------------------------
    # STEP 13: Session Termination / Logout & Security
    # -------------------------------------------------------------------------
    print("\n[STEP 13] Testing Session Termination / Logout...")
    logout_res = client.get("/api/logout")
    assert logout_res.status_code == 200
    # Verify protected endpoints are rejected
    post_dash = client.get("/dashboard")
    assert post_dash.status_code == 401
    post_stats = client.get("/api/dashboard-stats")
    assert post_stats.status_code == 401
    print("  ✓ User logged out. Protected resources return 401 Unauthorized.")

    # -------------------------------------------------------------------------
    # STEP 14: Theme & Development Cleanup Verification
    # -------------------------------------------------------------------------
    print("\n[STEP 14] Verifying Black + Gold Theme & Absence of Hardcoded Dev Passcodes...")
    index_res = client.get("/")
    index_html = index_res.get_data(as_text=True)
    assert "Passcode: 3412" not in index_html, "Found hardcoded 'Passcode: 3412' in index"
    assert "Default: 3412" not in index_html, "Found hardcoded 'Default: 3412' in index"

    css_res = client.get("/static/css/style.css")
    css_content = css_res.get_data(as_text=True)
    assert ".state-node.accept-node" in css_content, "Missing accept-node styling"
    assert ".state-node.dead-node" in css_content, "Missing dead-node styling"
    css_res.close()
    print("  ✓ Confirmed distinct DFA node styles (accept-node, dead-node) and clean user-facing UI.")

    print("\n" + "=" * 75)
    print("  ALL 14 PHASE 8 VERIFICATION STEPS PASSED SUCCESSFULLY!")
    print("=" * 75)
    return True


if __name__ == "__main__":
    success = run_phase8_verification()
    sys.exit(0 if success else 1)
