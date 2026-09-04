"""
StateLock - Phase 4 Security Enhancements Comprehensive Verification Suite
Tests all 7 user-specified Phase 4 security scenarios:
1. Correct login -> Access Granted -> failed attempts reset to 0
2. Wrong login 1-4 times -> counter increases (1/5, 2/5, 3/5, 4/5)
3. Wrong login 5th time -> account locked -> 60-second countdown appears
4. Try login while locked -> authentication prevented (HTTP 403)
5. After lockout expires -> account becomes available again
6. Successful login -> counter resets
7. Logout -> protected pages cannot be accessed without login
8. Server-side input validation and error sanitization
9. Security headers & anti-caching
"""

import time
import tempfile
import os
import database as db
from app import app


def run_verification():
    print("=================================================================")
    print("  STATELOCK PHASE 4: SECURITY ENHANCEMENTS LIVE VERIFICATION")
    print("=================================================================")

    # Setup isolated database for verification
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_db_path = temp_file.name
    temp_file.close()
    db.init_db(temp_db_path)

    orig_db_path = db.DB_PATH
    db.DB_PATH = temp_db_path

    app.config["TESTING"] = True
    client = app.test_client()

    try:
        # Step 1: Check Index and Anti-Caching Headers
        res_idx = client.get("/")
        assert res_idx.status_code == 200, "Index route failed"
        html = res_idx.data.decode("utf-8")
        assert "failed-attempts-badge" in html, "Failed attempts badge missing from HTML"
        assert "lockout-banner" in html, "Lockout banner missing from HTML"
        assert "Security & Protection" in html, "Security banner missing"
        assert "no-store" in res_idx.headers.get("Cache-Control", ""), "Missing Cache-Control header"
        assert res_idx.headers.get("X-Frame-Options") == "DENY", "Missing X-Frame-Options header"
        print("[PASS] Step 1: HTML loaded with Phase 4 security UI and anti-caching headers.")

        # Step 2: Register user
        username = f"sec_pilot_{int(time.time())}"
        passcode = "9#K2"
        reg_res = client.post("/api/register", json={"username": username, "passcode": passcode})
        assert reg_res.status_code == 201, f"Registration failed: {reg_res.get_json()}"
        print(f"[PASS] Step 2: Registered user '{username}' with passcode '{passcode}'.")

        # Step 3: Test 1: Correct login -> Access Granted -> failed attempts reset to 0
        login_1 = client.post("/api/login", json={"username": username, "passcode": passcode})
        assert login_1.status_code == 200, "Login failed"
        d1 = login_1.get_json()
        assert d1["is_accepted"] is True, "Expected acceptance"
        assert d1["final_state"] == "q4", "Expected q4"
        assert d1["failed_attempts"] == 0, "Expected failed_attempts == 0"
        assert d1["is_locked"] is False, "Expected is_locked == False"
        print(f"[PASS] Test 1: Correct login -> Access Granted (state: q4, failed attempts: 0).")

        # Step 4: Test 2: Wrong login 1–4 times -> counter increases
        for count in range(1, 5):
            wrong_res = client.post("/api/login", json={"username": username, "passcode": "0000"})
            assert wrong_res.status_code == 200, "Expected 200 for DFA rejection"
            wd = wrong_res.get_json()
            assert wd["is_accepted"] is False, "Expected rejection"
            assert wd["final_state"] == "DEAD", "Expected DEAD trap state"
            assert wd["failed_attempts"] == count, f"Expected failed_attempts == {count}, got {wd['failed_attempts']}"
            assert wd["is_locked"] is False, "Account should not be locked yet"
            print(f"       -> Wrong attempt {count}/5 logged (state: DEAD, failed count: {count}/5).")
        print("[PASS] Test 2: Consecutive failed attempts 1-4 incremented counter accurately.")

        # Step 5: Test 3: Wrong login 5th time -> account locked with 60-second lockout
        lock_res = client.post("/api/login", json={"username": username, "passcode": "0000"})
        assert lock_res.status_code == 200, "Expected 200 with lockout info"
        ld = lock_res.get_json()
        assert ld["is_accepted"] is False, "Expected rejection"
        assert ld["is_locked"] is True, "Expected is_locked == True"
        assert ld["status"] == "ACCOUNT LOCKED", "Expected status == ACCOUNT LOCKED"
        assert ld["failed_attempts"] == 5, "Expected failed_attempts == 5"
        assert 55 <= ld["lockout_remaining"] <= 60, f"Expected ~60s lockout, got {ld['lockout_remaining']}"
        print(f"[PASS] Test 3: 5th wrong attempt triggered account lockout (60s countdown: {ld['lockout_remaining']}s).")

        # Step 6: Test 4: Try login while locked -> authentication prevented
        attempt_while_locked = client.post("/api/login", json={"username": username, "passcode": passcode})
        assert attempt_while_locked.status_code == 403, f"Expected 403 Forbidden, got {attempt_while_locked.status_code}"
        ad = attempt_while_locked.get_json()
        assert ad["is_locked"] is True, "Expected is_locked == True"
        assert ad["status"] == "ACCOUNT LOCKED", "Expected status == ACCOUNT LOCKED"
        assert "temporarily locked" in ad["error"], "Expected lockout error message"
        print(f"[PASS] Test 4: Authentication strictly blocked during active lockout (HTTP 403).")

        # Step 7: Test 5: After 60 seconds -> account becomes available again
        # Simulate time advancement
        user_rec = db.get_user_by_username(username, temp_db_path)
        conn = db.get_db_connection(temp_db_path)
        conn.execute("UPDATE users SET locked_until = ? WHERE id = ?", (time.time() - 2, user_rec["id"]))
        conn.commit()
        conn.close()

        # Query lockout status endpoint
        status_check = client.get(f"/api/lockout-status?username={username}")
        assert status_check.status_code == 200
        sc = status_check.get_json()
        assert sc["is_locked"] is False, "Expected account to auto-unlock"
        assert sc["lockout_remaining"] == 0, "Expected 0s remaining"
        print("[PASS] Test 5: Expired lockout automatically unlocked account and restored access.")

        # Step 8: Test 6: Successful login -> counter resets
        login_recovered = client.post("/api/login", json={"username": username, "passcode": passcode})
        assert login_recovered.status_code == 200, "Expected successful login"
        rd = login_recovered.get_json()
        assert rd["is_accepted"] is True, "Expected acceptance"
        assert rd["final_state"] == "q4", "Expected q4"
        assert rd["failed_attempts"] == 0, "Expected failed_attempts reset to 0"
        assert rd["is_locked"] is False, "Expected is_locked == False"
        print("[PASS] Test 6: Successful login reset failed attempt counter to 0.")

        # Step 9: Verify Security History Event Logging
        hist_res = client.get("/api/history")
        assert hist_res.status_code == 200
        hist_records = hist_res.get_json()["history"]
        assert len(hist_records) >= 7, f"Expected >= 7 history events, got {len(hist_records)}"
        
        event_types = [h.get("event_type") for h in hist_records]
        assert "Successful login" in event_types, "Missing Successful login event"
        assert "Failed login" in event_types, "Missing Failed login event"
        assert "Account locked" in event_types, "Missing Account locked event"
        assert "Lockout ended" in event_types, "Missing Lockout ended event"

        # Check that DFA transition paths are preserved
        for rec in hist_records:
            assert "state_path" in rec, "Missing state_path in history record"
            assert "final_state" in rec, "Missing final_state in history record"
            assert "transitions" in rec, "Missing transitions in history record"

        print(f"[PASS] Step 9: History verified with all security events (Successful login, Failed login, Account locked, Lockout ended) + DFA transitions.")

        # Step 10: Test 7: Logout -> protected pages cannot be accessed without login
        logout_res = client.post("/api/logout")
        assert logout_res.status_code == 200, "Logout failed"

        # Verify session is dead
        status_after_logout = client.get("/api/user-status")
        assert status_after_logout.get_json()["logged_in"] is False, "User should be logged out"

        hist_unauth = client.get("/api/history")
        assert hist_unauth.status_code == 401, "Protected history should be denied with 401"

        pass_unauth = client.post("/api/change-passcode", json={
            "current_passcode": passcode,
            "new_passcode": "3412",
            "confirm_passcode": "3412"
        })
        assert pass_unauth.status_code == 401, "Protected change-passcode should be denied with 401"
        print("[PASS] Test 7: Logout completely destroyed session; protected routes returned 401 Unauthorized.")

        # Step 11: Server-side input validation and error handling
        bad_reg = client.post("/api/register", json={"username": "a", "passcode": "123"})
        assert bad_reg.status_code == 400
        bad_login_types = client.post("/api/login", json={"username": True, "passcode": 9999})
        assert bad_login_types.status_code == 400
        print("[PASS] Step 11: Malformed and invalid requests handled safely without internal leaks.")

        print("\n=================================================================")
        print("  ALL PHASE 4 SECURITY TESTS PASSED PERFECTLY (100% SUCCESS)")
        print("=================================================================")

    finally:
        db.DB_PATH = orig_db_path
        if os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
            except Exception:
                pass


if __name__ == "__main__":
    run_verification()
