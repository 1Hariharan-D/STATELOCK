"""
Verification script for Authentication History feature in StateLock.
Tests the exact 6 user verification steps programmatically against the active Flask application.
"""

import sys
import io
import json

# Ensure stdout uses UTF-8 encoding on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from app import app, db

def run_verification():
    print("=" * 70)
    print("STATELOCK AUTHENTICATION HISTORY VERIFICATION")
    print("=" * 70)

    client = app.test_client()

    # Step 1: Register and login with a test account
    username = "hist_verify_user"
    passcode = "3412"

    print("\n[Step 1] Register & Login with Test Account...")
    client.post("/api/register", json={"username": username, "passcode": passcode})
    login_resp = client.post("/api/login", json={"username": username, "passcode": passcode})
    assert login_resp.status_code == 200, f"Login failed with status {login_resp.status_code}"
    print("✓ Registered and Logged in as 'hist_verify_user'.")

    # Step 2: Perform successful and failed authentications
    print("\n[Step 2] Performing Authentication Attempts...")
    
    # 2a. Successful attempt
    succ_resp = client.post("/api/login", json={"username": username, "passcode": "3412"})
    assert succ_resp.json["is_accepted"] == True
    print("✓ Successful authentication performed (Input: 3412 -> ACCEPTED/q4).")

    # 2b. Failed attempt
    fail_resp = client.post("/api/login", json={"username": username, "passcode": "3535"})
    assert fail_resp.json["is_accepted"] == False
    print("✓ Failed authentication performed (Input: 3535 -> DENIED/DEAD).")

    # Step 3: Open History
    print("\n[Step 3 & 4] Accessing History & Verifying Attempts...")
    hist_route_resp = client.get("/history")
    assert hist_route_resp.status_code == 200, "Protected /history route returned non-200 for logged-in user!"
    assert b"data-open-history" in hist_route_resp.data
    print("✓ Protected /history route rendered with open_history=True flag.")

    api_hist_resp = client.get("/api/history")
    assert api_hist_resp.status_code == 200
    history = api_hist_resp.json.get("history", [])
    print(f"✓ Retrieved {len(history)} history records for '{username}'.")

    # Verify history contents
    found_success = False
    found_failed = False
    for rec in history:
        print(f"  - Record #{rec['id']}: [{rec['timestamp']}] Event='{rec['event_type']}' Input='{rec['input_sequence']}' Status='{rec['status']}' FinalState='{rec['final_state']}' Path='{rec['state_path']}'")
        if rec['input_sequence'] == "3412" and "GRANTED" in rec['status']:
            found_success = True
        if rec['input_sequence'] == "3535" and "DENIED" in rec['status']:
            found_failed = True
            # Verify exact path for 3535
            assert "DEAD" in rec['final_state'] or "DEAD" in rec['state_path']
            assert len(rec['transitions']) > 0

    assert found_success, "Successful attempt '3412' not found in history!"
    assert found_failed, "Failed attempt '3535' not found in history!"
    print("✓ Verified all attempts (SUCCESS and FAILED) appear with correct inputs and states.")

    # Step 5: Verify Details payload structure
    print("\n[Step 5] Verifying 'View Details' Data Payload...")
    sample_rec = history[0]
    assert "transitions" in sample_rec and isinstance(sample_rec["transitions"], list)
    assert "state_path" in sample_rec
    assert "final_state" in sample_rec
    print("✓ DFA transition path and step-by-step transition table data intact.")

    # Step 6: Logout & verify History is inaccessible
    print("\n[Step 6] Logout & Verify History Protection...")
    client.post("/api/logout")
    
    unauth_route_resp = client.get("/history")
    assert unauth_route_resp.status_code == 401
    assert b"data-unauthorized-history" in unauth_route_resp.data
    print("✓ Protected /history route returned 401 Unauthorized for logged-out request.")

    unauth_api_resp = client.get("/api/history")
    assert unauth_api_resp.status_code == 401
    print("✓ /api/history API endpoint returned 401 Unauthorized for logged-out request.")

    print("\n" + "=" * 70)
    print("ALL 6 VERIFICATION STEPS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_verification()
