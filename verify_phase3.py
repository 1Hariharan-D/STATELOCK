"""
StateLock - Phase 3 Character-by-Character Live Verification Suite
Tests that ANY 4-character input is processed symbol-by-symbol through the DFA,
verifying each character transition, acceptance at q4, rejection at DEAD,
history transition persistence, and passcode changes on the live server.
"""

import urllib.request
import urllib.parse
import http.cookiejar
import json
import sqlite3
import os
import time

BASE_URL = "http://127.0.0.1:5000"
DB_PATH = os.path.join(os.path.dirname(__file__), "statelock.db")

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def post_json(endpoint, data):
    url = f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with opener.open(req) as res:
            return res.status, json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def get_json(endpoint):
    url = f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(url)
    try:
        with opener.open(req) as res:
            return res.status, json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def main():
    print("--- Starting StateLock Phase 3 Character-by-Character Live Verification ---")

    # Step 1: Check GET /
    with opener.open(f"{BASE_URL}/") as res:
        assert res.status == 200
        html = res.read().decode("utf-8")
        assert "history-replay-banner" in html
        assert "history-table" in html
        print("[PASS] Step 1: GET / loaded with Phase 3 UI, history replay banner, and DFA controls.")

    username = f"user_dfa_{int(time.time())}"
    passcode = "A7@2"

    # Step 2: Register user with passcode A7@2
    status, reg_data = post_json("/api/register", {
        "username": username,
        "passcode": passcode
    })
    assert status == 201
    assert reg_data["success"] is True
    print(f"[PASS] Step 2: Registered user '{username}' with passcode '{passcode}'.")

    # Step 3: Duplicate username rejection
    status, dup_data = post_json("/api/register", {
        "username": username,
        "passcode": "9999"
    })
    assert status == 400
    assert dup_data["error"] == "Username already exists. Please choose another username."
    print("[PASS] Step 3: Duplicate username rejected with exact error message.")

    # Step 4: Login with exact match 'A7@2' -> q0 -A-> q1 -7-> q2 -@-> q3 -2-> q4 (ACCEPT)
    status, res_match = post_json("/api/login", {
        "username": username,
        "passcode": "A7@2"
    })
    assert status == 200
    assert res_match["is_accepted"] is True
    assert res_match["final_state"] == "q4"
    assert res_match["status"] == "ACCESS GRANTED"
    assert res_match["state_path"] == ["q0", "q1", "q2", "q3", "q4"]
    assert len(res_match["transitions"]) == 4
    assert res_match["transitions"][0]["to_state"] == "q1"
    assert res_match["transitions"][1]["to_state"] == "q2"
    assert res_match["transitions"][2]["to_state"] == "q3"
    assert res_match["transitions"][3]["to_state"] == "q4"
    print("[PASS] Step 4: Input 'A7@2' -> q0 -A-> q1 -7-> q2 -@-> q3 -2-> q4 -> ACCEPT (q4).")

    # Step 5: Login with mismatch at 3rd symbol 'A7#9' -> q0 -A-> q1 -7-> q2 -#-> DEAD -9-> DEAD (REJECT)
    status, res_mismatch3 = post_json("/api/login", {
        "username": username,
        "passcode": "A7#9"
    })
    assert status == 200
    assert res_mismatch3["is_accepted"] is False
    assert res_mismatch3["final_state"] == "DEAD"
    assert res_mismatch3["state_path"] == ["q0", "q1", "q2", "DEAD", "DEAD"]
    assert len(res_mismatch3["transitions"]) == 4
    assert res_mismatch3["transitions"][0]["to_state"] == "q1"
    assert res_mismatch3["transitions"][1]["to_state"] == "q2"
    assert res_mismatch3["transitions"][2]["to_state"] == "DEAD"
    assert res_mismatch3["transitions"][3]["to_state"] == "DEAD"
    print("[PASS] Step 5: Input 'A7#9' -> q0 -A-> q1 -7-> q2 -#-> DEAD -9-> DEAD -> REJECT (DEAD).")

    # Step 6: Login with mismatch at 1st symbol 'X7@2' -> q0 -X-> DEAD -7-> DEAD -@-> DEAD -2-> DEAD (REJECT)
    status, res_mismatch1 = post_json("/api/login", {
        "username": username,
        "passcode": "X7@2"
    })
    assert status == 200
    assert res_mismatch1["is_accepted"] is False
    assert res_mismatch1["final_state"] == "DEAD"
    assert res_mismatch1["state_path"] == ["q0", "DEAD", "DEAD", "DEAD", "DEAD"]
    assert len(res_mismatch1["transitions"]) == 4
    assert all(t["to_state"] == "DEAD" for t in res_mismatch1["transitions"])
    print("[PASS] Step 6: Input 'X7@2' -> q0 -X-> DEAD -7-> DEAD -@-> DEAD -2-> DEAD -> REJECT (DEAD).")

    # Step 7: Change passcode A7@2 -> B#3k
    status, change_res = post_json("/api/change-passcode", {
        "current_passcode": "A7@2",
        "new_passcode": "B#3k",
        "confirm_passcode": "B#3k"
    })
    assert status == 200
    assert change_res["success"] is True
    print("[PASS] Step 7: Successfully updated passcode to 'B#3k'.")

    # Step 8: Login with new passcode B#3k -> ACCEPT (q4)
    status, login_new = post_json("/api/login", {
        "username": username,
        "passcode": "B#3k"
    })
    assert status == 200
    assert login_new["is_accepted"] is True
    assert login_new["final_state"] == "q4"
    assert login_new["state_path"] == ["q0", "q1", "q2", "q3", "q4"]
    print("[PASS] Step 8: Login with new passcode 'B#3k' -> ACCESS GRANTED (final_state=q4).")

    # Step 9: Check History records contain exact transition logs and inputs
    status, hist_data = get_json("/api/history")
    assert status == 200
    assert hist_data["success"] is True
    assert len(hist_data["history"]) >= 4
    
    for rec in hist_data["history"]:
        assert "input_sequence" in rec
        assert "final_state" in rec
        assert "transitions" in rec
        assert len(rec["transitions"]) == 4
    print("[PASS] Step 9: History verified: contains full 4-step transition logs for each attempt.")

    # Step 10: Verify no plaintext passcodes in DB
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, passcode_encrypted FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    assert row is not None
    assert row["password_hash"] != "B#3k"
    assert row["password_hash"] != "A7@2"
    assert row["passcode_encrypted"] != "B#3k"
    conn.close()
    print("[PASS] Step 10: Verified database contains no plaintext passcodes.")

    # Step 11: Logout
    status, logout_res = post_json("/api/logout", {})
    assert status == 200
    status, sess = get_json("/api/user-status")
    assert sess["logged_in"] is False
    print("[PASS] Step 11: Logout verified, session destroyed.")

    print("\n[SUCCESS] ALL CHARACTER-BY-CHARACTER PHASE 3 TESTS PASSED PERFECTLY!")


if __name__ == "__main__":
    main()
