"""
End-to-End HTTP Verification against the running StateLock Flask server.
"""

import urllib.request
import urllib.parse
import json

BASE_URL = "http://127.0.0.1:5000"

def test_get_index():
    print("Testing GET / ...")
    with urllib.request.urlopen(f"{BASE_URL}/") as res:
        assert res.status == 200
        html = res.read().decode("utf-8")
        assert "StateLock" in html
        assert "Theory of Computation" in html
        assert "3412" in html
        assert "reset-btn" in html
        assert "animation-hud" in html
        assert "anim-play-btn" in html
        assert "anim-step-btn" in html
        assert "dfa-svg" in html
        assert "node-q0" in html
        assert "node-q4" in html
        assert "node-DEAD" in html
        print("[PASS] GET / returned 200 with complete DOM structure and Phase 2 Animation HUD.")

def post_verify(sequence):
    req = urllib.request.Request(
        f"{BASE_URL}/api/verify",
        data=json.dumps({"sequence": sequence}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read().decode("utf-8"))
            return res.status, data
    except urllib.error.HTTPError as e:
        data = json.loads(e.read().decode("utf-8"))
        return e.code, data

def main():
    print("--- Starting StateLock Phase 2 Live Verification ---")
    test_get_index()

    # Test 1: 3412 -> ACCEPT
    status, res = post_verify("3412")
    assert status == 200
    assert res["is_accepted"] is True
    assert res["status"] == "ACCESS GRANTED"
    assert res["final_state"] == "q4"
    assert res["state_path"] == ["q0", "q1", "q2", "q3", "q4"]
    print("[PASS] Test 1: 3412 -> ACCEPT (ACCESS GRANTED, final_state=q4)")

    # Test 2: 3419 -> REJECT
    status, res = post_verify("3419")
    assert status == 200
    assert res["is_accepted"] is False
    assert res["status"] == "ACCESS DENIED"
    assert res["final_state"] == "DEAD"
    assert res["state_path"] == ["q0", "q1", "q2", "q3", "DEAD"]
    print("[PASS] Test 2: 3419 -> REJECT (ACCESS DENIED, final_state=DEAD)")

    # Test 3: 3492 -> REJECT
    status, res = post_verify("3492")
    assert status == 200
    assert res["is_accepted"] is False
    assert res["status"] == "ACCESS DENIED"
    assert res["final_state"] == "DEAD"
    assert res["state_path"] == ["q0", "q1", "q2", "DEAD", "DEAD"]
    print("[PASS] Test 3: 3492 -> REJECT (ACCESS DENIED, final_state=DEAD)")

    # Test 4: 1234 -> REJECT
    status, res = post_verify("1234")
    assert status == 200
    assert res["is_accepted"] is False
    assert res["status"] == "ACCESS DENIED"
    assert res["final_state"] == "DEAD"
    assert res["state_path"] == ["q0", "DEAD", "DEAD", "DEAD", "DEAD"]
    print("[PASS] Test 4: 1234 -> REJECT (ACCESS DENIED, final_state=DEAD)")

    # Test 5: Empty input -> REJECT / Validation Error
    status, res = post_verify("")
    assert status == 400
    assert res["is_accepted"] is False
    assert res["status"] == "ACCESS DENIED"
    print("[PASS] Test 5: Empty input -> REJECT (HTTP 400 with validation message)")

    # Test 6: Alphanumeric & Special character input -> REJECT
    status, res = post_verify("A@12")
    assert status == 200
    assert res["is_accepted"] is False
    assert res["status"] == "ACCESS DENIED"
    assert res["final_state"] == "DEAD"
    print("[PASS] Test 6: A@12 -> REJECT (Alphanumeric/special char handling)")

    # Test 7: Check static assets
    with urllib.request.urlopen(f"{BASE_URL}/static/css/style.css") as res:
        assert res.status == 200
        print("[PASS] Test 7a: Static CSS style.css loaded successfully (200 OK)")

    with urllib.request.urlopen(f"{BASE_URL}/static/js/main.js") as res:
        assert res.status == 200
        print("[PASS] Test 7b: Static JS main.js loaded successfully (200 OK)")

    print("\n[SUCCESS] ALL LIVE SERVER ENDPOINT TESTS PASSED SUCCESSFULLY FOR PHASE 2!")

if __name__ == "__main__":
    main()
