"""
StateLock - Phase 3 Character-by-Character DFA Test Suite
Validates that ANY 4-character input is processed symbol-by-symbol through the DFA,
generating the complete 4-step transition log, determining acceptance strictly from the
final DFA state, and logging detailed history.
"""

import unittest
import os
import tempfile
from dfa_engine import DFAEngine
import database as db
from app import app


class TestCharacterByCharacterDFA(unittest.TestCase):
    """Validates symbol-by-symbol DFA execution for various sequences."""

    def test_example_1_exact_match(self):
        """Target 'A7@2' with Input 'A7@2' -> q0 -A-> q1 -7-> q2 -@-> q3 -2-> q4 (ACCEPT)."""
        dfa = DFAEngine(target_sequence="A7@2")
        res = dfa.process_sequence("A7@2")

        self.assertTrue(res["is_accepted"])
        self.assertEqual(res["final_state"], "q4")
        self.assertEqual(res["status"], "ACCESS GRANTED")
        self.assertEqual(res["state_path"], ["q0", "q1", "q2", "q3", "q4"])
        self.assertEqual(len(res["transitions"]), 4)

        # Step 1: q0 --A--> q1 (valid)
        self.assertEqual(res["transitions"][0], {"step": 1, "from_state": "q0", "symbol": "A", "to_state": "q1", "is_valid": True})
        # Step 2: q1 --7--> q2 (valid)
        self.assertEqual(res["transitions"][1], {"step": 2, "from_state": "q1", "symbol": "7", "to_state": "q2", "is_valid": True})
        # Step 3: q2 --@--> q3 (valid)
        self.assertEqual(res["transitions"][2], {"step": 3, "from_state": "q2", "symbol": "@", "to_state": "q3", "is_valid": True})
        # Step 4: q3 --2--> q4 (valid)
        self.assertEqual(res["transitions"][3], {"step": 4, "from_state": "q3", "symbol": "2", "to_state": "q4", "is_valid": True})

    def test_example_2_mismatch_at_step_3(self):
        """Target 'A7@2' with Input 'A7#9' -> q0 -A-> q1 -7-> q2 -#-> DEAD -9-> DEAD (REJECT)."""
        dfa = DFAEngine(target_sequence="A7@2")
        res = dfa.process_sequence("A7#9")

        self.assertFalse(res["is_accepted"])
        self.assertEqual(res["final_state"], "DEAD")
        self.assertEqual(res["status"], "ACCESS DENIED")
        self.assertEqual(res["state_path"], ["q0", "q1", "q2", "DEAD", "DEAD"])
        self.assertEqual(len(res["transitions"]), 4)

        # Step 1: q0 --A--> q1 (valid)
        self.assertTrue(res["transitions"][0]["is_valid"])
        self.assertEqual(res["transitions"][0]["to_state"], "q1")

        # Step 2: q1 --7--> q2 (valid)
        self.assertTrue(res["transitions"][1]["is_valid"])
        self.assertEqual(res["transitions"][1]["to_state"], "q2")

        # Step 3: q2 --#--> DEAD (invalid)
        self.assertFalse(res["transitions"][2]["is_valid"])
        self.assertEqual(res["transitions"][2]["to_state"], "DEAD")

        # Step 4: DEAD --9--> DEAD (invalid self-loop)
        self.assertFalse(res["transitions"][3]["is_valid"])
        self.assertEqual(res["transitions"][3]["from_state"], "DEAD")
        self.assertEqual(res["transitions"][3]["to_state"], "DEAD")

    def test_example_3_mismatch_at_step_1(self):
        """Target 'A7@2' with Input 'X7@2' -> q0 -X-> DEAD -7-> DEAD -@-> DEAD -2-> DEAD (REJECT)."""
        dfa = DFAEngine(target_sequence="A7@2")
        res = dfa.process_sequence("X7@2")

        self.assertFalse(res["is_accepted"])
        self.assertEqual(res["final_state"], "DEAD")
        self.assertEqual(res["status"], "ACCESS DENIED")
        self.assertEqual(res["state_path"], ["q0", "DEAD", "DEAD", "DEAD", "DEAD"])
        self.assertEqual(len(res["transitions"]), 4)

        # All 4 steps must be present in the transition log
        for idx, tr in enumerate(res["transitions"]):
            self.assertEqual(tr["step"], idx + 1)
            self.assertFalse(tr["is_valid"])
            self.assertEqual(tr["to_state"], "DEAD")

    def test_arbitrary_random_inputs(self):
        """Validates arbitrary 4-character passcodes with numbers, letters, and special symbols."""
        test_cases = [
            ("9*Z!", "9*Z!", True, "q4"),
            ("9*Z!", "9*Z?", False, "DEAD"),
            ("B#3k", "B#3k", True, "q4"),
            ("B#3k", "B#1k", False, "DEAD"),
            ("w9@1", "w9@1", True, "q4"),
            ("w9@1", "1234", False, "DEAD"),
        ]

        for target, test_input, expected_acc, expected_final in test_cases:
            dfa = DFAEngine(target_sequence=target)
            res = dfa.process_sequence(test_input)
            self.assertEqual(res["is_accepted"], expected_acc)
            self.assertEqual(res["final_state"], expected_final)
            self.assertEqual(len(res["transitions"]), 4)


class TestDatabaseAndHistory(unittest.TestCase):
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

    def test_user_registration_and_unique_constraint(self):
        """Test registration and duplicate rejection message."""
        ok1, _, _ = db.register_user("hariharan", "2311", self.temp_db_path)
        self.assertTrue(ok1)

        ok2, err2, _ = db.register_user("hariharan", "5678", self.temp_db_path)
        self.assertFalse(ok2)
        self.assertEqual(err2, "Username already exists. Please choose another username.")

    def test_passcode_change_and_target_retrieval(self):
        """Test changing passcode and retrieving updated encrypted target sequence."""
        _, _, user_id = db.register_user("alice_p3", "2311", self.temp_db_path)
        user = db.get_user_by_id(user_id, self.temp_db_path)
        self.assertEqual(db.get_user_target_sequence(user), "2311")

        # Change passcode to A7@2
        ok, _ = db.update_user_passcode(user_id, "2311", "A7@2", "A7@2", self.temp_db_path)
        self.assertTrue(ok)

        # Verify updated target
        updated_user = db.get_user_by_id(user_id, self.temp_db_path)
        self.assertEqual(db.get_user_target_sequence(updated_user), "A7@2")

    def test_history_logging_with_full_transitions(self):
        """Test logging and retrieving detailed transition logs in history."""
        _, _, user_id = db.register_user("bob_p3", "A7@2", self.temp_db_path)
        
        dfa = DFAEngine(target_sequence="A7@2")
        res = dfa.process_sequence("A7#9")

        db.log_auth_attempt(
            user_id=user_id,
            username="bob_p3",
            input_sequence="A7#9",
            is_success=res["is_accepted"],
            final_state=res["final_state"],
            state_path=res["state_path"],
            transitions=res["transitions"],
            db_path=self.temp_db_path
        )

        history = db.get_user_history(user_id=user_id, db_path=self.temp_db_path)
        self.assertEqual(len(history), 1)
        record = history[0]
        self.assertEqual(record["input_sequence"], "A7#9")
        self.assertEqual(record["status"], "ACCESS DENIED")
        self.assertEqual(record["final_state"], "DEAD")
        self.assertEqual(len(record["transitions"]), 4)
        self.assertEqual(record["transitions"][2]["symbol"], "#")
        self.assertEqual(record["transitions"][2]["to_state"], "DEAD")


class TestFlaskAPIPhase3(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db_path = self.temp_file.name
        self.temp_file.close()
        db.init_db(self.temp_db_path)

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

    def test_full_user_lifecycle_with_transitions(self):
        """
        Tests the user's complete requested scenario:
        1. Register hariharan + 2311 -> Account created
        2. Register hariharan again + 5678 -> "Username already exists. Please choose another username."
        3. Login hariharan + 2311 -> Access Granted (final_state=q4, all 4 transitions valid)
        4. Login hariharan + 2319 -> Access Denied (final_state=DEAD, 4 transitions with step 4 DEAD)
        5. Change passcode 2311 -> A7@2 -> Success
        6. Login with A7@2 -> Access Granted (final_state=q4)
        7. Fetch history -> Contains detailed records with input sequences & transition logs
        """
        username = "hariharan_phase3_e2e"
        passcode_1 = "2311"
        passcode_2 = "A7@2"

        # 1. Register
        reg_res = self.client.post("/api/register", json={"username": username, "passcode": passcode_1})
        self.assertIn(reg_res.status_code, [201, 400])

        # 2. Duplicate username error
        dup_res = self.client.post("/api/register", json={"username": username, "passcode": "5678"})
        self.assertEqual(dup_res.status_code, 400)
        self.assertEqual(dup_res.get_json()["error"], "Username already exists. Please choose another username.")

        # 3. Login with correct passcode 2311
        login_1 = self.client.post("/api/login", json={"username": username, "passcode": passcode_1})
        self.assertEqual(login_1.status_code, 200)
        data_1 = login_1.get_json()
        self.assertTrue(data_1["is_accepted"])
        self.assertEqual(data_1["final_state"], "q4")
        self.assertEqual(len(data_1["transitions"]), 4)
        self.assertTrue(all(t["is_valid"] for t in data_1["transitions"]))

        # 4. Login with wrong passcode 2319 (error at 4th char)
        login_wrong = self.client.post("/api/login", json={"username": username, "passcode": "2319"})
        self.assertEqual(login_wrong.status_code, 200)
        data_wrong = login_wrong.get_json()
        self.assertFalse(data_wrong["is_accepted"])
        self.assertEqual(data_wrong["final_state"], "DEAD")
        self.assertEqual(len(data_wrong["transitions"]), 4)
        self.assertFalse(data_wrong["transitions"][3]["is_valid"])

        # 5. Change passcode 2311 -> A7@2
        change_res = self.client.post("/api/change-passcode", json={
            "current_passcode": passcode_1,
            "new_passcode": passcode_2,
            "confirm_passcode": passcode_2
        })
        self.assertEqual(change_res.status_code, 200)
        self.assertTrue(change_res.get_json()["success"])

        # 6. Login with new passcode A7@2
        login_2 = self.client.post("/api/login", json={"username": username, "passcode": passcode_2})
        self.assertEqual(login_2.status_code, 200)
        data_2 = login_2.get_json()
        self.assertTrue(data_2["is_accepted"])
        self.assertEqual(data_2["final_state"], "q4")

        # 7. Check History
        hist_res = self.client.get("/api/history")
        self.assertEqual(hist_res.status_code, 200)
        hist_data = hist_res.get_json()
        self.assertTrue(hist_data["success"])
        self.assertTrue(len(hist_data["history"]) >= 3)
        # Verify history includes transitions
        for record in hist_data["history"]:
            self.assertIn("transitions", record)
            self.assertIn("input_sequence", record)


if __name__ == "__main__":
    unittest.main()
