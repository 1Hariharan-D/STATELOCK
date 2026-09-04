"""
StateLock - Automated Test Suite
Validates DFA engine transition logic, acceptance criteria, and API endpoints for passcode 3412.
"""

import unittest
from dfa_engine import DFAEngine
from app import app


class TestDFAEngine(unittest.TestCase):
    def setUp(self):
        self.dfa = DFAEngine(target_sequence="3412")

    def test_accepted_sequence_3412(self):
        """Test sequence '3412' -> ACCEPT (final state q4, path q0->q1->q2->q3->q4)."""
        res = self.dfa.process_sequence("3412")
        self.assertTrue(res["is_accepted"])
        self.assertEqual(res["status"], "ACCESS GRANTED")
        self.assertEqual(res["final_state"], "q4")
        self.assertEqual(res["state_path"], ["q0", "q1", "q2", "q3", "q4"])
        self.assertEqual(len(res["transitions"]), 4)
        self.assertEqual(res["transitions"][0], {"step": 1, "from_state": "q0", "symbol": "3", "to_state": "q1", "is_valid": True})
        self.assertEqual(res["transitions"][1], {"step": 2, "from_state": "q1", "symbol": "4", "to_state": "q2", "is_valid": True})
        self.assertEqual(res["transitions"][2], {"step": 3, "from_state": "q2", "symbol": "1", "to_state": "q3", "is_valid": True})
        self.assertEqual(res["transitions"][3], {"step": 4, "from_state": "q3", "symbol": "2", "to_state": "q4", "is_valid": True})

    def test_rejected_sequence_3419(self):
        """Test sequence '3419' -> REJECT (error at 4th symbol '9')."""
        res = self.dfa.process_sequence("3419")
        self.assertFalse(res["is_accepted"])
        self.assertEqual(res["status"], "ACCESS DENIED")
        self.assertEqual(res["final_state"], "DEAD")
        self.assertEqual(res["state_path"], ["q0", "q1", "q2", "q3", "DEAD"])
        self.assertFalse(res["transitions"][3]["is_valid"])

    def test_rejected_sequence_3492(self):
        """Test sequence '3492' -> REJECT (error at 3rd symbol '9')."""
        res = self.dfa.process_sequence("3492")
        self.assertFalse(res["is_accepted"])
        self.assertEqual(res["status"], "ACCESS DENIED")
        self.assertEqual(res["final_state"], "DEAD")
        self.assertEqual(res["state_path"], ["q0", "q1", "q2", "DEAD", "DEAD"])

    def test_rejected_sequence_1234(self):
        """Test sequence '1234' -> REJECT (error at 1st symbol '1')."""
        res = self.dfa.process_sequence("1234")
        self.assertFalse(res["is_accepted"])
        self.assertEqual(res["status"], "ACCESS DENIED")
        self.assertEqual(res["final_state"], "DEAD")
        self.assertEqual(res["state_path"], ["q0", "DEAD", "DEAD", "DEAD", "DEAD"])

    def test_empty_sequence(self):
        """Test empty string validation."""
        res = self.dfa.process_sequence("")
        self.assertFalse(res["is_accepted"])
        self.assertEqual(res["status"], "ACCESS DENIED")
        self.assertFalse(res["success"])

    def test_none_sequence(self):
        """Test None input validation."""
        res = self.dfa.process_sequence(None)
        self.assertFalse(res["is_accepted"])
        self.assertFalse(res["success"])

    def test_prefix_partial_sequence(self):
        """Test incomplete sequence '341' -> REJECT (stops at q3)."""
        res = self.dfa.process_sequence("341")
        self.assertFalse(res["is_accepted"])
        self.assertEqual(res["final_state"], "q3")
        self.assertEqual(res["state_path"], ["q0", "q1", "q2", "q3"])

    def test_extended_sequence(self):
        """Test longer sequence '34120' -> REJECT (extra symbol transitions to DEAD)."""
        res = self.dfa.process_sequence("34120")
        self.assertFalse(res["is_accepted"])
        self.assertEqual(res["final_state"], "DEAD")

    def test_alphanumeric_special_sequence(self):
        """Test alphanumeric and special characters allowed in input alphabet ('A@12' -> REJECT)."""
        res = self.dfa.process_sequence("A@12")
        self.assertFalse(res["is_accepted"])
        self.assertEqual(res["final_state"], "DEAD")
        self.assertEqual(res["state_path"], ["q0", "DEAD", "DEAD", "DEAD", "DEAD"])


class TestFlaskAPI(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_index_route(self):
        """Test GET / returns 200."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_api_verify_accepted(self):
        """Test POST /api/verify with sequence 3412."""
        response = self.client.post("/api/verify", json={"sequence": "3412"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["is_accepted"])
        self.assertEqual(data["status"], "ACCESS GRANTED")
        self.assertEqual(data["final_state"], "q4")

    def test_api_verify_rejected(self):
        """Test POST /api/verify with sequence 3419."""
        response = self.client.post("/api/verify", json={"sequence": "3419"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertFalse(data["is_accepted"])
        self.assertEqual(data["status"], "ACCESS DENIED")
        self.assertEqual(data["final_state"], "DEAD")

    def test_api_verify_empty(self):
        """Test POST /api/verify with empty sequence."""
        response = self.client.post("/api/verify", json={"sequence": ""})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertFalse(data["is_accepted"])


if __name__ == "__main__":
    unittest.main()
