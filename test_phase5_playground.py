"""
StateLock - Phase 5 DFA Playground Test Suite
Tests the CustomDFAEngine and /api/custom-dfa/simulate endpoint.

User-Specified Tutorial DFA:
  States:      q0, q1
  Alphabet:    0, 1
  Start:       q0
  Accept:      q1
  Transitions: δ(q0,0)=q1, δ(q0,1)=q0, δ(q1,0)=q0, δ(q1,1)=q1

Expected string results:
  '0'   -> q0-0->q1            ACCEPTED  (q1)
  '1'   -> q0-1->q0            REJECTED  (q0)
  '01'  -> q0-0->q1-1->q1      ACCEPTED  (q1)
  '10'  -> q0-1->q0-0->q1      ACCEPTED  (q1)
  '011' -> q0-0->q1-1->q1-1->q1 ACCEPTED (q1)
  '101' -> q0-1->q0-0->q1-1->q1 ACCEPTED (q1)
  '110' -> q0-1->q0-1->q0-0->q1 ACCEPTED (q1)
"""

import unittest
import tempfile
import os
import database as db
from app import app
from dfa_engine import CustomDFAEngine


# ─── Shared tutorial DFA 5-tuple ──────────────────────────────────────────────
TUTORIAL_STATES      = ['q0', 'q1']
TUTORIAL_ALPHABET    = ['0', '1']
TUTORIAL_START       = 'q0'
TUTORIAL_ACCEPT      = ['q1']
TUTORIAL_TRANSITIONS = [
    {'from': 'q0', 'symbol': '0', 'to': 'q1'},
    {'from': 'q0', 'symbol': '1', 'to': 'q0'},
    {'from': 'q1', 'symbol': '0', 'to': 'q0'},
    {'from': 'q1', 'symbol': '1', 'to': 'q1'},
]

def make_engine():
    return CustomDFAEngine(
        states=list(TUTORIAL_STATES),
        alphabet=list(TUTORIAL_ALPHABET),
        start_state=TUTORIAL_START,
        accept_states=list(TUTORIAL_ACCEPT),
        transitions=[dict(t) for t in TUTORIAL_TRANSITIONS],
    )

def api_payload(input_string):
    return {
        'states':       list(TUTORIAL_STATES),
        'alphabet':     list(TUTORIAL_ALPHABET),
        'start_state':  TUTORIAL_START,
        'accept_states': list(TUTORIAL_ACCEPT),
        'transitions':  [dict(t) for t in TUTORIAL_TRANSITIONS],
        'input_string': input_string,
    }


class TestCustomDFAEngine(unittest.TestCase):
    """Unit-tests for CustomDFAEngine directly."""

    def setUp(self):
        self.engine = make_engine()

    def test_validation_passes_for_complete_dfa(self):
        v = self.engine.validate()
        self.assertTrue(v['valid'])
        self.assertEqual(v['errors'], [])

    def test_string_0_accepted(self):
        r = self.engine.process_string('0')
        self.assertTrue(r['is_accepted'])
        self.assertEqual(r['final_state'], 'q1')
        self.assertEqual(r['state_path'], ['q0', 'q1'])

    def test_string_1_rejected(self):
        r = self.engine.process_string('1')
        self.assertFalse(r['is_accepted'])
        self.assertEqual(r['final_state'], 'q0')
        self.assertEqual(r['state_path'], ['q0', 'q0'])

    def test_string_01_accepted(self):
        r = self.engine.process_string('01')
        self.assertTrue(r['is_accepted'])
        self.assertEqual(r['state_path'], ['q0', 'q1', 'q1'])

    def test_string_10_accepted(self):
        r = self.engine.process_string('10')
        self.assertTrue(r['is_accepted'])
        self.assertEqual(r['state_path'], ['q0', 'q0', 'q1'])

    def test_string_011_accepted(self):
        r = self.engine.process_string('011')
        self.assertTrue(r['is_accepted'])
        self.assertEqual(r['state_path'], ['q0', 'q1', 'q1', 'q1'])

    def test_string_101_accepted(self):
        r = self.engine.process_string('101')
        self.assertTrue(r['is_accepted'])
        self.assertEqual(r['state_path'], ['q0', 'q0', 'q1', 'q1'])

    def test_string_110_accepted(self):
        r = self.engine.process_string('110')
        self.assertTrue(r['is_accepted'])
        self.assertEqual(r['state_path'], ['q0', 'q0', 'q0', 'q1'])

    def test_string_1100_rejected(self):
        r = self.engine.process_string('1100')
        self.assertFalse(r['is_accepted'])
        self.assertEqual(r['final_state'], 'q0')

    def test_empty_string_rejected(self):
        r = self.engine.process_string('')
        # q0 is not accepting
        self.assertFalse(r['is_accepted'])

    def test_out_of_alphabet_goes_dead(self):
        r = self.engine.process_string('X')
        self.assertFalse(r['is_accepted'])
        self.assertEqual(r['final_state'], 'DEAD')
        self.assertTrue(len(r['warnings']) > 0)

    def test_missing_transition_traps_to_dead(self):
        # Engine with incomplete transitions
        partial = CustomDFAEngine(
            states=['q0','q1'],
            alphabet=['0','1'],
            start_state='q0',
            accept_states=['q1'],
            transitions=[{'from':'q0','symbol':'0','to':'q1'}]  # missing δ(q0,1), δ(q1,0), δ(q1,1)
        )
        r = partial.process_string('1')  # δ(q0,1) not defined → DEAD
        self.assertFalse(r['is_accepted'])
        self.assertEqual(r['final_state'], 'DEAD')

    def test_validation_missing_start_state(self):
        eng = CustomDFAEngine(['q0','q1'],['0','1'],'',['q1'],TUTORIAL_TRANSITIONS)
        v = eng.validate()
        self.assertFalse(v['valid'])
        self.assertTrue(any('start' in e.lower() for e in v['errors']))

    def test_validation_missing_accept_states(self):
        eng = CustomDFAEngine(['q0','q1'],['0','1'],'q0',[],TUTORIAL_TRANSITIONS)
        v = eng.validate()
        self.assertFalse(v['valid'])

    def test_validation_start_state_not_in_states(self):
        eng = CustomDFAEngine(['q0','q1'],['0','1'],'qX',['q1'],TUTORIAL_TRANSITIONS)
        v = eng.validate()
        self.assertFalse(v['valid'])

    def test_validation_missing_transition_message(self):
        eng = CustomDFAEngine(['q0', 'q1'], ['0', '1'], 'q0', ['q1'], [])
        v = eng.validate()
        self.assertEqual(len(v['warnings']), 4)
        self.assertIn("During simulation, this input moves to the DEAD/TRAP state.", v['warnings'][0])
        self.assertTrue(any("δ(q0, '0')" in w for w in v['warnings']))


class TestPlaygroundAPI(unittest.TestCase):
    """Integration tests for /playground and /api/custom-dfa/simulate."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db   = self.temp_file.name
        self.temp_file.close()
        db.init_db(self.temp_db)
        self.orig_db = db.DB_PATH
        db.DB_PATH   = self.temp_db
        app.config['TESTING'] = True
        self.client = app.test_client()

    def tearDown(self):
        db.DB_PATH = self.orig_db
        if os.path.exists(self.temp_db):
            try: os.remove(self.temp_db)
            except Exception: pass

    def test_playground_route_ok(self):
        r = self.client.get('/playground')
        self.assertEqual(r.status_code, 200)
        html = r.data.decode()
        self.assertIn('DFA Playground', html)
        self.assertIn('pg-string-input', html)
        self.assertIn('pg-play-btn', html)
        self.assertIn('Return to StateLock', html)

    def test_api_string_0_accepted(self):
        r = self.client.post('/api/custom-dfa/simulate', json=api_payload('0'))
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertTrue(d['success'])
        self.assertTrue(d['is_accepted'])
        self.assertEqual(d['final_state'], 'q1')

    def test_api_string_1_rejected(self):
        r = self.client.post('/api/custom-dfa/simulate', json=api_payload('1'))
        d = r.get_json()
        self.assertFalse(d['is_accepted'])
        self.assertEqual(d['final_state'], 'q0')

    def test_api_string_01_accepted(self):
        r = self.client.post('/api/custom-dfa/simulate', json=api_payload('01'))
        d = r.get_json()
        self.assertTrue(d['is_accepted'])
        self.assertEqual(d['state_path'], ['q0','q1','q1'])

    def test_api_string_10_accepted(self):
        r = self.client.post('/api/custom-dfa/simulate', json=api_payload('10'))
        d = r.get_json()
        self.assertTrue(d['is_accepted'])
        self.assertEqual(d['state_path'], ['q0','q0','q1'])

    def test_api_string_011_accepted(self):
        r = self.client.post('/api/custom-dfa/simulate', json=api_payload('011'))
        d = r.get_json()
        self.assertTrue(d['is_accepted'])
        self.assertEqual(d['state_path'], ['q0','q1','q1','q1'])

    def test_api_string_101_accepted(self):
        r = self.client.post('/api/custom-dfa/simulate', json=api_payload('101'))
        d = r.get_json()
        self.assertTrue(d['is_accepted'])
        self.assertEqual(d['state_path'], ['q0','q0','q1','q1'])

    def test_api_conflicting_transition_rejected(self):
        bad = api_payload('0')
        bad['transitions'].append({'from':'q0','symbol':'0','to':'q0'})  # duplicate
        r = self.client.post('/api/custom-dfa/simulate', json=bad)
        self.assertEqual(r.status_code, 400)
        self.assertIn('Conflicting', r.get_json()['error'])

    def test_api_invalid_dfa_no_start(self):
        payload = api_payload('0')
        payload['start_state'] = ''
        r = self.client.post('/api/custom-dfa/simulate', json=payload)
        self.assertEqual(r.status_code, 400)

    def test_api_invalid_dfa_no_accept(self):
        payload = api_payload('0')
        payload['accept_states'] = []
        r = self.client.post('/api/custom-dfa/simulate', json=payload)
        self.assertEqual(r.status_code, 400)

    def test_independence_no_history_written(self):
        """Playground simulation must never write to auth_history."""
        ok, _, uid = db.register_user('pg_iso_user', '9999', self.temp_db)
        self.assertTrue(ok)
        for _ in range(5):
            self.client.post('/api/custom-dfa/simulate', json=api_payload('0'))
        history = db.get_user_history(uid, self.temp_db)
        self.assertEqual(len(history), 0)

    def test_independence_no_failed_attempts(self):
        """Playground must not increment user failed attempts."""
        ok, _, uid = db.register_user('pg_safe_user', '9999', self.temp_db)
        self.assertTrue(ok)
        for _ in range(6):
            self.client.post('/api/custom-dfa/simulate', json=api_payload('1'))
        user = db.get_user_by_id(uid, self.temp_db)
        self.assertEqual(user['failed_attempts'], 0)
        self.assertIsNone(user['locked_until'])

    def test_api_string_rejected_but_all_transitions_valid(self):
        """
        When string is rejected ONLY because final state is non-accepting,
        every step transition is valid (Green) while overall result is REJECTED (Red).
        """
        r = self.client.post('/api/custom-dfa/simulate', json=api_payload('1'))
        d = r.get_json()
        self.assertFalse(d['is_accepted'])
        self.assertEqual(d['status'], 'REJECTED')
        self.assertEqual(d['final_state'], 'q0')
        self.assertEqual(len(d['transitions']), 1)
        # The transition q0 -1-> q0 is completely valid
        self.assertTrue(d['transitions'][0]['is_valid'])

    def test_api_string_invalid_transition_traps_to_dead(self):
        """
        When string has an invalid symbol or undefined transition,
        that transition traps to DEAD with is_valid=False (Red).
        """
        r = self.client.post('/api/custom-dfa/simulate', json=api_payload('09'))
        d = r.get_json()
        self.assertFalse(d['is_accepted'])
        self.assertEqual(d['status'], 'REJECTED')
        self.assertEqual(d['final_state'], 'DEAD')
        self.assertEqual(len(d['transitions']), 2)
        # Step 1 was valid (0 -> q1)
        self.assertTrue(d['transitions'][0]['is_valid'])
        # Step 2 was invalid (9 -> DEAD)
        self.assertFalse(d['transitions'][1]['is_valid'])
        self.assertEqual(d['transitions'][1]['to_state'], 'DEAD')

    def test_api_multistate_dfa_simulation(self):
        """
        Tests a 4-state DFA ('Starts with ab') over alphabet {a, b}.
        q0 -a-> q1 -b-> q2 (Accept), other symbols go to q3 (trap).
        """
        payload = {
            'states': ['q0', 'q1', 'q2', 'q3'],
            'alphabet': ['a', 'b'],
            'start_state': 'q0',
            'accept_states': ['q2'],
            'transitions': [
                {'from': 'q0', 'symbol': 'a', 'to': 'q1'},
                {'from': 'q0', 'symbol': 'b', 'to': 'q3'},
                {'from': 'q1', 'symbol': 'a', 'to': 'q3'},
                {'from': 'q1', 'symbol': 'b', 'to': 'q2'},
                {'from': 'q2', 'symbol': 'a', 'to': 'q2'},
                {'from': 'q2', 'symbol': 'b', 'to': 'q2'},
                {'from': 'q3', 'symbol': 'a', 'to': 'q3'},
                {'from': 'q3', 'symbol': 'b', 'to': 'q3'},
            ],
            'input_string': 'ab'
        }
        r_valid = self.client.post('/api/custom-dfa/simulate', json=payload)
        self.assertEqual(r_valid.status_code, 200)
        d_valid = r_valid.get_json()
        self.assertTrue(d_valid['is_accepted'])
        self.assertEqual(d_valid['final_state'], 'q2')
        self.assertEqual(d_valid['state_path'], ['q0', 'q1', 'q2'])

        # Rejected string: 'ba'
        payload['input_string'] = 'ba'
        r_rej = self.client.post('/api/custom-dfa/simulate', json=payload)
        self.assertEqual(r_rej.status_code, 200)
        d_rej = r_rej.get_json()
        self.assertFalse(d_rej['is_accepted'])
        self.assertEqual(d_rej['final_state'], 'q3')
        self.assertEqual(d_rej['state_path'], ['q0', 'q3', 'q3'])

    def test_playground_template_contains_high_contrast_dropdowns(self):
        """Verifies template has From/Symbol/To dropdowns and playground.css."""
        r = self.client.get('/playground')
        self.assertEqual(r.status_code, 200)
        html = r.data.decode()
        self.assertIn('id="tr-from"', html)
        self.assertIn('id="tr-symbol"', html)
        self.assertIn('id="tr-to"', html)
        self.assertIn('playground.css', html)
    def test_index_contains_playground_link(self):
        r = self.client.get('/')
        self.assertIn('/playground', r.data.decode())


if __name__ == '__main__':
    unittest.main()
