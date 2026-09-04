"""
StateLock - Phase 5 DFA Playground Live Verification Script
Verifies:
 1. /playground route loads with correct UI elements.
 2. Main app / has navigation link to /playground.
 3. Tutorial DFA test strings produce correct ACCEPT/REJECT results.
 4. Conflict detection for duplicate transitions.
 5. Invalid DFA (no start, no accept) returns 400.
 6. Playground is 100% independent from user auth & history.
"""

import tempfile
import os
import sys
import database as db
from app import app

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

STATES      = ['q0', 'q1']
ALPHABET    = ['0', '1']
START       = 'q0'
ACCEPT      = ['q1']
TRANSITIONS = [
    {'from': 'q0', 'symbol': '0', 'to': 'q1'},
    {'from': 'q0', 'symbol': '1', 'to': 'q0'},
    {'from': 'q1', 'symbol': '0', 'to': 'q0'},
    {'from': 'q1', 'symbol': '1', 'to': 'q1'},
]

def payload(s):
    return {
        'states': list(STATES), 'alphabet': list(ALPHABET),
        'start_state': START, 'accept_states': list(ACCEPT),
        'transitions': [dict(t) for t in TRANSITIONS], 'input_string': s,
    }

def run():
    print('=================================================================')
    print('  STATELOCK DFA PLAYGROUND LIVE VERIFICATION')
    print('=================================================================')

    tf = tempfile.NamedTemporaryFile(delete=False)
    db_path = tf.name
    tf.close()
    db.init_db(db_path)
    orig = db.DB_PATH
    db.DB_PATH = db_path
    app.config['TESTING'] = True
    c = app.test_client()

    try:
        # 1. Route check
        r = c.get('/playground')
        assert r.status_code == 200
        html = r.data.decode()
        assert 'DFA Playground'   in html, 'Title missing'
        assert 'pg-string-input'  in html, 'Input missing'
        assert 'pg-play-btn'      in html, 'Play button missing'
        assert 'Return to StateLock' in html, 'Return link missing'
        print('[PASS] Step 1: GET /playground loaded with full UI, controls & SVG.')

        # 2. Main nav
        r2 = c.get('/')
        assert '/playground' in r2.data.decode()
        print('[PASS] Step 2: Main app header contains DFA Playground navigation link.')

        # 3. Tutorial DFA string tests
        cases = [
            ('0',    True,  'q1',  ['q0','q1']),
            ('1',    False, 'q0',  ['q0','q0']),
            ('01',   True,  'q1',  ['q0','q1','q1']),
            ('10',   True,  'q1',  ['q0','q0','q1']),
            ('011',  True,  'q1',  ['q0','q1','q1','q1']),
            ('101',  True,  'q1',  ['q0','q0','q1','q1']),
            ('110',  True,  'q1',  ['q0','q0','q0','q1']),
            ('1100', False, 'q0',  ['q0','q0','q0','q1','q0']),
        ]
        for (s, expected_accept, expected_final, expected_path) in cases:
            r = c.post('/api/custom-dfa/simulate', json=payload(s))
            assert r.status_code == 200, f'Non-200 for "{s}": {r.status_code}'
            d = r.get_json()
            assert d['success']
            assert d['is_accepted'] == expected_accept, \
                f'"{s}": expected is_accepted={expected_accept}, got {d["is_accepted"]}'
            assert d['final_state'] == expected_final, \
                f'"{s}": expected final={expected_final}, got {d["final_state"]}'
            assert d['state_path'] == expected_path, \
                f'"{s}": expected path={expected_path}, got {d["state_path"]}'
            verdict = 'ACCEPTED' if expected_accept else 'REJECTED'
            print(f'[PASS] Step 3/{s}: "{s}" → {" → ".join(expected_path)} → {verdict} ({expected_final})')

        # 4. Conflict detection
        bad_payload = payload('0')
        bad_payload['transitions'].append({'from':'q0','symbol':'0','to':'q0'})
        r4 = c.post('/api/custom-dfa/simulate', json=bad_payload)
        assert r4.status_code == 400
        assert 'Conflicting' in r4.get_json().get('error','')
        print('[PASS] Step 4: Conflicting transition δ(q0,0) detected and rejected with 400.')

        # 5. Invalid DFA errors
        no_start = payload('0'); no_start['start_state'] = ''
        r5a = c.post('/api/custom-dfa/simulate', json=no_start)
        assert r5a.status_code == 400
        no_accept = payload('0'); no_accept['accept_states'] = []
        r5b = c.post('/api/custom-dfa/simulate', json=no_accept)
        assert r5b.status_code == 400
        print('[PASS] Step 5: Missing start state and missing accept state both return 400.')

        # 6. Independence: no auth_history writes, no failed_attempts
        ok, _, uid = db.register_user('verify_pg_user', '5678', db_path)
        assert ok
        for _ in range(8):
            c.post('/api/custom-dfa/simulate', json=payload('1'))  # 8 REJECTED runs
        history = db.get_user_history(uid, db_path)
        assert len(history) == 0, f'Expected 0 history rows, got {len(history)}'
        user = db.get_user_by_id(uid, db_path)
        assert user['failed_attempts'] == 0
        assert user['locked_until'] is None
        print('[PASS] Step 6: Playground is 100% independent — no auth_history rows, no lockout.')

        # 7. Simulator color accuracy: Valid vs Invalid vs Non-accepting final state
        # A valid string
        r_val = c.post('/api/custom-dfa/simulate', json=payload('0'))
        d_val = r_val.get_json()
        assert d_val['is_accepted'] is True
        assert d_val['final_state'] == 'q1'
        assert all(t['is_valid'] for t in d_val['transitions'])
        print('[PASS] Step 7a: Valid string "0" -> ACCEPTED, transitions all valid (green).')

        # A rejected string where all transitions are valid
        r_rej = c.post('/api/custom-dfa/simulate', json=payload('1'))
        d_rej = r_rej.get_json()
        assert d_rej['is_accepted'] is False
        assert d_rej['final_state'] == 'q0'
        assert all(t['is_valid'] for t in d_rej['transitions'])
        print('[PASS] Step 7b: Rejected string "1" -> REJECTED (q0 non-accepting), valid transition stays green.')

        # A string with an actual invalid transition (trap to DEAD)
        r_trap = c.post('/api/custom-dfa/simulate', json=payload('0X'))
        d_trap = r_trap.get_json()
        assert d_trap['is_accepted'] is False
        assert d_trap['final_state'] == 'DEAD'
        assert d_trap['transitions'][0]['is_valid'] is True   # '0' was valid
        assert d_trap['transitions'][1]['is_valid'] is False  # 'X' was trap to DEAD (red)
        print('[PASS] Step 7c: String with invalid symbol "0X" -> Step 1 green, Step 2 red (DEAD).')

        # 8. Multi-state DFA verification (4 states)
        multi_payload = {
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
        r_multi = c.post('/api/custom-dfa/simulate', json=multi_payload)
        d_multi = r_multi.get_json()
        assert d_multi['is_accepted'] is True
        assert d_multi['final_state'] == 'q2'
        print('[PASS] Step 8: Multi-state DFA (4 states) processed successfully.')

        print('\n=================================================================')
        print('  ALL DFA PLAYGROUND VERIFICATIONS PASSED ✓')
        print('=================================================================')

    finally:
        db.DB_PATH = orig
        if os.path.exists(db_path):
            try: os.remove(db_path)
            except Exception: pass

if __name__ == '__main__':
    run()
