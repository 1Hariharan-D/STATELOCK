# StateLock - Phase 1

**Deterministic Finite Automaton (DFA) Authentication System**  
*Theory of Computation Semester Project*

---

## 📌 Project Overview
StateLock is a DFA-based authentication web platform. In Phase 1, the system models a formal 5-tuple Deterministic Finite Automaton $M = (Q, \Sigma, \delta, q_0, F)$ that verifies numerical passcode sequences.

- **Accepting Passcode:** `3142`
- **States:** $Q = \{q0, q1, q2, q3, q4, \text{DEAD}\}$
- **Alphabet:** $\Sigma = \{0, 1, 2, 3, 4, 5, 6, 7, 8, 9\}$
- **Start State:** $q_0 = q0$
- **Accepting State:** $F = \{q4\}$
- **Trap State:** $\text{DEAD}$ (any non-matching digit routes to DEAD)

---

## 🛠️ Architecture & Tech Stack
- **Backend:** Python 3 + Flask REST API (`app.py`, `dfa_engine.py`)
- **Frontend:** Semantic HTML5, Modern Vanilla CSS3 (Dark/Glassmorphism theme), Vanilla JavaScript (`templates/index.html`, `static/css/style.css`, `static/js/main.js`)
- **Testing:** Python `unittest` suite (`test_dfa.py`, `verify_live_app.py`)

---

## 🚀 How to Run

1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the Flask Server:**
   ```bash
   python app.py
   ```
   The application will start on: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

3. **Run Automated Unit Tests:**
   ```bash
   python -m unittest test_dfa.py
   ```

4. **Run Live Endpoint Verification:**
   ```bash
   python verify_live_app.py
   ```

---

## 🧪 Test Cases Verified
| Sequence | Expected Result | Final State | State Path |
| :--- | :--- | :--- | :--- |
| **`3142`** | **ACCESS GRANTED** | `q4` | `q0 ➔ q1 ➔ q2 ➔ q3 ➔ q4` |
| **`3149`** | **ACCESS DENIED** | `DEAD` | `q0 ➔ q1 ➔ q2 ➔ q3 ➔ DEAD` |
| **`3192`** | **ACCESS DENIED** | `DEAD` | `q0 ➔ q1 ➔ q2 ➔ DEAD ➔ DEAD` |
| **`1234`** | **ACCESS DENIED** | `DEAD` | `q0 ➔ DEAD ➔ DEAD ➔ DEAD ➔ DEAD` |
| *Empty* | **ACCESS DENIED** | `q0` | Validation Error / `q0` |

---

## 📁 Directory Structure
```
Statelock/
├── dfa_engine.py          # Modular 5-tuple DFA engine with state tracer
├── app.py                 # Flask web server & REST API
├── requirements.txt       # Python dependencies
├── test_dfa.py            # Unit test suite
├── verify_live_app.py     # Live HTTP server test runner
├── README.md              # Project documentation
├── templates/
│   └── index.html         # Web frontend with interactive SVG DFA diagram
└── static/
    ├── css/
    │   └── style.css      # Dark cybersecurity design system
    └── js/
        └── main.js        # Dynamic DOM rendering, keypad, diagram highlight
```
