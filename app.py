"""
StateLock - Flask Backend Application
Security Enhancements:
- Failed Attempt Limit (5 Max) & Tracking
- Temporary Account Lock (60s Lockout with Countdown)
- Success Reset
- Security Event History Logging
- Session Security & Anti-Caching Headers
- Server-Side Input Validation & Error Handling
DFA Playground:
- Interactive Custom DFA Builder & Simulator
- Custom 5-tuple DFA: states, alphabet, transitions, start/accept states
- Character-by-character string simulation with full trace
- Completely independent from user authentication & history
Theory of Computation Semester Project
"""

import os
import re
from datetime import timedelta
from flask import Flask, render_template, request, jsonify, session
from dfa_engine import DFAEngine, CustomDFAEngine
import database as db

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "statelock_master_key_toc_2026_dfa")

# Session security configuration
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

# Initialize database schema and migrations
db.init_db()

# Standalone demo DFA engine instance (passcode 3412)
demo_dfa = DFAEngine(target_sequence="3412")

# Allowed passcode and username regex patterns
PASSCODE_REGEX = re.compile(r"^[0-9a-zA-Z@#$%*!]{4}$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,24}$")


@app.after_request
def add_security_headers(response):
    """
    Sets anti-caching and security headers on every response to protect
    authenticated data and prevent viewing stale protected state on browser back/forward.
    """
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.route("/")
def index():
    """Renders the main StateLock authentication & history interface."""
    return render_template("index.html")


@app.route("/history")
def history():
    """
    Direct route to access the Authentication History interface.
    Requires an active authenticated session.
    Unauthenticated users receive HTTP 401 Unauthorized and are prompted to log in.
    """
    user_id = session.get("user_id")
    is_auth = session.get("authenticated", False)
    if not user_id or not is_auth:
        return render_template("index.html", unauthorized_history=True), 401
    return render_template("index.html", open_history=True)


@app.route("/dashboard")
def dashboard():
    """
    Direct route to access the Professional Dashboard & Analytics page.
    Requires an active authenticated session.
    Unauthenticated users receive HTTP 401 Unauthorized and are prompted to log in.
    """
    user_id = session.get("user_id")
    is_auth = session.get("authenticated", False)
    if not user_id or not is_auth:
        return render_template("index.html", unauthorized_dashboard=True), 401
    user = db.get_user_by_id(user_id)
    if not user:
        session.clear()
        return render_template("index.html", unauthorized_dashboard=True), 401
    return render_template("dashboard.html", username=user["username"])



@app.route("/api/register", methods=["POST"])
def register():
    """
    Registers a new user with a unique username and 4-character passcode.
    Passcode is securely hashed and encrypted before storage.
    """
    try:
        data = request.get_json(silent=True) or request.form
        if not data:
            return jsonify({"success": False, "error": "Missing registration data."}), 400

        username = data.get("username")
        passcode = data.get("passcode")

        # Input validation
        if not isinstance(username, str) or not isinstance(passcode, str):
            return jsonify({"success": False, "error": "Invalid input format."}), 400

        username = username.strip()
        passcode = passcode.strip()

        if not username:
            return jsonify({"success": False, "error": "Username cannot be empty."}), 400
        if not USERNAME_REGEX.match(username):
            return jsonify({"success": False, "error": "Username must be 3-24 characters (letters, numbers, underscores, hyphens)."}), 400

        if len(passcode) != 4:
            return jsonify({"success": False, "error": "Passcode must be exactly 4 characters."}), 400
        if not PASSCODE_REGEX.match(passcode):
            return jsonify({"success": False, "error": "Passcode can only contain 0-9, a-z, A-Z, and @ # $ % * !"}), 400

        success, message, user_id = db.register_user(username, passcode)
        if success:
            return jsonify({
                "success": True,
                "message": message,
                "username": username
            }), 201
        else:
            return jsonify({
                "success": False,
                "error": message
            }), 400
    except Exception:
        return jsonify({"success": False, "error": "An error occurred during registration. Please try again."}), 500


@app.route("/api/lockout-status", methods=["GET", "POST"])
def lockout_status():
    """
    Checks the current failed attempt count and lockout state for a given username.
    """
    try:
        if request.method == "POST":
            data = request.get_json(silent=True) or request.form or {}
            username = data.get("username", "")
        else:
            username = request.args.get("username", "")

        if not isinstance(username, str) or not username.strip():
            return jsonify({
                "is_locked": False,
                "failed_attempts": 0,
                "max_attempts": db.MAX_FAILED_ATTEMPTS,
                "lockout_remaining": 0
            }), 200

        user = db.get_user_by_username(username.strip())
        if not user:
            return jsonify({
                "is_locked": False,
                "failed_attempts": 0,
                "max_attempts": db.MAX_FAILED_ATTEMPTS,
                "lockout_remaining": 0
            }), 200

        is_locked, remaining = db.check_user_lockout(user)
        # Refresh user record in case lockout expired
        if not is_locked:
            user = db.get_user_by_username(username.strip())

        failed_attempts = user.get("failed_attempts", 0) if user else 0

        return jsonify({
            "is_locked": is_locked,
            "failed_attempts": failed_attempts,
            "max_attempts": db.MAX_FAILED_ATTEMPTS,
            "lockout_remaining": remaining
        }), 200
    except Exception:
        return jsonify({
            "is_locked": False,
            "failed_attempts": 0,
            "max_attempts": db.MAX_FAILED_ATTEMPTS,
            "lockout_remaining": 0
        }), 200


@app.route("/api/login", methods=["POST"])
def login():
    """
    Processes the entered sequence character-by-character through the user's DFA.
    Includes Security Enhancements:
      - Checks for active lockout before authentication.
      - Tracks consecutive failed attempts (1-5).
      - Locks account for 60s upon reaching 5 consecutive failures.
      - Resets failed attempts to 0 on successful authentication.
      - Logs security events (Failed login, Successful login, Account locked, Lockout ended).
    """
    try:
        data = request.get_json(silent=True) or request.form
        if not data:
            return jsonify({"success": False, "error": "Missing login credentials."}), 400

        username = data.get("username")
        passcode = data.get("passcode")

        if not isinstance(username, str) or not isinstance(passcode, str):
            return jsonify({"success": False, "error": "Invalid credentials format."}), 400

        username = username.strip()
        passcode = passcode.strip()

        if not username:
            return jsonify({"success": False, "error": "Please enter a username."}), 400
        if not passcode:
            return jsonify({"success": False, "error": "Please enter a passcode."}), 400

        # Validate input length and characters on server
        if len(passcode) != 4 or not PASSCODE_REGEX.match(passcode):
            return jsonify({"success": False, "error": "Passcode must be exactly 4 valid characters (0-9, a-z, A-Z, @#$%*!)."}), 400

        user = db.get_user_by_username(username)

        if user:
            # 1. Check if user account is currently locked
            is_locked, remaining_seconds = db.check_user_lockout(user)
            if is_locked:
                return jsonify({
                    "success": False,
                    "is_locked": True,
                    "lockout_remaining": remaining_seconds,
                    "failed_attempts": db.MAX_FAILED_ATTEMPTS,
                    "max_attempts": db.MAX_FAILED_ATTEMPTS,
                    "status": "ACCOUNT LOCKED",
                    "error": f"Account is temporarily locked due to 5 consecutive failed attempts. Please wait {remaining_seconds}s before trying again.",
                    "message": f"Account locked. Retry available in {remaining_seconds}s.",
                    "final_state": "DEAD",
                    "state_path": ["q0", "DEAD"],
                    "transitions": []
                }), 403

            # 2. Retrieve user's personal target sequence
            user_target = db.get_user_target_sequence(user) or ""
            
            # 3. Instantiate user's DFA & process character-by-character
            user_dfa = DFAEngine(target_sequence=user_target)
            dfa_result = user_dfa.process_sequence(passcode)
            
            # Determine authentication strictly from the final DFA state AND secure password hash
            is_dfa_accepted = (dfa_result["final_state"] == "q4")
            is_hash_valid = db.verify_user_passcode(user, passcode)
            is_accepted = is_dfa_accepted and is_hash_valid
            dfa_result["is_accepted"] = is_accepted

            if is_accepted:
                # SUCCESSFUL AUTHENTICATION
                # Reset failed attempt counter to 0
                db.reset_failed_attempts(user["id"])

                dfa_result["status"] = "ACCESS GRANTED"
                dfa_result["message"] = f"Access Granted! Reached accepting state q4. Welcome back, {user['username']}."
                dfa_result["failed_attempts"] = 0
                dfa_result["max_attempts"] = db.MAX_FAILED_ATTEMPTS
                dfa_result["is_locked"] = False
                dfa_result["lockout_remaining"] = 0

                # Establish clean authenticated session (clearing old keys prevents fixation)
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["authenticated"] = True
                dfa_result["user"] = {
                    "id": user["id"],
                    "username": user["username"]
                }

                # Log successful login to history
                db.log_auth_attempt(
                    user_id=user["id"],
                    username=user["username"],
                    input_sequence=passcode,
                    is_success=True,
                    final_state=dfa_result["final_state"],
                    state_path=dfa_result["state_path"],
                    transitions=dfa_result["transitions"],
                    event_type="Successful login",
                    status_override="ACCESS GRANTED"
                )

                return jsonify(dfa_result), 200

            else:
                # FAILED AUTHENTICATION
                lockout_info = db.record_failed_attempt(
                    user_id=user["id"],
                    username=user["username"],
                    lockout_duration=db.LOCKOUT_DURATION_SECONDS
                )

                dfa_result["failed_attempts"] = lockout_info["failed_attempts"]
                dfa_result["max_attempts"] = db.MAX_FAILED_ATTEMPTS
                dfa_result["is_locked"] = lockout_info["is_locked"]
                dfa_result["lockout_remaining"] = lockout_info["lockout_remaining"]

                if lockout_info["is_locked"]:
                    dfa_result["status"] = "ACCOUNT LOCKED"
                    dfa_result["message"] = f"Account locked! Maximum 5 failed attempts reached. Please wait {lockout_info['lockout_remaining']}s."
                else:
                    dfa_result["status"] = "ACCESS DENIED"
                    dfa_result["message"] = f"Access Denied ({lockout_info['failed_attempts']}/{db.MAX_FAILED_ATTEMPTS} failed): Reached non-accepting state {dfa_result['final_state']}."

                # Log failed attempt in history
                db.log_auth_attempt(
                    user_id=user["id"],
                    username=user["username"],
                    input_sequence=passcode,
                    is_success=False,
                    final_state=dfa_result["final_state"],
                    state_path=dfa_result["state_path"],
                    transitions=dfa_result["transitions"],
                    event_type="Failed login",
                    status_override="ACCESS DENIED"
                )

                return jsonify(dfa_result), 200

        else:
            # User not found: process through dummy DFA to keep consistent timing
            dummy_dfa = DFAEngine(target_sequence="")
            dfa_result = dummy_dfa.process_sequence(passcode)
            dfa_result["is_accepted"] = False
            dfa_result["status"] = "ACCESS DENIED"
            dfa_result["message"] = f"Access Denied: Invalid credentials. Transitioned to DEAD trap state."
            dfa_result["failed_attempts"] = 1
            dfa_result["max_attempts"] = db.MAX_FAILED_ATTEMPTS
            dfa_result["is_locked"] = False
            dfa_result["lockout_remaining"] = 0

            # Log unauthenticated failure attempt
            db.log_auth_attempt(
                user_id=None,
                username=username,
                input_sequence=passcode,
                is_success=False,
                final_state=dfa_result["final_state"],
                state_path=dfa_result["state_path"],
                transitions=dfa_result["transitions"],
                event_type="Failed login",
                status_override="ACCESS DENIED"
            )

            return jsonify(dfa_result), 200

    except Exception:
        return jsonify({"success": False, "error": "An authentication error occurred. Please try again."}), 500


@app.route("/api/change-passcode", methods=["POST"])
def change_passcode():
    """
    Allows authenticated users to change their 4-character passcode.
    Requires an active authenticated session.
    """
    try:
        user_id = session.get("user_id")
        if not user_id or not session.get("authenticated"):
            return jsonify({"success": False, "error": "Unauthorized. Please log in first."}), 401

        data = request.get_json(silent=True) or request.form
        if not data:
            return jsonify({"success": False, "error": "Missing passcode update data."}), 400

        current_passcode = data.get("current_passcode", "")
        new_passcode = data.get("new_passcode", "")
        confirm_passcode = data.get("confirm_passcode", "")

        if not isinstance(current_passcode, str) or not isinstance(new_passcode, str) or not isinstance(confirm_passcode, str):
            return jsonify({"success": False, "error": "Invalid passcode format."}), 400

        success, message = db.update_user_passcode(
            user_id=user_id,
            current_passcode=current_passcode,
            new_passcode=new_passcode,
            confirm_passcode=confirm_passcode
        )

        if success:
            return jsonify({"success": True, "message": message}), 200
        else:
            return jsonify({"success": False, "error": message}), 400
    except Exception:
        return jsonify({"success": False, "error": "Failed to update passcode. Please try again."}), 500


@app.route("/api/logout", methods=["POST", "GET"])
def logout():
    """Logs out current user, completely destroys session and clears session cookie."""
    session.clear()
    response = jsonify({"success": True, "message": "Logged out successfully."})
    response.delete_cookie(app.config.get("SESSION_COOKIE_NAME", "session"))
    return response, 200


@app.route("/api/user-status", methods=["GET"])
def user_status():
    """Returns the current user's session status."""
    user_id = session.get("user_id")
    username = session.get("username")
    is_auth = session.get("authenticated", False)
    if user_id and username and is_auth:
        return jsonify({
            "logged_in": True,
            "user_id": user_id,
            "username": username
        }), 200
    else:
        return jsonify({
            "logged_in": False,
            "user_id": None,
            "username": None
        }), 200


@app.route("/api/history", methods=["GET"])
def get_history():
    """Returns the authentication and security history for the logged-in user."""
    user_id = session.get("user_id")
    if not user_id or not session.get("authenticated"):
        return jsonify({"success": False, "error": "Unauthorized. Please log in to view history."}), 401

    try:
        history_records = db.get_user_history(user_id=user_id, limit=50)
        return jsonify({
            "success": True,
            "history": history_records,
            "username": session.get("username")
        }), 200
    except Exception:
        return jsonify({"success": False, "error": "Failed to retrieve history."}), 500


@app.route("/api/dashboard-stats", methods=["GET"])
def get_dashboard_stats():
    """
    Returns real-time authentication analytics, KPI metrics, chart data, 
    account status, and recent activity for the authenticated user from SQLite.
    """
    user_id = session.get("user_id")
    if not user_id or not session.get("authenticated"):
        return jsonify({"success": False, "error": "Unauthorized. Please log in to view dashboard analytics."}), 401

    try:
        stats = db.get_user_dashboard_stats(user_id)
        if not stats.get("success"):
            return jsonify({"success": False, "error": stats.get("error", "Failed to retrieve dashboard statistics.")}), 500
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"success": False, "error": f"Internal server error: {str(e)}"}), 500



@app.route("/api/verify", methods=["POST"])
def verify_sequence():
    """
    Demo / Standalone verification endpoint for testing DFA sequences directly.
    """
    try:
        data = request.get_json(silent=True) or request.form
        if not data or "sequence" not in data:
            sequence = request.args.get("sequence", "")
        else:
            sequence = data.get("sequence", "")

        if not isinstance(sequence, str):
            return jsonify({"success": False, "error": "Invalid sequence format."}), 400

        result = demo_dfa.process_sequence(sequence)
        status_code = 200 if result.get("success", False) else 400
        return jsonify(result), status_code
    except Exception:
        return jsonify({"success": False, "error": "Failed to process sequence."}), 500


@app.route("/api/dfa-info", methods=["GET"])
def get_dfa_info():
    """Returns formal DFA specifications."""
    return jsonify(demo_dfa.get_info()), 200


@app.route("/playground")
def playground():
    """Renders the Interactive DFA Builder & Playground page."""
    return render_template("playground.html")


@app.route("/api/custom-dfa/simulate", methods=["POST"])
def custom_dfa_simulate():
    """
    DFA Playground API endpoint.
    Accepts a user-defined DFA 5-tuple + input string and returns a full
    character-by-character execution trace.

    Does NOT touch user authentication, sessions, history, or lockout.
    """
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"success": False, "error": "No JSON body provided."}), 400

        # --- Parse DFA definition ---
        states = data.get("states", [])
        alphabet = data.get("alphabet", [])
        start_state = data.get("start_state", "")
        accept_states = data.get("accept_states", [])
        transitions = data.get("transitions", [])
        input_string = data.get("input_string", "")

        # Basic type validation
        if not isinstance(states, list) or not isinstance(alphabet, list):
            return jsonify({"success": False, "error": "'states' and 'alphabet' must be arrays."}), 400
        if not isinstance(accept_states, list) or not isinstance(transitions, list):
            return jsonify({"success": False, "error": "'accept_states' and 'transitions' must be arrays."}), 400
        if not isinstance(input_string, str):
            return jsonify({"success": False, "error": "'input_string' must be a string."}), 400

        # Strip and validate state names and alphabet symbols (no empty strings)
        states = [str(s).strip() for s in states if str(s).strip()]
        alphabet = [str(a).strip() for a in alphabet if str(a).strip()]
        accept_states = [str(s).strip() for s in accept_states if str(s).strip()]
        start_state = str(start_state).strip()

        # Validate transitions structure
        clean_transitions = []
        seen_keys = set()
        for tr in transitions:
            if not isinstance(tr, dict):
                continue
            fr = str(tr.get("from", "")).strip()
            sym = str(tr.get("symbol", "")).strip()
            to = str(tr.get("to", "")).strip()
            if not fr or not sym or not to:
                continue
            # Detect conflicting transitions for same (from, symbol)
            key = (fr, sym)
            if key in seen_keys:
                return jsonify({
                    "success": False,
                    "error": f"Conflicting transitions: δ({fr}, '{sym}') is defined more than once."
                }), 400
            seen_keys.add(key)
            clean_transitions.append({"from": fr, "symbol": sym, "to": to})

        # Build and validate engine
        engine = CustomDFAEngine(
            states=states,
            alphabet=alphabet,
            start_state=start_state,
            accept_states=accept_states,
            transitions=clean_transitions,
        )

        validation = engine.validate()
        if not validation["valid"]:
            return jsonify({
                "success": False,
                "error": "DFA definition is invalid.",
                "errors": validation["errors"],
                "warnings": validation["warnings"],
            }), 400

        # Run simulation
        result = engine.process_string(input_string)
        result["validation_warnings"] = validation["warnings"]
        return jsonify(result), 200

    except Exception as ex:
        return jsonify({"success": False, "error": "Failed to simulate custom DFA."}), 500



# =============================================================================
# Custom Sanitized Error Handlers (No Python/DB internals leaked)
# =============================================================================

@app.errorhandler(400)
def bad_request(error):
    return jsonify({"success": False, "error": "Bad request. Please verify your input."}), 400


@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"success": False, "error": "Unauthorized. Please log in first."}), 401


@app.errorhandler(403)
def forbidden(error):
    return jsonify({"success": False, "error": "Access forbidden or account locked."}), 403


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Resource not found."}), 404
    return render_template("index.html"), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"success": False, "error": "Method not allowed."}), 405


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"success": False, "error": "An internal server error occurred. Please try again later."}), 500


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
