"""
StateLock - DFA Engine Module
Theory of Computation Project

Defines the formal 5-tuple Deterministic Finite Automaton (Q, Σ, δ, q0, F)
for secure sequence authentication.
"""

from typing import Dict, List, Set, Any, Optional


class DFAEngine:
    """
    DFA Engine for sequence verification.
    
    Target Passcode / Sequence: "3412"
    
    Formal Specification:
      - Q (States): { 'q0', 'q1', 'q2', 'q3', 'q4', 'DEAD' }
      - Σ (Alphabet): { 0-9, a-z, A-Z, @, #, $, %, *, ! }
      - q0 (Start State): 'q0'
      - F (Accepting States): { 'q4' }
      - δ (Transition Function for target "3412"):
          δ(q0, '3') = q1
          δ(q1, '4') = q2
          δ(q2, '1') = q3
          δ(q3, '2') = q4
          All other state/symbol combinations → DEAD
    """

    def __init__(self, target_sequence: str = "3412"):
        self.target_sequence = str(target_sequence)
        self.states: Set[str] = {"q0", "q1", "q2", "q3", "q4", "DEAD"}
        
        # Alphabet includes 0-9, A-Z, a-z, and special characters @ # $ % * !
        digits = {str(i) for i in range(10)}
        uppercase = {chr(c) for c in range(ord('A'), ord('Z') + 1)}
        lowercase = {chr(c) for c in range(ord('a'), ord('z') + 1)}
        special = {'@', '#', '$', '%', '*', '!'}
        self.alphabet: Set[str] = digits | uppercase | lowercase | special
        
        self.start_state: str = "q0"
        self.accept_states: Set[str] = {"q4"}
        self.dead_state: str = "DEAD"

        # Build dynamic transition table for target sequence
        self.transitions_map: Dict[tuple, str] = {}
        state_names = ["q0", "q1", "q2", "q3", "q4"]
        for i, char in enumerate(self.target_sequence):
            if i < len(state_names) - 1:
                self.transitions_map[(state_names[i], char)] = state_names[i + 1]

    def get_transition(self, current_state: str, symbol: str) -> str:
        """
        Calculates δ(current_state, symbol).
        """
        # If already in DEAD state or post-accepting, remain in DEAD
        if current_state == self.dead_state or current_state not in self.states:
            return self.dead_state

        return self.transitions_map.get((current_state, symbol), self.dead_state)

    def process_sequence(self, input_sequence: Optional[str]) -> Dict[str, Any]:
        """
        Processes an input string symbol-by-symbol through the DFA.
        
        Returns:
            Dictionary containing acceptance status, state path, transitions, and explanation.
        """
        # Input validation
        if input_sequence is None:
            return {
                "success": False,
                "error": "Input sequence is missing.",
                "input_sequence": "",
                "is_accepted": False,
                "status": "ACCESS DENIED",
                "final_state": self.start_state,
                "state_path": [self.start_state],
                "transitions": [],
                "message": "Error: No input sequence provided."
            }

        seq = str(input_sequence).strip()

        if not seq:
            return {
                "success": False,
                "error": "Empty input sequence.",
                "input_sequence": "",
                "is_accepted": False,
                "status": "ACCESS DENIED",
                "final_state": self.start_state,
                "state_path": [self.start_state],
                "transitions": [],
                "message": "Error: Please enter a sequence to verify."
            }

        # Check for invalid characters
        invalid_symbols = [c for c in seq if c not in self.alphabet]

        current_state = self.start_state
        state_path: List[str] = [current_state]
        transitions_log: List[Dict[str, Any]] = []

        for index, symbol in enumerate(seq):
            from_state = current_state
            next_state = self.get_transition(from_state, symbol)

            is_valid_step = (next_state != self.dead_state)
            transitions_log.append({
                "step": index + 1,
                "from_state": from_state,
                "symbol": symbol,
                "to_state": next_state,
                "is_valid": is_valid_step
            })

            current_state = next_state
            state_path.append(current_state)

        is_accepted = (current_state in self.accept_states)

        if is_accepted:
            status_text = "ACCESS GRANTED"
            message = f"Passcode '{seq}' verified! Reached accepting state {current_state}."
        else:
            status_text = "ACCESS DENIED"
            if invalid_symbols:
                message = f"Sequence '{seq}' rejected: Contains invalid symbols: {', '.join(set(invalid_symbols))}."
            elif current_state == self.dead_state:
                message = f"Sequence '{seq}' rejected: Transitioned to {self.dead_state} trap state on incorrect symbol."
            else:
                message = f"Sequence '{seq}' rejected: Incomplete sequence. Stopped at non-accepting state {current_state}."

        return {
            "success": True,
            "input_sequence": seq,
            "is_accepted": is_accepted,
            "status": status_text,
            "final_state": current_state,
            "state_path": state_path,
            "transitions": transitions_log,
            "message": message,
            "target_sequence": self.target_sequence,
            "states": list(self.states),
            "accept_states": list(self.accept_states),
            "start_state": self.start_state,
            "has_invalid_symbols": len(invalid_symbols) > 0
        }

    def get_info(self) -> Dict[str, Any]:
        """Returns the formal metadata of this DFA."""
        return {
            "name": "StateLock 4-Digit Passcode DFA",
            "states": ["q0", "q1", "q2", "q3", "q4", "DEAD"],
            "alphabet": sorted(list(self.alphabet)),
            "start_state": self.start_state,
            "accept_states": list(self.accept_states),
            "dead_state": self.dead_state,
            "target_sequence": self.target_sequence,
            "formal_definition": "M = (Q, Σ, δ, q0, F)"
        }


class CustomDFAEngine:
    """
    Custom DFA Engine for the DFA Playground.

    Supports arbitrary user-defined 5-tuple DFAs:
      M = (Q, Σ, δ, q0, F)

    Users specify states, alphabet, start state, accept states, and
    transition rules δ(state, symbol) = next_state.
    Missing transitions lead to a synthetic 'DEAD' trap state.

    This engine is completely independent from the authentication DFA engine.
    """

    DEAD_STATE = "DEAD"

    def __init__(
        self,
        states: List[str],
        alphabet: List[str],
        start_state: str,
        accept_states: List[str],
        transitions: List[Dict[str, str]],   # [{"from": s, "symbol": a, "to": t}, ...]
    ):
        self.states: List[str] = list(states)
        self.alphabet: List[str] = list(alphabet)
        self.start_state: str = start_state
        self.accept_states: List[str] = list(accept_states)

        # Build δ map: {(from_state, symbol): to_state}
        self.delta: Dict[tuple, str] = {}
        for tr in transitions:
            key = (str(tr["from"]), str(tr["symbol"]))
            self.delta[key] = str(tr["to"])

    def validate(self) -> Dict[str, Any]:
        """
        Validates the DFA specification.
        Returns {'valid': bool, 'errors': [...], 'warnings': [...]}.
        """
        errors: List[str] = []
        warnings: List[str] = []

        if not self.states:
            errors.append("At least one state is required.")
        if not self.alphabet:
            errors.append("The alphabet must have at least one symbol.")
        if not self.start_state:
            errors.append("A start state must be specified.")
        elif self.start_state not in self.states:
            errors.append(f"Start state '{self.start_state}' is not in the defined states.")
        if not self.accept_states:
            errors.append("At least one accepting state must be specified.")
        else:
            for qs in self.accept_states:
                if qs not in self.states:
                    errors.append(f"Accept state '{qs}' is not in the defined states.")

        # Check for missing transitions (warnings)
        for state in self.states:
            for symbol in self.alphabet:
                if (state, symbol) not in self.delta:
                    warnings.append(
                        f"Missing transition: δ({state}, '{symbol}'). During simulation, this input moves to the DEAD/TRAP state."
                    )

        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}

    def get_transition(self, current_state: str, symbol: str) -> str:
        """Returns δ(current_state, symbol), or DEAD if undefined."""
        if current_state == self.DEAD_STATE:
            return self.DEAD_STATE
        return self.delta.get((current_state, symbol), self.DEAD_STATE)

    def process_string(self, input_string: str) -> Dict[str, Any]:
        """
        Runs input_string through the custom DFA symbol-by-symbol.

        Returns full execution trace: transitions, state path, final state, and acceptance.
        """
        if input_string is None:
            input_string = ""

        current_state = self.start_state
        state_path: List[str] = [current_state]
        transitions_log: List[Dict[str, Any]] = []
        warnings: List[str] = []

        for index, symbol in enumerate(input_string):
            from_state = current_state

            if symbol not in self.alphabet:
                warnings.append(f"Symbol '{symbol}' at position {index + 1} is not in the defined alphabet.")

            next_state = self.get_transition(from_state, symbol)
            is_trap = (next_state == self.DEAD_STATE)

            transitions_log.append({
                "step": index + 1,
                "from_state": from_state,
                "symbol": symbol,
                "to_state": next_state,
                "is_valid": not is_trap,
                "in_alphabet": symbol in self.alphabet,
            })

            current_state = next_state
            state_path.append(current_state)

        is_accepted = (current_state in self.accept_states)

        if not input_string:
            # Empty string: accepted only if start state is accepting
            is_accepted = (self.start_state in self.accept_states)
            message = (
                f"Empty string ε: Start state '{self.start_state}' is accepting."
                if is_accepted
                else f"Empty string ε: Start state '{self.start_state}' is not accepting."
            )
        elif is_accepted:
            message = f"String '{input_string}' ACCEPTED — reached accepting state '{current_state}'."
        elif current_state == self.DEAD_STATE:
            message = f"String '{input_string}' REJECTED — reached DEAD trap state."
        else:
            message = (
                f"String '{input_string}' REJECTED — stopped at non-accepting state '{current_state}'."
            )

        return {
            "success": True,
            "input_string": input_string,
            "is_accepted": is_accepted,
            "status": "ACCEPTED" if is_accepted else "REJECTED",
            "final_state": current_state,
            "state_path": state_path,
            "transitions": transitions_log,
            "message": message,
            "warnings": warnings,
            "states": self.states,
            "alphabet": self.alphabet,
            "start_state": self.start_state,
            "accept_states": self.accept_states,
        }
