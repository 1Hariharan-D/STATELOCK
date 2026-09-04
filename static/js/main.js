/**
 * StateLock - Multi-User Authentication, Passcode Management,
 * DFA Transition Visualizer & Advanced Security System
 * Theory of Computation Project
 */

document.addEventListener('DOMContentLoaded', () => {
    // Mode Switcher Elements
    const tabLogin = document.getElementById('tab-login');
    const tabRegister = document.getElementById('tab-register');
    const tabDemo = document.getElementById('tab-demo');

    // Form & Input Elements
    const authForm = document.getElementById('auth-form');
    const usernameGroup = document.getElementById('username-group');
    const usernameInput = document.getElementById('username-input');
    const sequenceInput = document.getElementById('sequence-input');
    const clearInputBtn = document.getElementById('clear-input-btn');
    const submitBtn = document.getElementById('submit-btn');
    const resetBtn = document.getElementById('reset-btn');
    const inputValidationMsg = document.getElementById('input-validation-msg');
    const quickTestSection = document.getElementById('quick-test-section');
    const presetButtons = document.querySelectorAll('.preset-btn');
    const passcodeLabel = document.getElementById('passcode-label');

    // Security Elements
    const failedAttemptsBadge = document.getElementById('failed-attempts-badge');
    const failedAttemptsCounter = document.getElementById('failed-attempts-counter');
    const lockoutBanner = document.getElementById('lockout-banner');
    const lockoutTimerVal = document.getElementById('lockout-timer-val');

    // User Session Header Elements
    const loggedOutView = document.getElementById('logged-out-view');
    const loggedInView = document.getElementById('loggedInView') || document.getElementById('logged-in-view');
    const sessionUsername = document.getElementById('session-username');
    const navHistoryBtn = document.getElementById('nav-history-btn');
    const navChangePasscodeBtn = document.getElementById('nav-change-passcode-btn');
    const navLogoutBtn = document.getElementById('nav-logout-btn');

    // Panels
    const diagramPanel = document.getElementById('diagram-panel');
    const historyPanel = document.getElementById('history-panel');
    const historyUserLabel = document.getElementById('history-user-label');
    const closeHistoryBtn = document.getElementById('close-history-btn');
    const historyTableBody = document.getElementById('history-table-body');
    const historyReplayBanner = document.getElementById('history-replay-banner');
    const historyReplayText = document.getElementById('history-replay-text');
    const backToHistoryBtn = document.getElementById('back-to-history-btn');

    // Change Passcode Form Elements
    const changePasscodePanel = document.getElementById('change-passcode-panel');
    const changePasscodeForm = document.getElementById('change-passcode-form');
    const currPasscodeInput = document.getElementById('curr-passcode-input');
    const newPasscodeInput = document.getElementById('new-passcode-input');
    const confirmPasscodeInput = document.getElementById('confirm-passcode-input');
    const savePasscodeBtn = document.getElementById('save-passcode-btn');
    const changePasscodeMsg = document.getElementById('change-passcode-msg');
    const closeChangePasscodeBtn = document.getElementById('close-change-passcode-btn');

    // UI Cards
    const resultsCard = document.getElementById('results-card');
    const idleCard = document.getElementById('idle-card');
    const statusBanner = document.getElementById('status-banner');
    const statusIcon = document.getElementById('status-icon');
    const statusTitle = document.getElementById('status-title');
    const statusMessage = document.getElementById('status-message');
    const finalStateBadge = document.getElementById('final-state-badge');
    const statePathTrail = document.getElementById('state-path-trail');
    const transitionsTableBody = document.getElementById('transitions-table-body');

    // Animation HUD & Controls
    const animationHud = document.getElementById('animation-hud');
    const symbolStream = document.getElementById('symbol-stream');
    const hudCurrentState = document.getElementById('hud-current-state');
    const hudStepCount = document.getElementById('hud-step-count');
    const animPlayBtn = document.getElementById('anim-play-btn');
    const animPauseBtn = document.getElementById('anim-pause-btn');
    const animStepBtn = document.getElementById('anim-step-btn');
    const animReplayBtn = document.getElementById('anim-replay-btn');
    const animResetBtn = document.getElementById('anim-reset-btn');

    // Regex
    const ALLOWED_CHARS_REGEX = /^[0-9a-zA-Z@#$%*!]+$/;
    const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,24}$/;

    // State Variables
    let currentMode = 'login';
    let currentUser = null;
    let cachedHistoryRecords = [];
    let lockoutTimerInterval = null;
    let lockoutRemainingSeconds = 0;

    // =========================================================================
    // SECURITY HELPERS: FAILED ATTEMPTS & COUNTDOWN TIMER
    // =========================================================================

    function updateFailedAttemptsDisplay(count, max = 5) {
        if (!failedAttemptsBadge || !failedAttemptsCounter) return;
        if (currentMode !== 'login' || count === undefined || count === null || count <= 0) {
            failedAttemptsBadge.style.display = 'none';
            return;
        }
        failedAttemptsBadge.style.display = 'flex';
        failedAttemptsCounter.textContent = `${count}/${max} failed`;
        failedAttemptsCounter.className = 'failed-attempts-pill';
        if (count >= 5) {
            failedAttemptsCounter.classList.add('danger');
        } else if (count >= 3) {
            failedAttemptsCounter.classList.add('warning');
        }
    }

    function startLockoutCountdown(seconds) {
        if (lockoutTimerInterval) clearInterval(lockoutTimerInterval);
        lockoutRemainingSeconds = Math.max(1, parseInt(seconds, 10) || 60);

        if (lockoutBanner && lockoutTimerVal) {
            lockoutBanner.style.display = 'flex';
            lockoutTimerVal.textContent = `${lockoutRemainingSeconds}s`;
        }
        
        submitBtn.disabled = true;
        sequenceInput.disabled = true;

        lockoutTimerInterval = setInterval(() => {
            lockoutRemainingSeconds -= 1;
            if (lockoutRemainingSeconds > 0) {
                if (lockoutTimerVal) lockoutTimerVal.textContent = `${lockoutRemainingSeconds}s`;
            } else {
                clearLockoutCountdown();
                showValidationSuccess('Lockout ended. You may now authenticate again.');
                updateFailedAttemptsDisplay(0);
                // Verify status with server
                const username = usernameInput.value.trim();
                if (username) checkUsernameLockoutStatus(username);
            }
        }, 1000);
    }

    function clearLockoutCountdown() {
        if (lockoutTimerInterval) {
            clearInterval(lockoutTimerInterval);
            lockoutTimerInterval = null;
        }
        lockoutRemainingSeconds = 0;
        if (lockoutBanner) lockoutBanner.style.display = 'none';
        submitBtn.disabled = false;
        sequenceInput.disabled = false;
    }

    async function checkUsernameLockoutStatus(username) {
        if (!username || currentMode !== 'login') return;
        try {
            const res = await fetch(`/api/lockout-status?username=${encodeURIComponent(username)}`);
            const data = await res.json();
            if (data.is_locked && data.lockout_remaining > 0) {
                startLockoutCountdown(data.lockout_remaining);
                updateFailedAttemptsDisplay(data.failed_attempts || 5, data.max_attempts || 5);
            } else {
                clearLockoutCountdown();
                if (data.failed_attempts > 0) {
                    updateFailedAttemptsDisplay(data.failed_attempts, data.max_attempts || 5);
                } else {
                    updateFailedAttemptsDisplay(0);
                }
            }
        } catch (e) {
            // Ignore background check failure silently
        }
    }

    // =========================================================================
    // DFA ANIMATION CONTROLLER
    // =========================================================================
    class DFAAnimationPlayer {
        constructor() {
            this.data = null;
            this.totalSteps = 0;
            this.currentStep = 0;
            this.isPlaying = false;
            this.timerId = null;
            this.stepDuration = 700; // ms per step
        }

        load(data) {
            this.pause();
            this.data = data;
            this.totalSteps = data.transitions ? data.transitions.length : 0;
            this.currentStep = 0;

            // Make sure diagram is visible
            showDiagramView();
            idleCard.style.display = 'none';
            animationHud.style.display = 'flex';
            resultsCard.style.display = 'none';

            // 1. Build Stream Characters
            symbolStream.innerHTML = '';
            const chars = data.input_sequence ? data.input_sequence.split('') : [];
            chars.forEach((char, idx) => {
                const charBox = document.createElement('span');
                charBox.className = 'stream-char';
                charBox.id = `stream-char-${idx}`;
                charBox.textContent = char;
                symbolStream.appendChild(charBox);
            });

            // 2. Pre-populate full transitions table
            transitionsTableBody.innerHTML = '';
            if (data.transitions && data.transitions.length > 0) {
                data.transitions.forEach((tr, idx) => {
                    const row = document.createElement('tr');
                    row.id = `trans-row-${idx}`;
                    const isValid = tr.is_valid;
                    row.innerHTML = `
                        <td><strong>#${tr.step}</strong></td>
                        <td><code>${tr.from_state}</code></td>
                        <td><span class="path-symbol">${tr.symbol}</span></td>
                        <td><code>${tr.to_state}</code></td>
                        <td>
                            <span class="status-chip ${isValid ? 'valid' : 'trap'}">
                                ${isValid ? '✓ Valid' : '✗ Trap (DEAD)'}
                            </span>
                        </td>
                    `;
                    transitionsTableBody.appendChild(row);
                });
            } else {
                const emptyRow = document.createElement('tr');
                emptyRow.innerHTML = `<td colspan="5" style="text-align: center; color: var(--text-dim);">No transitions executed.</td>`;
                transitionsTableBody.appendChild(emptyRow);
            }

            // Render step 0 and start playback
            this.renderStep(0);
            this.play();
        }

        renderStep(stepIndex) {
            this.currentStep = stepIndex;
            if (!this.data) return;

            const statePath = this.data.state_path || ['q0'];
            const transitions = this.data.transitions || [];
            const isAccepted = this.data.is_accepted;
            const currentState = statePath[stepIndex] || 'q0';

            // Update HUD
            hudCurrentState.textContent = currentState;
            hudCurrentState.className = `hud-state-pill ${
                currentState === 'DEAD' ? 'dead' : 
                (currentState === 'q4' && isAccepted && stepIndex === this.totalSteps ? 'accepted' : '')
            }`;
            hudStepCount.textContent = `Step ${stepIndex} / ${this.totalSteps}`;

            // Update Stream Character Boxes
            const chars = this.data.input_sequence ? this.data.input_sequence.split('') : [];
            chars.forEach((_, idx) => {
                const charEl = document.getElementById(`stream-char-${idx}`);
                if (charEl) {
                    charEl.className = 'stream-char';
                    if (idx < stepIndex) {
                        const tr = transitions[idx];
                        if (tr && !tr.is_valid) {
                            charEl.classList.add('error');
                        } else {
                            charEl.classList.add('passed');
                        }
                    } else if (idx === stepIndex && stepIndex < this.totalSteps) {
                        charEl.classList.add('active');
                    }
                }
            });

            // Update SVG Diagram
            resetDiagramHighlights();

            // Visited nodes
            for (let i = 0; i <= stepIndex; i++) {
                const st = statePath[i];
                const nodeEl = document.getElementById(`node-${st}`);
                if (nodeEl) {
                    if (st === 'DEAD') {
                        nodeEl.classList.add('dead-highlight');
                    } else if (st === 'q4' && isAccepted && i === this.totalSteps) {
                        nodeEl.classList.add('accepted');
                    } else if (i === stepIndex) {
                        nodeEl.classList.add('current-step');
                    } else {
                        nodeEl.classList.add('active');
                    }
                }
            }

            // Traversed edges
            for (let i = 0; i < stepIndex; i++) {
                const tr = transitions[i];
                if (tr) {
                    const from = tr.from_state;
                    const to = tr.to_state;
                    const edgeEl = document.getElementById(`edge-${from}-${to}`);
                    const boxEl = document.getElementById(`edge-box-${from}-${to}`);

                    if (edgeEl) {
                        if (to === 'DEAD') {
                            edgeEl.classList.add('dead-active-edge');
                        } else if (to === 'q4' && isAccepted && i === this.totalSteps - 1) {
                            edgeEl.classList.add('accept-edge');
                        } else {
                            edgeEl.classList.add('active-edge');
                        }
                    }

                    if (boxEl && to !== 'DEAD') {
                        boxEl.classList.add('active-label-bg');
                    }
                }
            }

            // Update Transitions Table
            document.querySelectorAll('.transitions-table tr').forEach(row => {
                row.classList.remove('active-row', 'error-row');
            });

            if (stepIndex > 0) {
                const activeRow = document.getElementById(`trans-row-${stepIndex - 1}`);
                if (activeRow) {
                    const lastTr = transitions[stepIndex - 1];
                    if (lastTr && !lastTr.is_valid) {
                        activeRow.classList.add('error-row');
                    } else {
                        activeRow.classList.add('active-row');
                    }
                    activeRow.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }
            }

            // Update Path Trail
            statePathTrail.innerHTML = '';
            for (let i = 0; i <= stepIndex; i++) {
                const st = statePath[i];
                const chip = document.createElement('span');
                chip.className = `path-node ${
                    st === 'q0' ? 'start' : ''
                } ${
                    st === 'DEAD' ? 'dead' : ''
                } ${
                    st === 'q4' && isAccepted && i === this.totalSteps ? 'accept' : ''
                } ${
                    i === stepIndex ? 'active-now' : ''
                }`;
                chip.textContent = st;
                statePathTrail.appendChild(chip);

                if (i < stepIndex && i < transitions.length) {
                    const tr = transitions[i];
                    const arrowSpan = document.createElement('span');
                    arrowSpan.className = 'path-arrow';
                    arrowSpan.innerHTML = `➔ <span class="path-symbol">${tr.symbol}</span> ➔`;
                    statePathTrail.appendChild(arrowSpan);
                }
            }

            // Final Step Reached
            if (stepIndex >= this.totalSteps) {
                this.pause();
                resultsCard.style.display = 'flex';

                statusBanner.className = `status-banner ${isAccepted ? 'granted' : 'denied'}`;
                statusIcon.textContent = isAccepted ? '🔓' : '🔒';
                statusTitle.textContent = this.data.status || (isAccepted ? 'ACCESS GRANTED' : 'ACCESS DENIED');
                statusMessage.textContent = this.data.message || '';

                finalStateBadge.className = `state-badge ${isAccepted ? 'granted' : 'denied'}`;
                finalStateBadge.textContent = `Final State: ${this.data.final_state || currentState}`;

                animStepBtn.disabled = true;

                // If login was successful, update session status
                if (isAccepted && this.data.user) {
                    updateUserSession(this.data.user);
                }
            } else {
                animStepBtn.disabled = false;
            }
        }

        play() {
            if (!this.data) return;
            if (this.currentStep >= this.totalSteps) {
                this.currentStep = 0;
                this.renderStep(0);
            }
            this.isPlaying = true;
            animPlayBtn.classList.add('active-play');
            animPauseBtn.classList.remove('active-play');
            this.scheduleNextStep();
        }

        scheduleNextStep() {
            if (this.timerId) clearTimeout(this.timerId);
            if (!this.isPlaying) return;

            if (this.currentStep < this.totalSteps) {
                this.timerId = setTimeout(() => {
                    if (this.isPlaying) {
                        this.renderStep(this.currentStep + 1);
                        if (this.currentStep < this.totalSteps) {
                            this.scheduleNextStep();
                        } else {
                            this.isPlaying = false;
                            animPlayBtn.classList.remove('active-play');
                        }
                    }
                }, this.stepDuration);
            } else {
                this.isPlaying = false;
                animPlayBtn.classList.remove('active-play');
            }
        }

        pause() {
            this.isPlaying = false;
            if (this.timerId) clearTimeout(this.timerId);
            animPlayBtn.classList.remove('active-play');
            animPauseBtn.classList.add('active-play');
            setTimeout(() => animPauseBtn.classList.remove('active-play'), 400);
        }

        step() {
            this.pause();
            if (!this.data) return;
            if (this.currentStep < this.totalSteps) {
                this.renderStep(this.currentStep + 1);
            }
        }

        replay() {
            this.pause();
            if (!this.data) return;
            this.renderStep(0);
            this.play();
        }

        reset() {
            this.pause();
            this.data = null;
            this.currentStep = 0;
            this.totalSteps = 0;

            animationHud.style.display = 'none';
            resultsCard.style.display = 'none';
            idleCard.style.display = 'flex';
            historyReplayBanner.style.display = 'none';

            resetDiagramHighlights();
            animPlayBtn.classList.remove('active-play');
            animPauseBtn.classList.remove('active-play');
            animStepBtn.disabled = false;
        }
    }

    const player = new DFAAnimationPlayer();

    // =========================================================================
    // UI VIEW & MODE CONTROLLERS
    // =========================================================================
    function setMode(mode) {
        currentMode = mode;
        clearValidation();
        player.reset();

        tabLogin.classList.toggle('active', mode === 'login');
        tabRegister.classList.toggle('active', mode === 'register');
        tabDemo.classList.toggle('active', mode === 'demo');

        if (mode === 'login') {
            usernameGroup.style.display = 'flex';
            passcodeLabel.textContent = '4-Character Passcode';
            sequenceInput.placeholder = '••••';
            submitBtn.textContent = 'Authenticate & Login';
            quickTestSection.style.display = 'none';
            
            // Check lockout for current username if typed
            const username = usernameInput.value.trim();
            if (username) checkUsernameLockoutStatus(username);
            else updateFailedAttemptsDisplay(0);

        } else if (mode === 'register') {
            usernameGroup.style.display = 'flex';
            passcodeLabel.textContent = 'Choose 4-Char Passcode';
            sequenceInput.placeholder = 'e.g. K@79';
            submitBtn.textContent = 'Register Account';
            quickTestSection.style.display = 'none';
            clearLockoutCountdown();
            updateFailedAttemptsDisplay(0);

        } else if (mode === 'demo') {
            usernameGroup.style.display = 'none';
            passcodeLabel.textContent = 'Enter 4-Character Passcode';
            sequenceInput.placeholder = '••••';
            sequenceInput.value = '';
            submitBtn.textContent = 'Verify Demo Sequence';
            quickTestSection.style.display = 'flex';
            clearLockoutCountdown();
            updateFailedAttemptsDisplay(0);
        }

        sequenceInput.focus();
    }

    function showDiagramView() {
        diagramPanel.style.display = 'flex';
        historyPanel.style.display = 'none';
        changePasscodePanel.style.display = 'none';
    }

    function showHistoryView() {
        diagramPanel.style.display = 'none';
        historyPanel.style.display = 'flex';
        changePasscodePanel.style.display = 'none';
        historyReplayBanner.style.display = 'none';
        loadUserHistory();
    }

    function showChangePasscodeView() {
        diagramPanel.style.display = 'none';
        historyPanel.style.display = 'none';
        changePasscodePanel.style.display = 'flex';
        historyReplayBanner.style.display = 'none';
        currPasscodeInput.value = '';
        newPasscodeInput.value = '';
        confirmPasscodeInput.value = '';
        changePasscodeMsg.textContent = '';
        changePasscodeMsg.className = 'validation-msg';
        currPasscodeInput.focus();
    }

    function clearValidation() {
        inputValidationMsg.textContent = '';
        inputValidationMsg.className = 'validation-msg';
    }

    function showValidationError(message) {
        inputValidationMsg.textContent = message;
        inputValidationMsg.className = 'validation-msg';
    }

    function showValidationSuccess(message, isHtml = false) {
        if (isHtml) {
            inputValidationMsg.innerHTML = message;
        } else {
            inputValidationMsg.textContent = message;
        }
        inputValidationMsg.className = 'validation-msg success-msg';
    }

    function resetDiagramHighlights() {
        document.querySelectorAll('.state-node').forEach(node => {
            node.classList.remove('active', 'accepted', 'dead-highlight', 'current-step');
        });
        document.querySelectorAll('.transition-edge').forEach(edge => {
            edge.classList.remove('active-edge', 'accept-edge', 'dead-active-edge');
        });
        document.querySelectorAll('.label-bg').forEach(box => {
            box.classList.remove('active-label-bg');
        });
    }

    // =========================================================================
    // USER SESSION & AUTH LOGIC
    // =========================================================================
    async function checkSessionStatus() {
        try {
            const res = await fetch('/api/user-status', { cache: 'no-store' });
            const data = await res.json();
            if (data.logged_in) {
                updateUserSession({ username: data.username, id: data.user_id });
                return true;
            } else {
                clearUserSession();
                return false;
            }
        } catch (e) {
            clearUserSession();
            return false;
        }
    }

    function updateUserSession(user) {
        currentUser = user;
        loggedOutView.style.display = 'none';
        loggedInView.style.display = 'flex';
        sessionUsername.textContent = user.username;
        historyUserLabel.textContent = user.username;
        clearLockoutCountdown();
        updateFailedAttemptsDisplay(0);
        // Show logged-in dashboard card with username
        const dashEl = document.getElementById('logged-in-dashboard');
        const dashUsername = document.getElementById('dash-username');
        if (dashEl) dashEl.style.display = 'block';
        if (dashUsername) dashUsername.textContent = user.username;
    }

    function clearUserSession() {
        currentUser = null;
        loggedOutView.style.display = 'flex';
        loggedInView.style.display = 'none';
        // Hide logged-in dashboard card
        const dashEl = document.getElementById('logged-in-dashboard');
        if (dashEl) dashEl.style.display = 'none';
        showDiagramView();
    }

    async function handleLogout() {
        try {
            await fetch('/api/logout', { method: 'POST', cache: 'no-store' });
            clearUserSession();
            setMode('login');
            showValidationSuccess('Logged out successfully.');
        } catch (e) {
            clearUserSession();
            setMode('login');
        }
    }

    async function loadUserHistory() {
        historyTableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-dim);">Loading history records...</td></tr>`;
        try {
            const res = await fetch('/api/history', { cache: 'no-store' });
            const data = await res.json();
            if (data.success && data.history) {
                cachedHistoryRecords = data.history;
                historyTableBody.innerHTML = '';
                if (data.history.length === 0) {
                    historyTableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-dim); padding: 20px;">No authentication or security events recorded yet.</td></tr>`;
                    return;
                }
                data.history.forEach((rec, idx) => {
                    const row = document.createElement('tr');
                    row.className = 'clickable-row';
                    const isSuccess = rec.status === 'ACCESS GRANTED' || rec.status === 'SUCCESS';
                    const isLocked = rec.status === 'ACCOUNT LOCKED' || rec.event_type === 'Account locked';
                    const isUnlocked = rec.status === 'LOCKOUT ENDED' || rec.event_type === 'Lockout ended';
                    const inputStr = rec.input_sequence || '••••';

                    // Determine event badge
                    let eventBadgeHtml = '';
                    if (isLocked) {
                        eventBadgeHtml = `<span class="event-tag account-locked">⏳ Account Locked</span>`;
                    } else if (isUnlocked) {
                        eventBadgeHtml = `<span class="event-tag lockout-ended">🔓 Lockout Ended</span>`;
                    } else if (isSuccess) {
                        eventBadgeHtml = `<span class="event-tag login-success">✓ Successful Login</span>`;
                    } else {
                        eventBadgeHtml = `<span class="event-tag login-failed">✗ Failed Login</span>`;
                    }

                    // Determine status badge
                    let statusBadgeHtml = '';
                    if (isSuccess) {
                        statusBadgeHtml = `<span class="history-tag success">✓ GRANTED</span>`;
                    } else if (isLocked) {
                        statusBadgeHtml = `<span class="history-tag failed">⏳ LOCKED</span>`;
                    } else if (isUnlocked) {
                        statusBadgeHtml = `<span class="history-tag success">🔓 UNLOCKED</span>`;
                    } else {
                        statusBadgeHtml = `<span class="history-tag failed">✗ DENIED</span>`;
                    }

                    row.innerHTML = `
                        <td><strong>#${rec.id}</strong></td>
                        <td>${rec.timestamp}</td>
                        <td>${eventBadgeHtml}</td>
                        <td><span class="input-chip">${inputStr}</span></td>
                        <td>${statusBadgeHtml}</td>
                        <td><code>${rec.final_state}</code></td>
                        <td>${rec.state_path}</td>
                        <td>
                            <button type="button" class="inspect-btn view-details-btn" data-index="${idx}">
                                🔍 View Details
                            </button>
                        </td>
                    `;

                    // Clicking row or button inspects this historical record
                    row.addEventListener('click', () => {
                        inspectHistoryRecord(rec);
                    });

                    historyTableBody.appendChild(row);
                });
            } else {
                historyTableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #f87171;">${data.error || 'Failed to load history.'}</td></tr>`;
            }
        } catch (err) {
            historyTableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #f87171;">Unable to connect to server.</td></tr>`;
        }
    }

    /**
     * Inspects and replays an exact historical DFA transition record
     */
    function inspectHistoryRecord(record) {
        showDiagramView();
        historyReplayBanner.style.display = 'flex';
        historyReplayText.textContent = `📜 Viewing Historical Attempt #${record.id} (Input: ${record.input_sequence || '••••'})`;

        const isAccepted = record.status === 'ACCESS GRANTED' || record.status === 'SUCCESS';
        
        // Parse state path from string if needed
        let statePath = [];
        if (record.state_path) {
            statePath = record.state_path.split(' ➔ ').map(s => s.trim());
        }

        const replayPayload = {
            input_sequence: record.input_sequence || '',
            state_path: statePath.length > 0 ? statePath : ['q0'],
            transitions: record.transitions || [],
            is_accepted: isAccepted,
            status: record.status || (isAccepted ? 'ACCESS GRANTED' : 'ACCESS DENIED'),
            final_state: record.final_state || 'q0',
            message: `Historical record #${record.id} (${record.timestamp}) - Event: ${record.event_type || record.status}`
        };

        player.load(replayPayload);

        // Smooth scroll to DFA results panel
        const resultsCard = document.getElementById('results-card');
        if (resultsCard) {
            setTimeout(() => resultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' }), 300);
        }
    }

    // =========================================================================
    // SUBMISSION HANDLERS
    // =========================================================================
    async function handleFormSubmit() {
        clearValidation();
        historyReplayBanner.style.display = 'none';

        const username = usernameInput.value.trim();
        const passcode = sequenceInput.value.trim();

        // 1. REGISTER MODE
        if (currentMode === 'register') {
            if (!username) {
                showValidationError('Please enter a username.');
                usernameInput.focus();
                return;
            }
            if (!USERNAME_REGEX.test(username)) {
                showValidationError('Username must be 3-24 characters (letters, numbers, underscores, hyphens).');
                usernameInput.focus();
                return;
            }
            if (passcode.length !== 4) {
                showValidationError('Passcode must be exactly 4 characters.');
                sequenceInput.focus();
                return;
            }
            if (!ALLOWED_CHARS_REGEX.test(passcode)) {
                showValidationError('Passcode can only contain 0-9, a-z, A-Z, and @ # $ % * !');
                sequenceInput.focus();
                return;
            }

            try {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Registering...';

                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, passcode })
                });

                const result = await response.json();

                if (result.success) {
                    showValidationSuccess(`Account '${username}' registered! Please log in now.`);
                    tabLogin.click();
                    usernameInput.value = username;
                    sequenceInput.value = '';
                    sequenceInput.focus();
                } else {
                    showValidationError(result.error || 'Registration failed.');
                }
            } catch (err) {
                showValidationError('Server error occurred during registration.');
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Register Account';
            }
            return;
        }

        // 2. LOGIN MODE
        if (currentMode === 'login') {
            if (!username) {
                showValidationError('Please enter your username.');
                usernameInput.focus();
                return;
            }
            if (!passcode) {
                showValidationError('Please enter your 4-character passcode.');
                sequenceInput.focus();
                return;
            }
            if (passcode.length !== 4) {
                showValidationError('Passcode must be exactly 4 characters.');
                sequenceInput.focus();
                return;
            }

            try {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Authenticating (DFA)...';

                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, passcode })
                });

                const data = await response.json();

                // Check for 403 Forbidden / Account Locked
                if (response.status === 403 || data.is_locked) {
                    startLockoutCountdown(data.lockout_remaining || 60);
                    updateFailedAttemptsDisplay(data.failed_attempts || 5, data.max_attempts || 5);
                    showValidationError(data.error || data.message || 'Account temporarily locked.');
                    if (data.transitions && data.transitions.length > 0) {
                        player.load(data);
                    }
                    return;
                }

                // If authentication succeeded
                if (data.is_accepted) {
                    clearLockoutCountdown();
                    updateFailedAttemptsDisplay(0);
                    if (data.user) updateUserSession(data.user);
                    player.load(data);
                    showValidationSuccess(`Access Granted! Reached accepting state q4. <a href="/dashboard" style="color: var(--gold-bright); text-decoration: underline; font-weight: 700; margin-left: 6px;">Open Dashboard →</a>`, true);
                } else {
                    // Failed authentication
                    if (data.is_locked) {
                        startLockoutCountdown(data.lockout_remaining || 60);
                        updateFailedAttemptsDisplay(data.failed_attempts || 5, data.max_attempts || 5);
                    } else {
                        updateFailedAttemptsDisplay(data.failed_attempts || 1, data.max_attempts || 5);
                    }
                    player.load(data);
                }
            } catch (err) {
                showValidationError('Unable to reach authentication server.');
            } finally {
                if (lockoutRemainingSeconds <= 0) {
                    submitBtn.disabled = false;
                }
                submitBtn.textContent = 'Authenticate (DFA)';
            }
            return;
        }

        // 3. DEMO MODE
        if (currentMode === 'demo') {
            if (!passcode) {
                showValidationError('Please enter a sequence to verify.');
                return;
            }
            if (!ALLOWED_CHARS_REGEX.test(passcode)) {
                showValidationError('Only 0-9, a-z, A-Z, and @ # $ % * ! are allowed.');
                return;
            }

            try {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Verifying...';

                const response = await fetch('/api/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sequence: passcode })
                });

                const data = await response.json();
                player.load(data);
            } catch (err) {
                showValidationError('Unable to verify sequence with server.');
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'Verify Demo Sequence';
            }
        }
    }

    // =========================================================================
    // CHANGE PASSCODE HANDLER
    // =========================================================================
    async function handleChangePasscodeSubmit() {
        changePasscodeMsg.textContent = '';
        changePasscodeMsg.className = 'validation-msg';

        const current_passcode = currPasscodeInput.value.trim();
        const new_passcode = newPasscodeInput.value.trim();
        const confirm_passcode = confirmPasscodeInput.value.trim();

        if (!current_passcode) {
            changePasscodeMsg.textContent = 'Please enter your current passcode.';
            currPasscodeInput.focus();
            return;
        }
        if (new_passcode.length !== 4) {
            changePasscodeMsg.textContent = 'New passcode must be exactly 4 characters.';
            newPasscodeInput.focus();
            return;
        }
        if (!ALLOWED_CHARS_REGEX.test(new_passcode)) {
            changePasscodeMsg.textContent = 'New passcode can only contain 0-9, a-z, A-Z, and @ # $ % * !';
            newPasscodeInput.focus();
            return;
        }
        if (new_passcode !== confirm_passcode) {
            changePasscodeMsg.textContent = 'New passcode and confirmation do not match.';
            confirmPasscodeInput.focus();
            return;
        }

        try {
            savePasscodeBtn.disabled = true;
            savePasscodeBtn.textContent = 'Updating...';

            const res = await fetch('/api/change-passcode', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ current_passcode, new_passcode, confirm_passcode })
            });
            const data = await res.json();

            if (data.success) {
                changePasscodeMsg.className = 'validation-msg success-msg';
                changePasscodeMsg.textContent = data.message || 'Passcode updated successfully!';
                setTimeout(() => {
                    showDiagramView();
                    showValidationSuccess('Passcode updated successfully! You can now authenticate with your new passcode.');
                }, 1200);
            } else {
                changePasscodeMsg.textContent = data.error || 'Failed to update passcode.';
            }
        } catch (e) {
            changePasscodeMsg.textContent = 'Server communication error.';
        } finally {
            savePasscodeBtn.disabled = false;
            savePasscodeBtn.textContent = 'Update Passcode';
        }
    }

    function resetAll() {
        sequenceInput.value = '';
        clearValidation();
        player.reset();
        sequenceInput.focus();
    }

    // =========================================================================
    // EVENT LISTENERS
    // =========================================================================

    // Mode Switcher Tabs
    tabLogin.addEventListener('click', () => setMode('login'));
    tabRegister.addEventListener('click', () => setMode('register'));
    tabDemo.addEventListener('click', () => setMode('demo'));

    // Form Submissions
    authForm.addEventListener('submit', (e) => {
        e.preventDefault();
        handleFormSubmit();
    });
    submitBtn.addEventListener('click', handleFormSubmit);
    resetBtn.addEventListener('click', resetAll);

    // Clear input button
    clearInputBtn.addEventListener('click', () => {
        sequenceInput.value = '';
        clearValidation();
        sequenceInput.focus();
    });

    // Strip whitespace and monitor input
    sequenceInput.addEventListener('input', () => {
        clearValidation();
        if (sequenceInput.value.includes(' ')) {
            sequenceInput.value = sequenceInput.value.replace(/\s/g, '');
        }
    });

    // When username changes in login mode, check lockout status
    usernameInput.addEventListener('blur', () => {
        if (currentMode === 'login') {
            const username = usernameInput.value.trim();
            if (username) checkUsernameLockoutStatus(username);
        }
    });

    // Preset buttons (in demo mode)
    presetButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const seq = btn.getAttribute('data-seq');
            sequenceInput.value = seq;
            handleFormSubmit();
        });
    });

    // Header Session Navigation
    // navHistoryBtn is now an <a href="/history"> anchor — no JS listener needed.
    navChangePasscodeBtn.addEventListener('click', showChangePasscodeView);
    navLogoutBtn.addEventListener('click', handleLogout);
    closeHistoryBtn.addEventListener('click', showDiagramView);
    closeChangePasscodeBtn.addEventListener('click', showDiagramView);
    backToHistoryBtn.addEventListener('click', showHistoryView);

    // Dashboard card buttons
    const dashHistoryBtn = document.getElementById('dash-history-btn');
    const dashChangePasscodeBtn = document.getElementById('dash-change-passcode-btn');
    if (dashHistoryBtn) dashHistoryBtn.addEventListener('click', showHistoryView);
    if (dashChangePasscodeBtn) dashChangePasscodeBtn.addEventListener('click', showChangePasscodeView);

    // Change passcode form
    changePasscodeForm.addEventListener('submit', (e) => {
        e.preventDefault();
        handleChangePasscodeSubmit();
    });
    savePasscodeBtn.addEventListener('click', handleChangePasscodeSubmit);

    // Animation Controls
    animPlayBtn.addEventListener('click', () => player.play());
    animPauseBtn.addEventListener('click', () => player.pause());
    animStepBtn.addEventListener('click', () => player.step());
    animReplayBtn.addEventListener('click', () => player.replay());
    animResetBtn.addEventListener('click', resetAll);

    // =========================================================================
    // PAGE INITIALISATION
    // =========================================================================
    // Run session check first, then decide which view to show.
    (async () => {
        const isLoggedIn = await checkSessionStatus();
        setMode('login');

        const bodyData = document.body.dataset;
        if (bodyData.openHistory === 'true') {
            if (isLoggedIn) {
                showHistoryView();
            } else {
                // Not authenticated — show login form with a helpful message
                showValidationError('Please log in to view your Authentication History.');
            }
        } else if (bodyData.unauthorizedHistory === 'true') {
            showValidationError('Please log in to view your Authentication History.');
        } else if (bodyData.unauthorizedDashboard === 'true') {
            showValidationError('Please log in to access your Analytics Dashboard.');
        }
    })();

    // Browser back button & tab visibility security hooks
    window.addEventListener('pageshow', () => { checkSessionStatus(); });
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') checkSessionStatus();
    });
});
