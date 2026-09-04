/**
 * StateLock – DFA Playground Controller (playground.js)
 * Interactive DFA Builder & Simulator
 *
 * Enhanced & Fixed:
 *  - 100% Visible, high-contrast dropdowns with gold accents & dark options
 *  - Responsive SVG Diagram layout fitting completely inside container (no clipping, auto-scaling)
 *  - Color-accurate String Simulator:
 *      * Green = valid/successful transitions
 *      * Red = actual invalid/failed transitions (trap/DEAD)
 *      * If rejected only because final state is non-accepting, valid transitions stay green
 *        and only the final state & verdict are displayed as RED.
 *  - Play, Pause, Step, Replay, Reset animation controls
 *  - Independent from user authentication & database history
 */
document.addEventListener('DOMContentLoaded', () => {

    // =========================================================================
    // STATE
    // =========================================================================
    let dfa = {
        states:       [],   // [{name, isStart, isAccept}]
        alphabet:     [],   // ['0','1',...]
        transitions:  [],   // [{from, symbol, to}]
    };

    // Keep track of any dynamic DEAD state reached in active simulation
    let activeSimulationDead = null;

    // =========================================================================
    // DOM REFERENCES
    // =========================================================================
    const alphabetInput   = document.getElementById('alphabet-input');
    const alphabetAddBtn  = document.getElementById('alphabet-add-btn');
    const alphabetChips   = document.getElementById('alphabet-chips');
    const quickSetBtns    = document.querySelectorAll('.quick-set-btn');

    const stateInput      = document.getElementById('state-input');
    const stateAddBtn     = document.getElementById('state-add-btn');
    const statesList      = document.getElementById('states-list');

    const trFrom          = document.getElementById('tr-from');
    const trSymbol        = document.getElementById('tr-symbol');
    const trTo            = document.getElementById('tr-to');
    const trAddBtn        = document.getElementById('tr-add-btn');
    const transitionsList = document.getElementById('transitions-list');

    const validationPanel = document.getElementById('validation-panel');
    const diagramIdle     = document.getElementById('diagram-idle');
    const dfaSvg          = document.getElementById('dfa-svg');
    const diagramWrap     = document.getElementById('diagram-wrap');
    const dfaStatsRow     = document.getElementById('dfa-stats-row');
    const tableWrap       = document.getElementById('transition-table-wrap');

    const pgStringInput   = document.getElementById('pg-string-input');
    const pgSimBtn        = document.getElementById('pg-sim-btn');
    const pgSimClearBtn   = document.getElementById('pg-sim-clear-btn');
    const quickStrBtns    = document.querySelectorAll('.quick-str-btn');
    const pgSimValidation = document.getElementById('pg-sim-validation');

    const pgAnimHud       = document.getElementById('pg-anim-hud');
    const pgSymbolStream  = document.getElementById('pg-symbol-stream');
    const pgHudState      = document.getElementById('pg-hud-state');
    const pgHudStep       = document.getElementById('pg-hud-step');
    const pgPlayBtn       = document.getElementById('pg-play-btn');
    const pgPauseBtn      = document.getElementById('pg-pause-btn');
    const pgStepBtn       = document.getElementById('pg-step-btn');
    const pgReplayBtn     = document.getElementById('pg-replay-btn');
    const pgResetBtn      = document.getElementById('pg-reset-btn');

    const pgResultsCard   = document.getElementById('pg-results-card');
    const pgStatusBanner  = document.getElementById('pg-status-banner');
    const pgStatusIcon    = document.getElementById('pg-status-icon');
    const pgStatusTitle   = document.getElementById('pg-status-title');
    const pgStatusMsg     = document.getElementById('pg-status-msg');
    const pgFinalBadge    = document.getElementById('pg-final-state-badge');
    const pgPathTrail     = document.getElementById('pg-path-trail');

    const pgBreakdownWrap = document.getElementById('pg-breakdown-wrap');
    const pgBreakdownBody = document.getElementById('pg-breakdown-tbody');
    const pgWarningsWrap  = document.getElementById('pg-warnings-wrap');
    const pgWarningsList  = document.getElementById('pg-warnings-list');

    const presetBtns      = document.querySelectorAll('.preset-dfa-btn');

    // =========================================================================
    // PRESETS
    // =========================================================================
    const DFA_PRESETS = {
        'user-spec': {
            label: 'Tutorial DFA',
            alphabet: ['0','1'],
            states: [
                { name:'q0', isStart:true,  isAccept:false },
                { name:'q1', isStart:false, isAccept:true  },
            ],
            transitions: [
                { from:'q0', symbol:'0', to:'q1' },
                { from:'q0', symbol:'1', to:'q0' },
                { from:'q1', symbol:'0', to:'q0' },
                { from:'q1', symbol:'1', to:'q1' },
            ],
        },
        'binary-ends-0': {
            label: 'Ends in 0',
            alphabet: ['0','1'],
            states: [
                { name:'q0', isStart:true,  isAccept:false },
                { name:'q1', isStart:false, isAccept:true  },
            ],
            transitions: [
                { from:'q0', symbol:'0', to:'q1' },
                { from:'q0', symbol:'1', to:'q0' },
                { from:'q1', symbol:'0', to:'q1' },
                { from:'q1', symbol:'1', to:'q0' },
            ],
        },
        'binary-even': {
            label: 'Even 1s',
            alphabet: ['0','1'],
            states: [
                { name:'even', isStart:true,  isAccept:true  },
                { name:'odd',  isStart:false, isAccept:false },
            ],
            transitions: [
                { from:'even', symbol:'0', to:'even' },
                { from:'even', symbol:'1', to:'odd'  },
                { from:'odd',  symbol:'0', to:'odd'  },
                { from:'odd',  symbol:'1', to:'even' },
            ],
        },
        'ab-lang': {
            label: "Starts 'ab'",
            alphabet: ['a','b'],
            states: [
                { name:'q0', isStart:true,  isAccept:false },
                { name:'q1', isStart:false, isAccept:false },
                { name:'q2', isStart:false, isAccept:true  },
                { name:'q3', isStart:false, isAccept:false },
            ],
            transitions: [
                { from:'q0', symbol:'a', to:'q1' },
                { from:'q0', symbol:'b', to:'q3' },
                { from:'q1', symbol:'a', to:'q3' },
                { from:'q1', symbol:'b', to:'q2' },
                { from:'q2', symbol:'a', to:'q2' },
                { from:'q2', symbol:'b', to:'q2' },
                { from:'q3', symbol:'a', to:'q3' },
                { from:'q3', symbol:'b', to:'q3' },
            ],
        },
    };

    // =========================================================================
    // ALPHABET MANAGEMENT
    // =========================================================================
    function addSymbol(sym) {
        sym = sym.trim();
        if (!sym) return;
        if (sym.length > 1) { showSimValidation('Symbol must be a single character.'); return; }
        if (dfa.alphabet.includes(sym)) return;
        dfa.alphabet.push(sym);
        renderAlphabet();
        rebuildTransitionSelects();
        renderDiagram();
        renderTable();
        runValidation();
    }

    function removeSymbol(sym) {
        dfa.alphabet = dfa.alphabet.filter(s => s !== sym);
        dfa.transitions = dfa.transitions.filter(t => t.symbol !== sym);
        renderAlphabet();
        renderTransitions();
        rebuildTransitionSelects();
        renderDiagram();
        renderTable();
        runValidation();
    }

    function renderAlphabet() {
        alphabetChips.innerHTML = '';
        dfa.alphabet.forEach(sym => {
            const chip = document.createElement('span');
            chip.className = 'symbol-chip';
            chip.innerHTML = `<span>${escapeHTML(sym)}</span>
                <button class="chip-remove" title="Remove '${escapeHTML(sym)}'">×</button>`;
            chip.querySelector('.chip-remove').addEventListener('click', () => removeSymbol(sym));
            alphabetChips.appendChild(chip);
        });
    }

    alphabetAddBtn.addEventListener('click', () => {
        addSymbol(alphabetInput.value);
        alphabetInput.value = '';
        alphabetInput.focus();
    });
    alphabetInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') { addSymbol(alphabetInput.value); alphabetInput.value = ''; }
    });
    quickSetBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const syms = JSON.parse(btn.dataset.symbols || '[]');
            dfa.alphabet = [];
            dfa.transitions = [];
            syms.forEach(s => { if (!dfa.alphabet.includes(s)) dfa.alphabet.push(s); });
            renderAlphabet();
            renderTransitions();
            rebuildTransitionSelects();
            renderDiagram();
            renderTable();
            runValidation();
        });
    });

    // =========================================================================
    // STATE MANAGEMENT
    // =========================================================================
    const STATE_NAME_RE = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

    function addState(name) {
        name = name.trim();
        if (!name) return;
        if (!STATE_NAME_RE.test(name)) {
            showSimValidation('State name must start with a letter/underscore, then letters/digits.');
            return;
        }
        if (dfa.states.find(s => s.name === name)) return;
        const isFirst = dfa.states.length === 0;
        dfa.states.push({ name, isStart: isFirst, isAccept: false });
        renderStates();
        rebuildTransitionSelects();
        renderDiagram();
        renderTable();
        runValidation();
    }

    function removeState(name) {
        dfa.states = dfa.states.filter(s => s.name !== name);
        dfa.transitions = dfa.transitions.filter(t => t.from !== name && t.to !== name);
        // If start state was removed and states remain, pick the first
        if (dfa.states.length > 0 && !dfa.states.some(s => s.isStart)) {
            dfa.states[0].isStart = true;
        }
        renderStates();
        renderTransitions();
        rebuildTransitionSelects();
        renderDiagram();
        renderTable();
        runValidation();
    }

    function setStartState(name) {
        dfa.states.forEach(s => s.isStart = (s.name === name));
        renderStates();
        rebuildTransitionSelects();
        renderDiagram();
        renderTable();
        runValidation();
    }

    function toggleAccept(name) {
        const s = dfa.states.find(st => st.name === name);
        if (s) s.isAccept = !s.isAccept;
        renderStates();
        rebuildTransitionSelects();
        renderDiagram();
        renderTable();
        runValidation();
    }

    function renderStates() {
        statesList.innerHTML = '';
        dfa.states.forEach(st => {
            const item = document.createElement('div');
            item.className = 'state-item';
            item.innerHTML = `
                <span class="state-name">${escapeHTML(st.name)}</span>
                <div class="state-badges">
                    <span class="state-badge-pill ${st.isStart ? 'badge-start' : 'badge-normal'}"
                          data-action="set-start" data-state="${escapeHTML(st.name)}"
                          title="Set as start state">${st.isStart ? '▶ Start' : 'Set Start'}</span>
                    <span class="state-badge-pill ${st.isAccept ? 'badge-accept' : 'badge-normal'}"
                          data-action="toggle-accept" data-state="${escapeHTML(st.name)}"
                          title="Toggle accept state">${st.isAccept ? '✓ Accept' : 'Accept?'}</span>
                </div>
                <div class="state-controls">
                    <button class="state-action-btn" data-action="remove" data-state="${escapeHTML(st.name)}" title="Remove state">✕</button>
                </div>`;
            statesList.appendChild(item);
        });
        statesList.querySelectorAll('[data-action]').forEach(el => {
            el.addEventListener('click', () => {
                const action = el.dataset.action;
                const name   = el.dataset.state;
                if (action === 'set-start')     setStartState(name);
                if (action === 'toggle-accept') toggleAccept(name);
                if (action === 'remove')        removeState(name);
            });
        });
    }

    stateAddBtn.addEventListener('click', () => {
        addState(stateInput.value);
        stateInput.value = '';
        stateInput.focus();
    });
    stateInput.addEventListener('keydown', e => {
        if (e.key === 'Enter') { addState(stateInput.value); stateInput.value = ''; }
    });

    // =========================================================================
    // HIGH-CONTRAST DROPDOWNS REBUILD
    // =========================================================================
    function rebuildTransitionSelects() {
        // From State Select
        const prevFrom = trFrom.value;
        trFrom.innerHTML = `<option value="" disabled ${!prevFrom ? 'selected' : ''}>Select state</option>`;
        dfa.states.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.name;
            opt.textContent = `${s.name}${s.isStart ? ' [Start]' : ''}${s.isAccept ? ' [Accept]' : ''}`;
            if (s.name === prevFrom) opt.selected = true;
            trFrom.appendChild(opt);
        });

        // To State Select
        const prevTo = trTo.value;
        trTo.innerHTML = `<option value="" disabled ${!prevTo ? 'selected' : ''}>Select state</option>`;
        dfa.states.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.name;
            opt.textContent = `${s.name}${s.isStart ? ' [Start]' : ''}${s.isAccept ? ' [Accept]' : ''}`;
            if (s.name === prevTo) opt.selected = true;
            trTo.appendChild(opt);
        });

        // Symbol Select
        const prevSym = trSymbol.value;
        trSymbol.innerHTML = `<option value="" disabled ${!prevSym ? 'selected' : ''}>Select symbol</option>`;
        dfa.alphabet.forEach(sym => {
            const opt = document.createElement('option');
            opt.value = sym;
            opt.textContent = `'${sym}'`;
            if (sym === prevSym) opt.selected = true;
            trSymbol.appendChild(opt);
        });
    }

    function addTransition() {
        const from   = trFrom.value;
        const symbol = trSymbol.value;
        const to     = trTo.value;
        if (!from || !symbol || !to) {
            showSimValidation('Please select From State, Symbol, and To State.');
            return;
        }
        // Check conflict
        const conflict = dfa.transitions.find(t => t.from === from && t.symbol === symbol);
        if (conflict) {
            showSimValidation(`Conflict: δ(${from}, '${symbol}') = ${conflict.to} already exists. Remove it first.`);
            return;
        }
        dfa.transitions.push({ from, symbol, to });
        renderTransitions();
        renderDiagram();
        renderTable();
        runValidation();
        clearSimValidation();
    }

    function removeTransition(from, symbol, to) {
        dfa.transitions = dfa.transitions.filter(
            t => !(t.from === from && t.symbol === symbol && t.to === to)
        );
        renderTransitions();
        renderDiagram();
        renderTable();
        runValidation();
    }

    function renderTransitions() {
        transitionsList.innerHTML = '';
        if (dfa.transitions.length === 0) {
            const empty = document.createElement('p');
            empty.className = 'empty-rules-text';
            empty.textContent = 'No transitions defined.';
            transitionsList.appendChild(empty);
            return;
        }
        dfa.transitions.forEach(tr => {
            const rule = document.createElement('div');
            rule.className = 'transition-rule';
            rule.innerHTML = `
                <div class="tr-equation">
                    <span class="eq-fn">δ</span><span class="eq-paren">(</span><span class="eq-state">${escapeHTML(tr.from)}</span><span class="eq-comma">,</span> <span class="eq-sym">'${escapeHTML(tr.symbol)}'</span><span class="eq-paren">)</span>
                    <span class="eq-equals">=</span>
                    <span class="eq-target">${escapeHTML(tr.to)}</span>
                </div>
                <button class="tr-delete-btn" title="Remove transition δ(${escapeHTML(tr.from)}, '${escapeHTML(tr.symbol)}')">✕</button>
            `;
            rule.querySelector('.tr-delete-btn').addEventListener('click', () =>
                removeTransition(tr.from, tr.symbol, tr.to)
            );
            transitionsList.appendChild(rule);
        });
    }

    trAddBtn.addEventListener('click', addTransition);

    // =========================================================================
    // VALIDATION
    // =========================================================================
    function runValidation() {
        validationPanel.innerHTML = '';
        const errors = [];

        if (dfa.states.length === 0)          errors.push('No states defined.');
        if (dfa.alphabet.length === 0)         errors.push('Alphabet is empty.');
        const startState = dfa.states.find(s => s.isStart);
        if (!startState)                       errors.push('No start state selected.');
        const acceptStates = dfa.states.filter(s => s.isAccept);
        if (acceptStates.length === 0)         errors.push('No accepting state defined.');

        // 1. Errors
        if (errors.length > 0) {
            errors.forEach(e => {
                const d = document.createElement('div');
                d.className = 'validate-error';
                d.innerHTML = `<span class="validate-icon">✕</span> ${escapeHTML(e)}`;
                validationPanel.appendChild(d);
            });
        } else {
            const okDiv = document.createElement('div');
            okDiv.className = 'validate-ok';
            okDiv.innerHTML = `<span class="validate-icon">✓</span> <strong>DFA is valid</strong> (Ready for simulation)`;
            validationPanel.appendChild(okDiv);
        }

        updateDFAStats();
        return errors;
    }

    function updateDFAStats() {
        const startSt = dfa.states.find(s => s.isStart);
        const accepts = dfa.states.filter(s => s.isAccept);
        dfaStatsRow.innerHTML = `
            <span class="stat-pill">Q: <strong>${dfa.states.length}</strong></span>
            <span class="stat-pill">Σ: <strong>${dfa.alphabet.length}</strong></span>
            <span class="stat-pill">δ: <strong>${dfa.transitions.length}</strong></span>
            <span class="stat-pill">q₀: <strong>${startSt ? escapeHTML(startSt.name) : '—'}</strong></span>
            <span class="stat-pill">F: <strong>${accepts.length > 0 ? accepts.map(s=>escapeHTML(s.name)).join(', ') : '—'}</strong></span>
        `;
    }

    // =========================================================================
    // AUTO-SCALING & FITTING SVG DIAGRAM RENDERER
    // =========================================================================
    const NODE_RADIUS = 26;

    /**
     * Computes node positions tailored to state count:
     * - N = 1: Single state centered
     * - N = 2: Horizontal textbook layout (q0 on left, q1 on right)
     * - N >= 3: Symmetrical polygon/circle with radius chosen to keep bounds compact
     */
    function computeLayout() {
        const n = dfa.states.length;
        if (n === 0) return {};

        const cx = 400;
        const cy = 200;
        const pos = {};

        if (n === 1) {
            pos[dfa.states[0].name] = { x: cx, y: cy, outwardAngle: -Math.PI / 2 };
        } else if (n === 2) {
            // Horizontal layout: left and right
            const spacing = 220;
            pos[dfa.states[0].name] = { x: cx - spacing / 2, y: cy, outwardAngle: -Math.PI / 2 };
            pos[dfa.states[1].name] = { x: cx + spacing / 2, y: cy, outwardAngle: -Math.PI / 2 };
        } else {
            // Circular polygon layout
            const radius = Math.min(170, Math.max(115, n * 34));
            dfa.states.forEach((st, i) => {
                const angle = (2 * Math.PI * i / n) - Math.PI / 2;
                pos[st.name] = {
                    x: cx + radius * Math.cos(angle),
                    y: cy + radius * Math.sin(angle),
                    outwardAngle: angle
                };
            });
        }

        // If dynamic DEAD state is active in simulation, place it outside gracefully
        if (activeSimulationDead) {
            pos['DEAD'] = {
                x: cx + 180,
                y: cy + 130,
                outwardAngle: Math.PI / 4
            };
        }

        return pos;
    }

    function renderDiagram() {
        // Clear SVG content (keep defs)
        const defs = dfaSvg.querySelector('defs');
        dfaSvg.innerHTML = '';
        if (defs) dfaSvg.appendChild(defs);

        if (dfa.states.length === 0) {
            diagramIdle.style.display = 'flex';
            return;
        }
        diagramIdle.style.display = 'none';

        const pos = computeLayout();

        // Bounding box accumulator to compute dynamic viewBox
        let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
        function updateBounds(x, y, radius = 0) {
            if (x - radius < minX) minX = x - radius;
            if (x + radius > maxX) maxX = x + radius;
            if (y - radius < minY) minY = y - radius;
            if (y + radius > maxY) maxY = y + radius;
        }

        // Group transitions by from -> to
        const edgeGroups = {};
        dfa.transitions.forEach(tr => {
            const key = `${tr.from}||${tr.to}`;
            if (!edgeGroups[key]) edgeGroups[key] = [];
            edgeGroups[key].push(tr.symbol);
        });

        // If active DEAD trap transition exists, include it
        if (activeSimulationDead && activeSimulationDead.from) {
            const key = `${activeSimulationDead.from}||DEAD`;
            if (!edgeGroups[key]) edgeGroups[key] = [activeSimulationDead.symbol];
        }

        // 1. Draw Edges
        Object.entries(edgeGroups).forEach(([key, symbols]) => {
            const [from, to] = key.split('||');
            const pf = pos[from];
            const pt = pos[to];
            if (!pf || !pt) return;

            const label = symbols.join(', ');
            const isSelf = (from === to);
            const revKey = `${to}||${from}`;
            const isBidirectional = (from !== to) && edgeGroups[revKey];
            const isDeadEdge = (to === 'DEAD');

            const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            g.id = `pg-edge-${from}-${to}`;

            if (isSelf) {
                // Self-loop: Arc directed outward
                const outAngle = pf.outwardAngle !== undefined ? pf.outwardAngle : -Math.PI / 2;
                const ux = Math.cos(outAngle);
                const uy = Math.sin(outAngle);
                const px = -uy;
                const py = ux;

                const r = NODE_RADIUS;
                const loopDist = 44;

                const startX = pf.x + ux * r - px * 13;
                const startY = pf.y + uy * r - py * 13;
                const endX   = pf.x + ux * r + px * 13;
                const endY   = pf.y + uy * r + py * 13;

                const cp1X = pf.x + ux * (r + loopDist) - px * 26;
                const cp1Y = pf.y + uy * (r + loopDist) - py * 26;
                const cp2X = pf.x + ux * (r + loopDist) + px * 26;
                const cp2Y = pf.y + uy * (r + loopDist) + py * 26;

                const lblX = pf.x + ux * (r + loopDist + 12);
                const lblY = pf.y + uy * (r + loopDist + 12);

                const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                path.setAttribute('d', `M ${startX} ${startY} C ${cp1X} ${cp1Y}, ${cp2X} ${cp2Y}, ${endX} ${endY}`);
                path.setAttribute('class', 'pg-edge');
                path.setAttribute('marker-end', 'url(#arrow)');
                g.appendChild(path);

                const txt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                txt.setAttribute('x', lblX);
                txt.setAttribute('y', lblY);
                txt.setAttribute('class', 'pg-edge-label');
                txt.textContent = label;
                g.appendChild(txt);

                updateBounds(cp1X, cp1Y, 15);
                updateBounds(cp2X, cp2Y, 15);
                updateBounds(lblX, lblY, 20);

            } else {
                // Directed edge between different states
                const dx = pt.x - pf.x;
                const dy = pt.y - pf.y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                const ux = dx / dist;
                const uy = dy / dist;
                const px = -uy;
                const py = ux;

                // Curvature offset
                let curve = 0;
                if (isBidirectional) {
                    curve = 32; // Curve rightwards
                } else if (isDeadEdge) {
                    curve = -15;
                }

                // Node attachment points
                const startX = pf.x + ux * (NODE_RADIUS + 2) + px * (curve * 0.15);
                const startY = pf.y + uy * (NODE_RADIUS + 2) + py * (curve * 0.15);
                const endX   = pt.x - ux * (NODE_RADIUS + 7) + px * (curve * 0.15);
                const endY   = pt.y - uy * (NODE_RADIUS + 7) + py * (curve * 0.15);

                const cpX = (startX + endX) / 2 + px * curve;
                const cpY = (startY + endY) / 2 + py * curve;

                // Label at midpoint
                const midX = (startX + 2 * cpX + endX) / 4 + px * (curve ? 8 : 12);
                const midY = (startY + 2 * cpY + endY) / 4 + py * (curve ? 8 : 12);

                const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                path.setAttribute('d', `M ${startX} ${startY} Q ${cpX} ${cpY} ${endX} ${endY}`);
                path.setAttribute('class', isDeadEdge ? 'pg-edge dead-active' : 'pg-edge');
                path.setAttribute('marker-end', isDeadEdge ? 'url(#arrow-red)' : 'url(#arrow)');
                g.appendChild(path);

                const txt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                txt.setAttribute('x', midX);
                txt.setAttribute('y', midY);
                txt.setAttribute('class', isDeadEdge ? 'pg-edge-label dead-lbl' : 'pg-edge-label');
                txt.textContent = label;
                g.appendChild(txt);

                updateBounds(cpX, cpY, 20);
                updateBounds(midX, midY, 20);
            }

            dfaSvg.appendChild(g);
        });

        // 2. Draw Nodes
        const allStatesToDraw = [...dfa.states];
        if (activeSimulationDead) {
            allStatesToDraw.push({ name: 'DEAD', isStart: false, isAccept: false, isDead: true });
        }

        allStatesToDraw.forEach(st => {
            const coord = pos[st.name];
            if (!coord) return;
            const { x, y } = coord;

            const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            g.classList.add('pg-state-node');
            g.id = `pg-node-${st.name}`;

            // Start State Arrow & Label
            if (st.isStart) {
                const arrStartX = x - NODE_RADIUS - 40;
                const arrEndX   = x - NODE_RADIUS - 5;

                const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                line.setAttribute('x1', arrStartX);
                line.setAttribute('y1', y);
                line.setAttribute('x2', arrEndX);
                line.setAttribute('y2', y);
                line.setAttribute('class', 'pg-start-arrow');
                g.appendChild(line);

                const startTxt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                startTxt.setAttribute('x', (arrStartX + arrEndX) / 2);
                startTxt.setAttribute('y', y - 10);
                startTxt.setAttribute('class', 'pg-start-label');
                startTxt.textContent = 'Start';
                g.appendChild(startTxt);

                updateBounds(arrStartX - 10, y, 20);
            }

            // Outer Circle
            const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            circle.setAttribute('cx', x);
            circle.setAttribute('cy', y);
            circle.setAttribute('r', NODE_RADIUS);
            circle.classList.add('pg-node-circle');
            if (st.isStart)  circle.classList.add('start');
            if (st.isAccept) circle.classList.add('accept');
            if (st.isDead)   circle.classList.add('dead-node');
            g.appendChild(circle);

            // Double circle for accepting states
            if (st.isAccept) {
                const inner = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                inner.setAttribute('cx', x);
                inner.setAttribute('cy', y);
                inner.setAttribute('r', NODE_RADIUS - 5);
                inner.classList.add('pg-node-circle', 'accept-inner');
                g.appendChild(inner);
            }

            // Node Label
            const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            label.setAttribute('x', x);
            label.setAttribute('y', y);
            label.setAttribute('class', 'pg-node-label');
            label.textContent = st.name;
            g.appendChild(label);

            updateBounds(x, y, NODE_RADIUS + 15);
            dfaSvg.appendChild(g);
        });

        // 3. Set dynamic viewBox with generous padding so NOTHING is ever clipped
        if (minX !== Infinity && maxX !== -Infinity) {
            const padX = 45;
            const padY = 40;
            const finalMinX = Math.floor(minX - padX);
            const finalMinY = Math.floor(minY - padY);
            const finalW    = Math.max(360, Math.ceil(maxX - minX + padX * 2));
            const finalH    = Math.max(240, Math.ceil(maxY - minY + padY * 2));

            dfaSvg.setAttribute('viewBox', `${finalMinX} ${finalMinY} ${finalW} ${finalH}`);
            dfaSvg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
        }
    }

    // Auto-fit on window resize
    window.addEventListener('resize', () => {
        if (dfa.states.length > 0) renderDiagram();
    });

    // =========================================================================
    // TRANSITION TABLE
    // =========================================================================
    function renderTable() {
        if (dfa.states.length === 0 || dfa.alphabet.length === 0) {
            tableWrap.innerHTML = '<p class="table-idle">Define states and alphabet to generate the table.</p>';
            return;
        }
        const table = document.createElement('table');
        table.className = 'pg-trans-table';

        // Header row
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        headerRow.innerHTML = `<th>Current State</th>`;
        dfa.alphabet.forEach(sym => {
            const th = document.createElement('th');
            th.textContent = `'${sym}'`;
            headerRow.appendChild(th);
        });
        thead.appendChild(headerRow);
        table.appendChild(thead);

        // Body
        const tbody = document.createElement('tbody');
        dfa.states.forEach(st => {
            const row = document.createElement('tr');
            const stateCell = document.createElement('td');
            let markers = '';
            if (st.isStart)  markers += '<span class="cell-start-marker" title="Start State">▶</span>';
            if (st.isAccept) markers += '<span class="cell-accept-marker" title="Accepting State">⊙</span>';
            stateCell.innerHTML = `${markers}<strong>${escapeHTML(st.name)}</strong>`;
            row.appendChild(stateCell);

            dfa.alphabet.forEach(sym => {
                const tr = dfa.transitions.find(t => t.from === st.name && t.symbol === sym);
                const td = document.createElement('td');
                if (tr) {
                    td.textContent = tr.to;
                    td.className = 'cell-defined';
                } else {
                    td.textContent = 'DEAD';
                    td.className = 'cell-dead';
                }
                row.appendChild(td);
            });
            tbody.appendChild(row);
        });
        table.appendChild(tbody);

        tableWrap.innerHTML = '';
        tableWrap.appendChild(table);
    }

    // =========================================================================
    // ANIMATION PLAYER (COLOR-ACCURATE SIMULATION)
    // =========================================================================
    class PlaygroundAnimator {
        constructor() {
            this.data = null;
            this.step = 0;
            this.isPlaying = false;
            this.timer = null;
            this.stepDuration = 650;
        }

        load(data) {
            this.pause();
            this.data = data;
            this.step = 0;
            activeSimulationDead = null;

            // Check if DEAD was reached anywhere in the run
            const reachedDead = (data.state_path || []).includes('DEAD');
            if (reachedDead) {
                // Find first transition entering DEAD
                const deadTr = (data.transitions || []).find(t => t.to_state === 'DEAD');
                if (deadTr) {
                    activeSimulationDead = { from: deadTr.from_state, symbol: deadTr.symbol };
                }
            }
            renderDiagram();

            // Populate step breakdown table
            pgBreakdownBody.innerHTML = '';
            (data.transitions || []).forEach((tr, idx) => {
                const row = document.createElement('tr');
                row.id = `pg-brow-${idx}`;
                const isValid = tr.is_valid;
                const chipClass = isValid ? 'valid' : 'trap';
                const chipText = isValid ? '✓ Valid' : '✕ Trap (DEAD)';

                row.innerHTML = `
                    <td><strong>#${tr.step}</strong></td>
                    <td><code>${escapeHTML(tr.from_state)}</code></td>
                    <td><span style="font-family:var(--font-mono);font-weight:700;color:var(--gold-bright);">'${escapeHTML(tr.symbol)}'</span></td>
                    <td><code>${escapeHTML(tr.to_state)}</code></td>
                    <td><span class="status-chip ${chipClass}">${chipText}</span></td>`;
                pgBreakdownBody.appendChild(row);
            });

            // Build Symbol Stream Characters
            pgSymbolStream.innerHTML = '';
            const chars = data.input_string ? data.input_string.split('') : [];
            chars.forEach((ch, i) => {
                const box = document.createElement('span');
                box.className = 'pg-stream-char';
                box.id = `pg-sc-${i}`;
                box.textContent = ch;
                pgSymbolStream.appendChild(box);
            });

            // Display UI panels
            pgAnimHud.style.display = 'flex';
            pgResultsCard.style.display = 'none';
            pgBreakdownWrap.style.display = 'block';
            pgWarningsWrap.style.display = 'none';

            this.renderStep(0);
            this.play();
        }

        renderStep(stepIdx) {
            this.step = stepIdx;
            if (!this.data) return;

            const transitions = this.data.transitions || [];
            const statePath   = this.data.state_path  || [this.data.start_state];
            const totalSteps  = transitions.length;
            const isAccepted  = this.data.is_accepted;
            const currentState = statePath[stepIdx] || '';

            // Update HUD State Pill & Step Count
            pgHudState.textContent = currentState;
            pgHudState.className = 'pg-hud-state';

            if (currentState === 'DEAD') {
                pgHudState.classList.add('dead');
            } else if (stepIdx === totalSteps) {
                // Final state: Green if accepted, Red if non-accepting
                if (isAccepted) {
                    pgHudState.classList.add('accepted');
                } else {
                    pgHudState.classList.add('rejected');
                }
            }

            pgHudStep.textContent = `Step ${stepIdx} / ${totalSteps}`;
            pgStepBtn.disabled = (stepIdx >= totalSteps);

            // Update Stream Characters:
            // - GREEN = valid transition step
            // - RED = invalid transition step (trap / DEAD)
            // - Active = Gold
            (this.data.input_string || '').split('').forEach((_, i) => {
                const el = document.getElementById(`pg-sc-${i}`);
                if (!el) return;
                el.className = 'pg-stream-char';
                if (i < stepIdx) {
                    const tr = transitions[i];
                    if (tr && tr.is_valid) {
                        el.classList.add('pg-passed'); // Valid transition -> GREEN
                    } else {
                        el.classList.add('pg-error');  // Actual invalid transition -> RED
                    }
                } else if (i === stepIdx && stepIdx < totalSteps) {
                    el.classList.add('pg-active');
                }
            });

            // Update SVG Diagram Node Highlights
            resetSVGHighlights();
            for (let i = 0; i <= stepIdx; i++) {
                const st = statePath[i];
                const nodeG = document.getElementById(`pg-node-${st}`);
                if (nodeG) {
                    nodeG.classList.remove('pg-node-active','pg-node-dead','pg-node-visited','pg-node-accepted','pg-node-rejected');
                    if (st === 'DEAD') {
                        nodeG.classList.add('pg-node-dead');
                    } else if (i === stepIdx) {
                        if (stepIdx === totalSteps) {
                            // Final step reached: GREEN if accept, RED if non-accepting
                            if (isAccepted) {
                                nodeG.classList.add('pg-node-accepted');
                            } else {
                                nodeG.classList.add('pg-node-rejected');
                            }
                        } else {
                            nodeG.classList.add('pg-node-active'); // In-progress step -> Gold
                        }
                    } else {
                        nodeG.classList.add('pg-node-visited');
                    }
                }
            }

            // Update SVG Diagram Edge Highlights
            for (let i = 0; i < stepIdx; i++) {
                const tr = transitions[i];
                if (!tr) continue;
                const edgeG = document.getElementById(`pg-edge-${tr.from_state}-${tr.to_state}`);
                if (edgeG) {
                    const path = edgeG.querySelector('.pg-edge');
                    const lbl  = edgeG.querySelector('.pg-edge-label');
                    if (tr.to_state === 'DEAD' || !tr.is_valid) {
                        if (path) path.className.baseVal = 'pg-edge dead-active';
                        if (lbl)  lbl.className.baseVal  = 'pg-edge-label dead-lbl';
                    } else {
                        if (path) path.className.baseVal = 'pg-edge valid-active';
                        if (lbl)  lbl.className.baseVal  = 'pg-edge-label valid-lbl';
                    }
                }
            }

            // Highlight Breakdown Table Row
            // During animation: gold = current step in progress
            // At final step: green = valid transition, red = trap/invalid transition
            const isFinalStep = (stepIdx >= totalSteps);
            document.querySelectorAll('#pg-breakdown-tbody tr').forEach(r =>
                r.classList.remove('pg-active-row', 'pg-valid-row', 'pg-error-row')
            );
            if (isFinalStep) {
                // Final state: colour every row by its own result
                transitions.forEach((tr, i) => {
                    const row = document.getElementById(`pg-brow-${i}`);
                    if (row) {
                        row.classList.add(tr.is_valid ? 'pg-valid-row' : 'pg-error-row');
                    }
                });
            } else if (stepIdx > 0) {
                // Mid-animation: gold highlight on the just-completed row
                const activeRow = document.getElementById(`pg-brow-${stepIdx - 1}`);
                if (activeRow) {
                    activeRow.classList.add('pg-active-row');
                    activeRow.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }
            }

            // Update Path Trail
            pgPathTrail.innerHTML = '';
            for (let i = 0; i <= stepIdx; i++) {
                const st = statePath[i];
                const node = document.createElement('span');
                node.className = 'pg-path-node';
                if (i === 0) node.classList.add('start');

                if (i === totalSteps && stepIdx === totalSteps) {
                    if (isAccepted) {
                        node.classList.add('accept');    // GREEN
                    } else {
                        node.classList.add('rejected');  // RED
                    }
                } else if (st === 'DEAD') {
                    node.classList.add('dead');          // RED
                } else if (i === stepIdx) {
                    node.classList.add('active-now');
                }

                node.textContent = st;
                pgPathTrail.appendChild(node);

                if (i < stepIdx) {
                    const tr = transitions[i];
                    const arr = document.createElement('span');
                    const isValid = tr && tr.is_valid;
                    arr.className = `pg-path-arrow ${isValid ? 'valid-arrow' : 'invalid-arrow'}`;
                    arr.innerHTML = `➔ <span class="pg-path-sym">'${escapeHTML(tr.symbol)}'</span> ➔`;
                    pgPathTrail.appendChild(arr);
                }
            }

            // Final Step Reached: Display Status Banner & Result Card
            if (stepIdx >= totalSteps) {
                this.pause();
                pgResultsCard.style.display = 'block';

                pgStatusBanner.className = `pg-status-banner ${isAccepted ? 'granted' : 'denied'}`;
                pgStatusIcon.textContent = isAccepted ? '🔓' : '🔒';
                pgStatusTitle.textContent = isAccepted ? 'ACCEPTED' : 'REJECTED';

                // Build a clear, specific status message
                const finalSt = this.data.final_state;
                let statusMsg;
                if (isAccepted) {
                    statusMsg = this.data.message || `String accepted — final state ${finalSt} is an accepting state.`;
                } else if (finalSt === 'DEAD') {
                    statusMsg = `String rejected — an undefined transition was taken, reaching the DEAD trap state.`;
                } else {
                    // Rejected because final state is non-accepting (all transitions were valid)
                    const hadTrap = (this.data.transitions || []).some(t => !t.is_valid);
                    if (hadTrap) {
                        statusMsg = this.data.message || `String rejected — ended in non-accepting state ${finalSt}.`;
                    } else {
                        statusMsg = `String rejected — all transitions were valid, but final state ${finalSt} is non-accepting.`;
                    }
                }
                pgStatusMsg.textContent = statusMsg;

                if (isAccepted) {
                    pgFinalBadge.textContent = `Final: ${finalSt} (Accepting)`;
                } else if (finalSt === 'DEAD') {
                    pgFinalBadge.textContent = `Final: DEAD (Trap State)`;
                } else {
                    pgFinalBadge.textContent = `Final: ${finalSt} (Non-Accepting)`;
                }

                pgStepBtn.disabled = true;

                // Warnings (filter out internal missing-transition notices)
                const otherWarns = [...(this.data.warnings || []), ...(this.data.validation_warnings || [])]
                    .filter(w => !w.includes('Missing transition:'));
                if (otherWarns.length > 0) {
                    pgWarningsWrap.style.display = 'block';
                    pgWarningsList.innerHTML = otherWarns.map(w =>
                        `<div class="pg-warning-item"><span>⚠</span> <span>${escapeHTML(w)}</span></div>`
                    ).join('');
                } else {
                    pgWarningsWrap.style.display = 'none';
                }
            }
        }

        play() {
            if (!this.data) return;
            const total = (this.data.transitions || []).length;
            if (this.step >= total) {
                this.step = 0;
                this.renderStep(0);
            }
            this.isPlaying = true;
            pgPlayBtn.classList.add('active-play');
            this.schedule();
        }

        schedule() {
            if (this.timer) clearTimeout(this.timer);
            if (!this.isPlaying) return;
            const total = (this.data.transitions || []).length;
            if (this.step < total) {
                this.timer = setTimeout(() => {
                    if (this.isPlaying) {
                        this.renderStep(this.step + 1);
                        this.schedule();
                    }
                }, this.stepDuration);
            } else {
                this.isPlaying = false;
                pgPlayBtn.classList.remove('active-play');
            }
        }

        pause() {
            this.isPlaying = false;
            if (this.timer) { clearTimeout(this.timer); this.timer = null; }
            pgPlayBtn.classList.remove('active-play');
        }

        step() {
            this.pause();
            if (!this.data) return;
            const total = (this.data.transitions || []).length;
            if (this.step < total) this.renderStep(this.step + 1);
        }

        replay() {
            this.pause();
            if (!this.data) return;
            pgResultsCard.style.display = 'none';
            pgWarningsWrap.style.display = 'none';
            this.renderStep(0);
            this.play();
        }

        reset() {
            this.pause();
            this.data = null;
            this.step = 0;
            activeSimulationDead = null;

            pgAnimHud.style.display = 'none';
            pgResultsCard.style.display = 'none';
            pgBreakdownWrap.style.display = 'none';
            pgWarningsWrap.style.display = 'none';
            pgSimValidation.textContent = '';

            resetSVGHighlights();
            renderDiagram();
        }
    }

    function resetSVGHighlights() {
        document.querySelectorAll('.pg-state-node').forEach(g => {
            g.classList.remove('pg-node-active','pg-node-dead','pg-node-visited','pg-node-accepted','pg-node-rejected');
        });
        document.querySelectorAll('.pg-edge').forEach(p => {
            p.className.baseVal = 'pg-edge';
        });
        document.querySelectorAll('.pg-edge-label').forEach(l => {
            l.className.baseVal = 'pg-edge-label';
        });
    }

    const animator = new PlaygroundAnimator();

    // =========================================================================
    // SIMULATION SUBMIT
    // =========================================================================
    function showSimValidation(msg) {
        pgSimValidation.textContent = msg;
        pgSimValidation.style.color = '#f87171';
    }
    function clearSimValidation() { pgSimValidation.textContent = ''; }

    async function simulate() {
        clearSimValidation();
        const inputStr = pgStringInput.value;

        // Client-side DFA requirements
        const errors = runValidation();
        if (errors.length > 0) {
            showSimValidation('Fix DFA errors first: ' + errors[0]);
            return;
        }

        const startSt    = dfa.states.find(s => s.isStart);
        const acceptSts  = dfa.states.filter(s => s.isAccept);

        const payload = {
            states:       dfa.states.map(s => s.name),
            alphabet:     dfa.alphabet,
            start_state:  startSt ? startSt.name : '',
            accept_states: acceptSts.map(s => s.name),
            transitions:  dfa.transitions.map(t => ({ from: t.from, symbol: t.symbol, to: t.to })),
            input_string: inputStr || '',
        };

        try {
            pgSimBtn.disabled = true;
            pgSimBtn.textContent = 'Simulating...';
            animator.reset();

            const resp = await fetch('/api/custom-dfa/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await resp.json();

            if (data.success) {
                animator.load(data);
            } else {
                const errs = (data.errors || []).join(' | ') || data.error || 'Simulation failed.';
                showSimValidation(errs);
            }
        } catch {
            showSimValidation('Cannot reach server. Is StateLock running?');
        } finally {
            pgSimBtn.disabled = false;
            pgSimBtn.textContent = 'Simulate';
        }
    }

    pgSimBtn.addEventListener('click', simulate);
    pgStringInput.addEventListener('keydown', e => { if (e.key === 'Enter') simulate(); });
    pgSimClearBtn.addEventListener('click', () => {
        pgStringInput.value = '';
        clearSimValidation();
        animator.reset();
    });

    quickStrBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            pgStringInput.value = btn.dataset.str;
            simulate();
        });
    });

    // Playback controls
    pgPlayBtn.addEventListener('click',   () => animator.play());
    pgPauseBtn.addEventListener('click',  () => animator.pause());
    pgStepBtn.addEventListener('click',   () => animator.step());
    pgReplayBtn.addEventListener('click', () => animator.replay());
    pgResetBtn.addEventListener('click',  () => {
        animator.reset();
        pgStringInput.value = '';
    });

    // =========================================================================
    // PRESETS
    // =========================================================================
    function loadPreset(key) {
        const p = DFA_PRESETS[key];
        if (!p) return;
        dfa.alphabet    = [...p.alphabet];
        dfa.states      = p.states.map(s => ({ ...s }));
        dfa.transitions = p.transitions.map(t => ({ ...t }));
        renderAlphabet();
        renderStates();
        renderTransitions();
        rebuildTransitionSelects();
        renderDiagram();
        renderTable();
        runValidation();
        animator.reset();
        if (key === 'user-spec' || key === 'binary-ends-0') {
            pgStringInput.value = '0';
        }
    }

    presetBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            presetBtns.forEach(b => b.classList.remove('active-preset'));
            btn.classList.add('active-preset');
            loadPreset(btn.dataset.preset);
        });
    });

    // =========================================================================
    // INIT – load Tutorial DFA
    // =========================================================================
    function init() {
        loadPreset('user-spec');
        alphabetInput.focus();
    }

    // =========================================================================
    // UTILS
    // =========================================================================
    function escapeHTML(str) {
        return String(str)
            .replace(/&/g,'&amp;')
            .replace(/</g,'&lt;')
            .replace(/>/g,'&gt;')
            .replace(/"/g,'&quot;')
            .replace(/'/g,'&#039;');
    }

    init();
});
