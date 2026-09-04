/**
 * StateLock - Professional Dashboard & Analytics Controller
 * Fetches real authentication metrics from SQLite and renders visual SVG analytics.
 */

document.addEventListener('DOMContentLoaded', () => {
    initDashboard();
});

let currentStatsData = null;

async function initDashboard() {
    setupEventListeners();
    await loadDashboardData();
}

function setupEventListeners() {
    // Refresh button
    const refreshBtn = document.getElementById('refresh-dashboard-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', async () => {
            const icon = refreshBtn.querySelector('.refresh-icon');
            if (icon) icon.classList.add('spin-animation');
            await loadDashboardData();
            setTimeout(() => {
                if (icon) icon.classList.remove('spin-animation');
            }, 600);
        });
    }

    // Logout buttons
    const headerLogoutBtn = document.getElementById('dash-logout-btn');
    const actionLogoutBtn = document.getElementById('action-logout-btn');
    [headerLogoutBtn, actionLogoutBtn].forEach(btn => {
        if (btn) {
            btn.addEventListener('click', handleLogout);
        }
    });

    // Passcode Change Modal
    const actionPasscodeBtn = document.getElementById('action-change-passcode-btn');
    const dashNavPasscodeBtn = document.getElementById('dash-nav-change-passcode-btn');
    const modal = document.getElementById('change-passcode-modal');
    const closeBtn = document.getElementById('close-passcode-modal-btn');
    const cancelBtn = document.getElementById('cancel-passcode-btn');
    const passcodeForm = document.getElementById('dash-passcode-form');

    const openModal = () => {
        resetPasscodeModal();
        if (modal) modal.style.display = 'flex';
    };

    if (actionPasscodeBtn) actionPasscodeBtn.addEventListener('click', openModal);
    if (dashNavPasscodeBtn) dashNavPasscodeBtn.addEventListener('click', openModal);

    [closeBtn, cancelBtn].forEach(btn => {
        if (btn && modal) {
            btn.addEventListener('click', () => {
                modal.style.display = 'none';
            });
        }
    });

    // Close on overlay click
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.style.display = 'none';
        });
    }

    // Passcode form submit
    if (passcodeForm) {
        passcodeForm.addEventListener('submit', handlePasscodeUpdate);
    }
}

async function loadDashboardData() {
    try {
        const res = await fetch('/api/dashboard-stats', {
            method: 'GET',
            cache: 'no-store',
            headers: {
                'Accept': 'application/json'
            }
        });

        if (res.status === 401) {
            // Unauthorized - redirect to login
            window.location.href = '/?unauthorized=1';
            return;
        }

        const data = await res.json();
        if (data.success) {
            currentStatsData = data;
            renderDashboard(data);
        } else {
            console.error('Failed to load dashboard data:', data.error);
        }
    } catch (err) {
        console.error('Network error loading dashboard statistics:', err);
    }
}

function renderDashboard(data) {
    const user = data.user || {};
    const stats = data.statistics || {};
    const account = data.account_status || {};
    const charts = data.chart_data || {};
    const recents = data.recent_activity || [];

    // 1. User & Header info
    const userDisplayName = document.getElementById('user-display-name');
    const headerUsername = document.getElementById('dash-header-username');
    const createdAtEl = document.getElementById('user-created-at');
    
    if (userDisplayName) userDisplayName.textContent = user.username || 'User';
    if (headerUsername) headerUsername.textContent = user.username || 'User';
    if (createdAtEl) createdAtEl.textContent = user.created_at || 'Recently';

    // 2. Security Status Banner & Account Lock Status
    renderSecurityStatus(account);

    // 3. KPI Cards
    const totalEl = document.getElementById('kpi-total-attempts');
    const successEl = document.getElementById('kpi-successful-attempts');
    const failedEl = document.getElementById('kpi-failed-attempts');
    const rateEl = document.getElementById('kpi-success-rate');
    const rateBar = document.getElementById('kpi-rate-bar');

    const total = stats.total_attempts || 0;
    const successful = stats.successful_attempts || 0;
    const failed = stats.failed_attempts || 0;
    const rate = typeof stats.success_rate === 'number' ? stats.success_rate : 0.0;

    if (totalEl) totalEl.textContent = total.toLocaleString();
    if (successEl) successEl.textContent = successful.toLocaleString();
    if (failedEl) failedEl.textContent = failed.toLocaleString();
    if (rateEl) rateEl.textContent = `${rate.toFixed(1)}%`;
    if (rateBar) rateBar.style.width = `${Math.min(100, Math.max(0, rate))}%`;

    // 4. Account Status Card Details
    const failedText = document.getElementById('failed-attempts-text');
    const failedMeter = document.getElementById('failed-meter-fill');
    const lastAuthEl = document.getElementById('last-auth-timestamp');

    const failedCount = account.failed_attempts || 0;
    const maxFailed = account.max_failed_attempts || 5;
    if (failedText) failedText.textContent = `${failedCount} / ${maxFailed}`;

    if (failedMeter) {
        const percent = Math.min(100, (failedCount / maxFailed) * 100);
        failedMeter.style.width = `${percent}%`;
        if (failedCount >= 4) {
            failedMeter.style.backgroundColor = 'var(--danger-color, #ef4444)';
        } else if (failedCount >= 2) {
            failedMeter.style.backgroundColor = 'var(--gold-bright, #facc15)';
        } else {
            failedMeter.style.backgroundColor = 'var(--gold-color, #d4af37)';
        }
    }

    if (lastAuthEl) {
        lastAuthEl.textContent = stats.last_attempt_at || 'No attempts yet';
    }

    // 5. Visual Analytics: Donut Chart
    renderDonutChart(charts.success_vs_failed || { successful, failed }, total, rate);

    // 6. Visual Analytics: Timeline Activity Chart
    renderTimelineChart(charts.activity_over_time || [], total);

    // 7. Recent Activity Table
    renderRecentActivity(recents);
}

function renderSecurityStatus(account) {
    const badge = document.getElementById('security-status-badge');
    const text = document.getElementById('security-status-text');
    const lockStatusBadge = document.getElementById('badge-lock-status');

    if (!badge || !text) return;

    badge.className = 'status-badge';
    if (account.is_locked) {
        badge.classList.add('status-danger');
        text.textContent = `Locked (${account.lockout_remaining}s left)`;
        if (lockStatusBadge) {
            lockStatusBadge.className = 'badge badge-danger';
            lockStatusBadge.textContent = 'Account Locked (Cooldown)';
        }
    } else if (account.failed_attempts >= 3) {
        badge.classList.add('status-warning');
        text.textContent = `Warning (${account.failed_attempts}/5 Failed)`;
        if (lockStatusBadge) {
            lockStatusBadge.className = 'badge badge-warning';
            lockStatusBadge.textContent = 'High Failed Count';
        }
    } else if (account.failed_attempts > 0) {
        badge.classList.add('status-attention');
        text.textContent = `Active (${account.failed_attempts}/5 Failed)`;
        if (lockStatusBadge) {
            lockStatusBadge.className = 'badge badge-gold';
            lockStatusBadge.textContent = 'Active (1 Failure)';
        }
    } else {
        badge.classList.add('status-normal');
        text.textContent = 'Active & Secure';
        if (lockStatusBadge) {
            lockStatusBadge.className = 'badge badge-success';
            lockStatusBadge.textContent = 'Active / Normal';
        }
    }
}

/**
 * Renders SVG Donut Chart for Successful vs Failed attempts
 */
function renderDonutChart(data, total, rate) {
    const container = document.getElementById('donut-chart-container');
    const legendSuccess = document.getElementById('legend-success-count');
    const legendFailed = document.getElementById('legend-failed-count');

    const successful = data.successful || 0;
    const failed = data.failed || 0;

    if (legendSuccess) legendSuccess.textContent = successful;
    if (legendFailed) legendFailed.textContent = failed;

    if (!container) return;

    if (total === 0) {
        container.innerHTML = `
            <div class="empty-chart-state">
                <svg width="180" height="180" viewBox="0 0 180 180">
                    <circle cx="90" cy="90" r="68" fill="none" stroke="#26262e" stroke-width="16" />
                    <text x="90" y="86" text-anchor="middle" fill="#888" font-size="13" font-family="Inter, sans-serif">No Data</text>
                    <text x="90" y="104" text-anchor="middle" fill="#555" font-size="11" font-family="Inter, sans-serif">0 Attempts</text>
                </svg>
                <p class="chart-empty-msg">No authentication history recorded yet.<br>Authenticate using the DFA to populate metrics.</p>
            </div>
        `;
        return;
    }

    const size = 200;
    const strokeWidth = 20;
    const radius = 70;
    const circumference = 2 * Math.PI * radius;

    const successRatio = total > 0 ? successful / total : 0;
    const failedRatio = total > 0 ? failed / total : 0;

    const successDash = successRatio * circumference;
    const failedDash = failedRatio * circumference;

    const successOffset = 0;
    const failedOffset = -successDash;

    container.innerHTML = `
        <div class="donut-chart-wrapper">
            <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" class="donut-svg">
                <defs>
                    <linearGradient id="goldDonutGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stop-color="#facc15" />
                        <stop offset="100%" stop-color="#d4af37" />
                    </linearGradient>
                    <linearGradient id="dangerDonutGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stop-color="#ef4444" />
                        <stop offset="100%" stop-color="#991b1b" />
                    </linearGradient>
                    <filter id="donutGlow" x="-20%" y="-20%" width="140%" height="140%">
                        <feDropShadow dx="0" dy="0" stdDeviation="3" flood-color="#d4af37" flood-opacity="0.3"/>
                    </filter>
                </defs>
                <!-- Background track -->
                <circle cx="100" cy="100" r="${radius}" fill="none" stroke="#1f1f26" stroke-width="${strokeWidth}" />
                
                <!-- Successful Segment (Gold) -->
                ${successful > 0 ? `
                <circle cx="100" cy="100" r="${radius}" fill="none" stroke="url(#goldDonutGrad)" 
                    stroke-width="${strokeWidth}"
                    stroke-dasharray="${successDash} ${circumference}"
                    stroke-dashoffset="${successOffset}"
                    stroke-linecap="round"
                    transform="rotate(-90 100 100)"
                    filter="url(#donutGlow)"
                    class="donut-segment donut-segment-success" />
                ` : ''}

                <!-- Failed Segment (Red) -->
                ${failed > 0 ? `
                <circle cx="100" cy="100" r="${radius}" fill="none" stroke="url(#dangerDonutGrad)" 
                    stroke-width="${strokeWidth}"
                    stroke-dasharray="${failedDash} ${circumference}"
                    stroke-dashoffset="${failedOffset}"
                    stroke-linecap="round"
                    transform="rotate(-90 100 100)"
                    class="donut-segment donut-segment-failed" />
                ` : ''}

                <!-- Center Text -->
                <text x="100" y="93" text-anchor="middle" fill="#d4af37" font-size="22" font-weight="700" font-family="'JetBrains Mono', monospace">${rate.toFixed(0)}%</text>
                <text x="100" y="112" text-anchor="middle" fill="#a0a0a8" font-size="11" font-weight="600" font-family="Inter, sans-serif">SUCCESS</text>
                <text x="100" y="126" text-anchor="middle" fill="#666" font-size="10" font-family="Inter, sans-serif">${total} total</text>
            </svg>
        </div>
    `;
}

/**
 * Renders SVG Bar/Timeline Chart for Authentication Activity Over Time
 */
function renderTimelineChart(activityData, total) {
    const container = document.getElementById('timeline-chart-container');
    const rangeLabel = document.getElementById('timeline-range-label');
    if (!container) return;

    if (!activityData || activityData.length === 0 || total === 0) {
        container.innerHTML = `
            <div class="empty-chart-state">
                <div style="font-size: 2.2rem; margin-bottom: 8px;">📈</div>
                <p class="chart-empty-msg">No temporal authentication history found.<br>Authentications are timestamped and logged automatically in SQLite.</p>
            </div>
        `;
        if (rangeLabel) rangeLabel.textContent = 'No date records found';
        return;
    }

    if (rangeLabel) {
        rangeLabel.textContent = `Showing ${activityData.length} active day(s) of authentication data`;
    }

    // Chart dimensions
    const width = 460;
    const height = 200;
    const padLeft = 40;
    const padRight = 20;
    const padTop = 20;
    const padBottom = 40;

    const chartWidth = width - padLeft - padRight;
    const chartHeight = height - padTop - padBottom;

    // Find max value for Y-axis scale
    const maxVal = Math.max(...activityData.map(d => d.total || 0), 4);

    const barWidth = Math.min(48, Math.max(16, (chartWidth / activityData.length) * 0.65));
    const step = chartWidth / activityData.length;

    let barsHtml = '';
    activityData.forEach((item, index) => {
        const xCenter = padLeft + (index * step) + (step / 2);
        const x = xCenter - (barWidth / 2);

        const totalAttempts = item.total || 0;
        const succ = item.successful || 0;
        const fail = item.failed || 0;

        const totalHeight = (totalAttempts / maxVal) * chartHeight;
        const succHeight = (succ / maxVal) * chartHeight;
        const failHeight = (fail / maxVal) * chartHeight;

        const yBottom = padTop + chartHeight;
        const yTop = yBottom - totalHeight;

        // Date label formatting (shorten if YYYY-MM-DD)
        const dateParts = (item.date || '').split('-');
        const displayDate = dateParts.length === 3 ? `${dateParts[1]}/${dateParts[2]}` : (item.date || '');

        barsHtml += `
            <g class="chart-bar-group" data-tooltip="${item.date}: ${succ} Success, ${fail} Failed (${totalAttempts} total)">
                <!-- Full bar / Failed base -->
                <rect x="${x}" y="${yTop}" width="${barWidth}" height="${totalHeight}" 
                    rx="4" fill="rgba(239, 68, 68, 0.4)" stroke="#ef4444" stroke-width="1" />
                
                <!-- Successful portion -->
                ${succ > 0 ? `
                <rect x="${x}" y="${yBottom - succHeight}" width="${barWidth}" height="${succHeight}" 
                    rx="4" fill="url(#goldBarGrad)" stroke="#d4af37" stroke-width="1" />
                ` : ''}

                <!-- Top count label -->
                <text x="${xCenter}" y="${yTop - 5}" text-anchor="middle" fill="#d4af37" font-size="11" font-weight="700" font-family="'JetBrains Mono', monospace">
                    ${totalAttempts}
                </text>

                <!-- X Axis Date Label -->
                <text x="${xCenter}" y="${yBottom + 18}" text-anchor="middle" fill="#999" font-size="11" font-family="Inter, sans-serif">
                    ${displayDate}
                </text>
            </g>
        `;
    });

    // Y Axis Grid lines
    let gridLinesHtml = '';
    const ySteps = 3;
    for (let i = 0; i <= ySteps; i++) {
        const val = Math.round((maxVal / ySteps) * i);
        const y = (padTop + chartHeight) - (i / ySteps) * chartHeight;
        gridLinesHtml += `
            <line x1="${padLeft}" y1="${y}" x2="${width - padRight}" y2="${y}" stroke="rgba(255,255,255,0.06)" stroke-dasharray="3 3" />
            <text x="${padLeft - 8}" y="${y + 4}" text-anchor="end" fill="#666" font-size="10" font-family="'JetBrains Mono', monospace">${val}</text>
        `;
    }

    container.innerHTML = `
        <div class="timeline-svg-wrapper">
            <svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet" class="timeline-svg">
                <defs>
                    <linearGradient id="goldBarGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" stop-color="#fde047" />
                        <stop offset="100%" stop-color="#b45309" />
                    </linearGradient>
                </defs>
                <!-- Grid Lines & Y Labels -->
                ${gridLinesHtml}
                
                <!-- Base Axis Line -->
                <line x1="${padLeft}" y1="${padTop + chartHeight}" x2="${width - padRight}" y2="${padTop + chartHeight}" stroke="rgba(212, 175, 55, 0.3)" stroke-width="1.5" />
                
                <!-- Bars -->
                ${barsHtml}
            </svg>
        </div>
        <div class="chart-timeline-legend">
            <span class="legend-mini"><span class="legend-dot gold-dot"></span> Successful</span>
            <span class="legend-mini"><span class="legend-dot red-dot"></span> Failed</span>
        </div>
    `;
}

/**
 * Renders Recent Authentication Activity Table
 */
function renderRecentActivity(records) {
    const tbody = document.getElementById('recent-activity-tbody');
    if (!tbody) return;

    if (!records || records.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="table-empty">
                    <div style="padding: 24px; text-align: center; color: var(--text-muted);">
                        <p style="margin-bottom: 8px;">No recent authentication activity recorded.</p>
                        <a href="/" class="btn btn-primary btn-sm" style="display: inline-block;">Test DFA Authenticator</a>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    let rowsHtml = '';
    records.forEach(rec => {
        const isSuccess = rec.is_success;
        const resultBadge = isSuccess
            ? `<span class="badge badge-success">✓ ACCESS GRANTED</span>`
            : `<span class="badge badge-danger">✗ ACCESS DENIED</span>`;

        const stateBadge = rec.final_state === 'q4'
            ? `<span class="badge badge-gold font-mono">q4 (Accepted)</span>`
            : `<span class="badge badge-subtle font-mono">${escapeHtml(rec.final_state)}</span>`;

        const maskedSeq = rec.input_sequence ? `<code>${escapeHtml(rec.input_sequence)}</code>` : '<span class="text-muted">—</span>';
        const cleanPath = escapeHtml(rec.state_path || rec.final_state || 'q0');

        rowsHtml += `
            <tr>
                <td class="cell-timestamp font-mono">${escapeHtml(rec.timestamp)}</td>
                <td class="cell-result">${resultBadge}</td>
                <td class="cell-state">${stateBadge}</td>
                <td class="cell-seq">${maskedSeq}</td>
                <td class="cell-path font-mono text-muted-sm">${cleanPath}</td>
            </tr>
        `;
    });

    tbody.innerHTML = rowsHtml;
}

/**
 * Handles Passcode Change in Modal
 */
async function handlePasscodeUpdate(e) {
    e.preventDefault();
    const curr = (document.getElementById('modal-curr-passcode').value || '').trim();
    const newP = (document.getElementById('modal-new-passcode').value || '').trim();
    const conf = (document.getElementById('modal-conf-passcode').value || '').trim();
    const alertEl = document.getElementById('passcode-modal-alert');
    const submitBtn = document.getElementById('submit-passcode-btn');

    if (!curr || !newP || !conf) {
        showModalAlert('Please fill in all passcode fields.', 'danger');
        return;
    }

    if (newP.length !== 4) {
        showModalAlert('New passcode must be exactly 4 characters.', 'danger');
        return;
    }

    if (newP !== conf) {
        showModalAlert('New passcode and confirmation do not match.', 'danger');
        return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Updating...';

    try {
        const res = await fetch('/api/change-passcode', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                current_passcode: curr,
                new_passcode: newP,
                confirm_passcode: conf
            })
        });

        const data = await res.json();
        if (data.success) {
            showModalAlert('✓ Passcode changed successfully! Your DFA machine sequence is now updated.', 'success');
            setTimeout(() => {
                const modal = document.getElementById('change-passcode-modal');
                if (modal) modal.style.display = 'none';
                resetPasscodeModal();
                loadDashboardData();
            }, 1400);
        } else {
            showModalAlert(data.error || 'Failed to update passcode.', 'danger');
        }
    } catch (err) {
        showModalAlert('Network error updating passcode. Please try again.', 'danger');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Update Passcode';
    }
}

function showModalAlert(msg, type) {
    const alertEl = document.getElementById('passcode-modal-alert');
    if (!alertEl) return;
    alertEl.style.display = 'block';
    alertEl.className = `alert-box alert-${type}`;
    alertEl.textContent = msg;
}

function resetPasscodeModal() {
    const form = document.getElementById('dash-passcode-form');
    if (form) form.reset();
    const alertEl = document.getElementById('passcode-modal-alert');
    if (alertEl) alertEl.style.display = 'none';
}

/**
 * Handles Logout
 */
async function handleLogout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
    } catch (e) {
        // ignore
    } finally {
        window.location.href = '/';
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
