/**
 * DNS Spoofing Simulation Framework - Dashboard & Multi-Tab JS
 */

document.addEventListener('DOMContentLoaded', () => {
    // State
    let charts = {};
    let currentEvents = [];
    let currentAlerts = [];
    let activeTab = 'dashboard';

    // DOM Elements - Navigation & Headers
    const navItems = document.querySelectorAll('.nav-item');
    const pageTitleEl = document.getElementById('page-title');
    const tabContents = document.querySelectorAll('.page-tab-content');

    // Dashboard Elements
    const totalQueriesEl = document.getElementById('total-queries');
    const suspiciousQueriesEl = document.getElementById('suspicious-queries');
    const spoofedEventsEl = document.getElementById('spoofed-events');
    const criticalAlertsEl = document.getElementById('critical-alerts');
    const runDemoBtn = document.getElementById('run-demo-btn');
    const interfaceSelect = document.getElementById('interface-select');
    const toggleMonitorBtn = document.getElementById('toggle-monitor-btn');

    // Modal
    const modal = document.getElementById('event-modal');
    const modalBody = document.getElementById('modal-body');
    const modalClose = document.getElementById('modal-close');

    // Initialize Application
    init();

    function init() {
        initCharts();
        initThreeLogoCanvas();
        init3DHackerMatrixBackground();
        setupNavigation();
        setupEventListeners();

        // Check initial tab from URL path
        const path = window.location.pathname.replace('/', '');
        if (path && ['dashboard', 'events', 'alerts', 'pcap', 'settings'].includes(path)) {
            switchTab(path, false);
        } else {
            switchTab('dashboard', false);
        }

        loadMonitorInterfaces();
        checkMonitorStatus();

        // Auto refresh every 10 seconds
        setInterval(refreshActiveTab, 10000);
        setInterval(checkMonitorStatus, 5000);
    }

    function setupNavigation() {
        navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const page = item.dataset.page || item.getAttribute('href').replace('/', '');
                if (page) {
                    switchTab(page, true);
                }
            });
        });

        window.addEventListener('popstate', () => {
            const path = window.location.pathname.replace('/', '') || 'dashboard';
            switchTab(path, false);
        });
    }

    function switchTab(tabName, pushState = true) {
        activeTab = tabName;

        // Update active class on nav links
        navItems.forEach(item => {
            const page = item.dataset.page || item.getAttribute('href').replace('/', '');
            if (page === tabName) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });

        // Update page title
        if (pageTitleEl) {
            const titleMap = {
                'dashboard': 'Dashboard',
                'events': 'DNS Events',
                'alerts': 'Security Alerts',
                'pcap': 'PCAP Packet Analysis',
                'settings': 'Settings & Baseline Configuration'
            };
            pageTitleEl.textContent = titleMap[tabName] || 'Dashboard';
        }

        // Hide all tab contents, show active
        tabContents.forEach(content => {
            if (content.id === `${tabName}-content`) {
                content.style.display = 'block';
                content.classList.add('active');
            } else {
                content.style.display = 'none';
                content.classList.remove('active');
            }
        });

        if (pushState && window.location.pathname !== `/${tabName}`) {
            history.pushState({}, '', `/${tabName === 'dashboard' ? '' : tabName}`);
        }

        // Load specific data for active tab
        refreshActiveTab();
    }

    function refreshActiveTab() {
        if (activeTab === 'dashboard') {
            loadDashboardData();
        } else if (activeTab === 'events') {
            loadEventsTab();
        } else if (activeTab === 'alerts') {
            loadAlertsTab();
        } else if (activeTab === 'settings') {
            loadSettingsTab();
        }
    }

    function setupEventListeners() {
        // Refresh buttons
        const refreshBtn = document.getElementById('refresh-btn');
        if (refreshBtn) refreshBtn.addEventListener('click', loadDashboardData);

        const eventsRefreshBtn = document.getElementById('events-tab-refresh');
        if (eventsRefreshBtn) eventsRefreshBtn.addEventListener('click', loadEventsTab);

        const alertsRefreshBtn = document.getElementById('alerts-refresh-btn');
        if (alertsRefreshBtn) alertsRefreshBtn.addEventListener('click', loadAlertsTab);

        const trustedRefreshBtn = document.getElementById('refresh-trusted-btn');
        if (trustedRefreshBtn) trustedRefreshBtn.addEventListener('click', loadTrustedDomains);

        // Header buttons
        if (runDemoBtn) runDemoBtn.addEventListener('click', handleRunDemo);
        if (toggleMonitorBtn) toggleMonitorBtn.addEventListener('click', handleToggleMonitor);

        const exportBtn = document.getElementById('export-report-btn');
        const exportMenu = document.getElementById('export-menu');
        if (exportBtn && exportMenu) {
            exportBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                exportMenu.style.display = exportMenu.style.display === 'none' ? 'block' : 'none';
            });
            document.addEventListener('click', () => {
                exportMenu.style.display = 'none';
            });
        }

        // Filters
        const searchInput = document.getElementById('event-search');
        if (searchInput) searchInput.addEventListener('input', () => filterAndRenderEvents('events-body', currentEvents, searchInput, document.getElementById('severity-filter')));

        const severityFilter = document.getElementById('severity-filter');
        if (severityFilter) severityFilter.addEventListener('change', () => filterAndRenderEvents('events-body', currentEvents, searchInput, severityFilter));

        const eventsSearch = document.getElementById('events-tab-search');
        const eventsSeverity = document.getElementById('events-tab-severity');
        if (eventsSearch) eventsSearch.addEventListener('input', () => filterAndRenderEvents('events-tab-body', currentEvents, eventsSearch, eventsSeverity));
        if (eventsSeverity) eventsSeverity.addEventListener('change', () => filterAndRenderEvents('events-tab-body', currentEvents, eventsSearch, eventsSeverity));

        const alertsSeverity = document.getElementById('alerts-severity-filter');
        if (alertsSeverity) alertsSeverity.addEventListener('change', loadAlertsTab);

        // PCAP Upload Form
        const pcapForm = document.getElementById('pcap-upload-form');
        if (pcapForm) pcapForm.addEventListener('submit', handlePcapUpload);

        // Settings Forms
        const trustedForm = document.getElementById('add-trusted-form');
        if (trustedForm) trustedForm.addEventListener('submit', handleAddTrustedDomain);

        const clearSimBtn = document.getElementById('clear-sim-btn');
        if (clearSimBtn) clearSimBtn.addEventListener('click', handleClearSimulation);

        // Modal close
        if (modalClose) modalClose.addEventListener('click', closeModal);
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal || e.target.classList.contains('modal-overlay')) closeModal();
            });
        }
    }

    // ==================== TAB LOADERS ====================

    async function loadDashboardData() {
        await Promise.all([
            fetchStats(),
            fetchEvents(),
            fetchChartData()
        ]);
    }

    async function loadEventsTab() {
        await fetchEvents();
        filterAndRenderEvents('events-tab-body', currentEvents, document.getElementById('events-tab-search'), document.getElementById('events-tab-severity'));
    }

    async function loadAlertsTab() {
        const body = document.getElementById('alerts-table-body');
        if (!body) return;
        const severitySelect = document.getElementById('alerts-severity-filter');
        const selectedSeverity = severitySelect ? severitySelect.value : '';

        try {
            const url = selectedSeverity ? `/api/alerts?severity=${encodeURIComponent(selectedSeverity)}` : '/api/alerts';
            const res = await fetch(url);
            if (!res.ok) return;
            currentAlerts = await res.json();

            if (currentAlerts.length === 0) {
                body.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 24px;">No alerts recorded.</td></tr>`;
                return;
            }

            body.innerHTML = currentAlerts.map(alert => `
                <tr>
                    <td>${alert.timestamp ? new Date(alert.timestamp).toLocaleString() : 'N/A'}</td>
                    <td><span class="badge badge-${(alert.severity || 'low').toLowerCase()}">${alert.severity}</span></td>
                    <td><strong>${escapeHtml(alert.title)}</strong></td>
                    <td style="max-width: 400px;">${escapeHtml(alert.description)}</td>
                    <td>
                        <button class="btn btn-sm btn-danger delete-alert-btn" data-id="${alert.id}">
                            🗑️ Delete
                        </button>
                    </td>
                </tr>
            `).join('');

            body.querySelectorAll('.delete-alert-btn').forEach(btn => {
                btn.addEventListener('click', () => handleDeleteAlert(btn.dataset.id));
            });
        } catch (err) {
            console.error('Error fetching alerts:', err);
        }
    }

    async function loadSettingsTab() {
        await loadTrustedDomains();
    }

    async function loadTrustedDomains() {
        const body = document.getElementById('trusted-domains-body');
        if (!body) return;

        try {
            const res = await fetch('/api/trusted-domains');
            if (!res.ok) return;
            const domains = await res.json();

            if (domains.length === 0) {
                body.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">No trusted baseline domains configured. Add one above!</td></tr>`;
                return;
            }

            body.innerHTML = domains.map(d => `
                <tr>
                    <td>${d.id}</td>
                    <td><strong>${escapeHtml(d.domain)}</strong></td>
                    <td><span class="badge badge-secondary">${escapeHtml(d.expected_ip)}</span></td>
                    <td>${d.expected_ttl_min ?? 300}s - ${d.expected_ttl_max ?? 86400}s</td>
                    <td><span class="status-tag status-normal">ACTIVE</span></td>
                </tr>
            `).join('');
        } catch (err) {
            console.error('Error loading trusted domains:', err);
        }
    }

    // ==================== API ACTIONS ====================

    async function fetchStats() {
        try {
            const res = await fetch('/api/dashboard-stats');
            if (!res.ok) return;
            const stats = await res.json();

            if (totalQueriesEl) totalQueriesEl.textContent = stats.total_queries ?? 0;
            if (suspiciousQueriesEl) suspiciousQueriesEl.textContent = stats.suspicious_queries ?? 0;
            if (spoofedEventsEl) spoofedEventsEl.textContent = stats.spoofed_events ?? 0;
            if (criticalAlertsEl) criticalAlertsEl.textContent = stats.critical_alerts ?? 0;

            updateSeverityChart(stats.severity_distribution || {});
            updateDomainsChart(stats.top_domains || []);
        } catch (err) {
            console.error('Error fetching stats:', err);
        }
    }

    async function fetchEvents() {
        try {
            const res = await fetch('/api/dns-events?limit=100');
            if (!res.ok) return;
            currentEvents = await res.json();
            filterAndRenderEvents('events-body', currentEvents, document.getElementById('event-search'), document.getElementById('severity-filter'));
        } catch (err) {
            console.error('Error fetching events:', err);
        }
    }

    async function fetchChartData() {
        try {
            const res = await fetch('/api/charts/events-over-time?hours=24');
            if (!res.ok) return;
            const data = await res.json();
            updateTimeSeriesCharts(data);
        } catch (err) {
            console.error('Error fetching chart data:', err);
        }
    }

    function filterAndRenderEvents(tableBodyId, eventsList, searchEl, severityEl) {
        const body = document.getElementById(tableBodyId);
        if (!body) return;

        const query = searchEl ? searchEl.value.toLowerCase().trim() : '';
        const selectedSeverity = severityEl ? severityEl.value : '';

        const filtered = eventsList.filter(ev => {
            const matchesDomain = !query || (ev.domain && ev.domain.toLowerCase().includes(query));
            const matchesSeverity = !selectedSeverity || ev.severity === selectedSeverity;
            return matchesDomain && matchesSeverity;
        });

        if (filtered.length === 0) {
            body.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 20px;">No matching DNS events found.</td></tr>`;
            return;
        }

        body.innerHTML = filtered.map(ev => {
            const timeStr = ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'N/A';
            const sevClass = (ev.severity || 'low').toLowerCase();
            const statusClass = (ev.status || 'normal').toLowerCase();

            return `
                <tr>
                    <td>${timeStr}</td>
                    <td><strong>${escapeHtml(ev.domain)}</strong></td>
                    <td><span class="badge badge-secondary">${escapeHtml(ev.query_type || 'A')}</span></td>
                    <td>${escapeHtml(ev.expected_ip || 'N/A')}</td>
                    <td class="${ev.response_ip !== ev.expected_ip && ev.expected_ip ? 'text-danger' : ''}">
                        ${escapeHtml(ev.response_ip || 'N/A')}
                    </td>
                    <td>
                        <span class="risk-score risk-${getRiskLevel(ev.risk_score)}">
                            ${ev.risk_score}
                        </span>
                    </td>
                    <td><span class="badge badge-${sevClass}">${ev.severity || 'LOW'}</span></td>
                    <td><span class="status-tag status-${statusClass}">${ev.status || 'NORMAL'}</span></td>
                    <td>
                        <button class="btn btn-sm btn-outline view-event-btn" data-id="${ev.id}">
                            View
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        body.querySelectorAll('.view-event-btn').forEach(btn => {
            btn.addEventListener('click', () => openEventModal(btn.dataset.id));
        });
    }

    async function handlePcapUpload(e) {
        e.preventDefault();
        const fileInput = document.getElementById('pcap-file-input');
        const msg = document.getElementById('pcap-status-msg');
        const btn = document.getElementById('upload-pcap-btn');
        const resultsContainer = document.getElementById('pcap-results-container');
        const resultsBody = document.getElementById('pcap-results-body');
        const badge = document.getElementById('pcap-summary-badge');

        if (!fileInput || !fileInput.files.length) return;

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);

        btn.disabled = true;
        msg.style.color = 'var(--text-primary)';
        msg.textContent = '⏳ Analyzing PCAP packet capture...';

        try {
            const res = await fetch('/api/analyze-pcap', { method: 'POST', body: formData });
            const data = await res.json();

            if (!res.ok) throw new Error(data.detail || 'PCAP analysis failed');

            msg.style.color = 'var(--accent-green)';
            msg.textContent = `✅ Successfully analyzed ${data.filename}: Extracted ${data.records_found} records (${data.events_analyzed} analyzed).`;

            if (resultsContainer && resultsBody) {
                resultsContainer.style.display = 'block';
                if (badge) badge.textContent = `${data.events_analyzed} Events Analyzed`;

                resultsBody.innerHTML = (data.results || []).map(r => `
                    <tr>
                        <td>${r.id}</td>
                        <td><strong>${escapeHtml(r.domain)}</strong></td>
                        <td>${escapeHtml(r.response_ip || 'N/A')}</td>
                        <td><span class="risk-score risk-${getRiskLevel(r.risk_score)}">${r.risk_score}</span></td>
                        <td><span class="badge badge-${(r.severity || 'low').toLowerCase()}">${r.severity}</span></td>
                        <td><span class="status-tag status-${(r.status || 'normal').toLowerCase()}">${r.status}</span></td>
                    </tr>
                `).join('');
            }
        } catch (err) {
            msg.style.color = 'var(--accent-red)';
            msg.textContent = `❌ ${err.message}`;
        } finally {
            btn.disabled = false;
        }
    }

    async function handleAddTrustedDomain(e) {
        e.preventDefault();
        const domainInput = document.getElementById('trusted-domain-input');
        const ipInput = document.getElementById('trusted-ip-input');
        const msg = document.getElementById('trusted-msg');

        if (!domainInput || !ipInput) return;

        const domain = domainInput.value.trim();
        const expectedIp = ipInput.value.trim();

        try {
            const res = await fetch(`/api/load-trusted-domain?domain=${encodeURIComponent(domain)}&expected_ip=${encodeURIComponent(expectedIp)}`, { method: 'POST' });
            if (!res.ok) throw new Error('Failed to add trusted domain');

            msg.style.color = 'var(--accent-green)';
            msg.textContent = `✅ Added ${domain} -> ${expectedIp} to trusted baseline!`;
            domainInput.value = '';
            ipInput.value = '';
            await loadTrustedDomains();
        } catch (err) {
            msg.style.color = 'var(--accent-red)';
            msg.textContent = `❌ Error: ${err.message}`;
        }
    }

    async function handleClearSimulation() {
        const msg = document.getElementById('clear-sim-msg');
        try {
            const res = await fetch('/api/dns-events/clear-simulation', { method: 'DELETE' });
            const data = await res.json();
            if (msg) {
                msg.style.color = 'var(--accent-green)';
                msg.textContent = `✅ ${data.message}`;
            }
            refreshActiveTab();
        } catch (err) {
            if (msg) {
                msg.style.color = 'var(--accent-red)';
                msg.textContent = `❌ ${err.message}`;
            }
        }
    }

    async function handleDeleteAlert(alertId) {
        try {
            const res = await fetch(`/api/alerts/${alertId}`, { method: 'DELETE' });
            if (res.ok) {
                await loadAlertsTab();
            }
        } catch (err) {
            console.error('Error deleting alert:', err);
        }
    }

    async function openEventModal(eventId) {
        if (!modal || !modalBody) return;
        modalBody.innerHTML = '<div style="text-align: center; padding: 30px;">Loading event details...</div>';
        modal.classList.add('active');

        try {
            const res = await fetch(`/api/dns-events/${eventId}`);
            if (!res.ok) throw new Error('Event not found');
            const mitreMapping = {
                'unexpected_ip': 'T1557.006 (DNS Spoofing)',
                'unexpected_dns_server': 'T1071.004 (Rogue DNS Server)',
                'ttl_anomaly': 'T1557.006 (TTL Poisoning)',
                'repeated_suspicious': 'T1557.006 (Persistent Poisoning)',
                'multiple_ip_changes': 'T1568.002 (Fast-Flux DNS)',
                'dga_entropy': 'T1568.002 / T1071.004 (DGA & Tunneling)',
                'fast_flux': 'T1568.002 (Ultra-short TTL Fast-Flux)',
                'no_baseline': 'T1557 (Unmonitored Domain)'
            };

            const reasonsHtml = data.detection_reasons && data.detection_reasons.length > 0
                ? data.detection_reasons.map(r => `
                    <div class="reason-item ${r.triggered ? 'triggered' : ''}" style="margin: 8px 0; padding: 12px; border-radius: 6px; background: var(--bg-hover);">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <strong>${escapeHtml(r.rule || 'Rule')}:</strong>
                            ${r.rule && mitreMapping[r.rule] ? `<span class="badge badge-secondary" style="font-size:10px;">${mitreMapping[r.rule]}</span>` : ''}
                        </div>
                        <p style="margin:6px 0 0 0; color:var(--text-secondary); font-size:13px;">${escapeHtml(r.description || '')}</p>
                        ${r.triggered ? `<span class="badge badge-critical" style="margin-top:6px; display:inline-block;">+${r.score} Risk Points</span>` : ''}
                    </div>
                `).join('')
                : '<p>No detection rules triggered.</p>';

            modalBody.innerHTML = `
                <div class="modal-event-detail">
                    <div class="detail-header" style="display: flex; justify-content: space-between; align-items: center;">
                        <h3>${escapeHtml(data.domain)}</h3>
                        <span class="badge badge-${(data.severity || 'low').toLowerCase()}">${data.severity}</span>
                    </div>

                    <div class="detail-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 15px 0;">
                        <div><strong>Timestamp:</strong> ${data.timestamp ? new Date(data.timestamp).toLocaleString() : 'N/A'}</div>
                        <div><strong>Source IP:</strong> ${escapeHtml(data.source_ip || 'N/A')}</div>
                        <div><strong>Query Type:</strong> ${escapeHtml(data.query_type || 'A')}</div>
                        <div><strong>DNS Server:</strong> ${escapeHtml(data.dns_server || 'N/A')}</div>
                        <div><strong>Expected IP:</strong> ${escapeHtml(data.expected_ip || 'N/A')}</div>
                        <div><strong>Received IP:</strong> ${escapeHtml(data.response_ip || 'N/A')}</div>
                        <div><strong>TTL:</strong> ${data.ttl ?? 'N/A'} s</div>
                        <div><strong>Risk Score:</strong> <span class="risk-score risk-${getRiskLevel(data.risk_score)}">${data.risk_score} / 100</span></div>
                    </div>

                    <h4>🎯 MITRE ATT&CK Analysis & Triggered Rules</h4>
                    <div class="reasons-list">${reasonsHtml}</div>
                </div>
            `;
        } catch (err) {
            modalBody.innerHTML = `<div style="color: red; padding: 20px;">Failed to load details: ${err.message}</div>`;
        }
    }

    function closeModal() {
        if (modal) modal.classList.remove('active');
    }

    async function handleRunDemo() {
        if (!runDemoBtn) return;
        const originalText = runDemoBtn.innerHTML;
        runDemoBtn.disabled = true;
        runDemoBtn.innerHTML = '<span>⏳</span> Simulating...';

        try {
            const res = await fetch('/api/simulate-batch?count=10', { method: 'POST' });
            if (res.ok) {
                refreshActiveTab();
            }
        } catch (err) {
            console.error('Demo simulation error:', err);
        } finally {
            runDemoBtn.disabled = false;
            runDemoBtn.innerHTML = originalText;
        }
    }

    // Live Sniffing Monitor Controls
    async function loadMonitorInterfaces() {
        if (!interfaceSelect) return;
        try {
            const res = await fetch('/api/monitor/interfaces');
            if (!res.ok) return;
            const data = await res.json();
            const ifaces = data.interfaces || [];

            interfaceSelect.innerHTML = '<option value="">Interface: Default (Any)</option>' +
                ifaces.map(iface => `<option value="${escapeHtml(iface)}">${escapeHtml(iface)}</option>`).join('');
        } catch (err) {
            console.error('Error fetching interfaces:', err);
        }
    }

    async function checkMonitorStatus() {
        if (!toggleMonitorBtn) return;
        try {
            const res = await fetch('/api/monitor/status');
            if (!res.ok) return;
            const status = await res.json();

            if (status.running) {
                toggleMonitorBtn.classList.remove('btn-secondary');
                toggleMonitorBtn.classList.add('btn-danger');
                toggleMonitorBtn.innerHTML = `<span>🔴</span> Stop Sniffing (${status.packet_count || 0})`;
            } else {
                toggleMonitorBtn.classList.remove('btn-danger');
                toggleMonitorBtn.classList.add('btn-secondary');
                toggleMonitorBtn.innerHTML = '<span>📡</span> Start Sniffing';
            }
        } catch (err) {
            console.error('Error checking monitor status:', err);
        }
    }

    async function handleToggleMonitor() {
        if (!toggleMonitorBtn) return;
        toggleMonitorBtn.disabled = true;

        try {
            const statusRes = await fetch('/api/monitor/status');
            const status = await statusRes.json();

            if (status.running) {
                await fetch('/api/monitor/stop', { method: 'POST' });
                appendTerminalLog('t-yellow', 'MONITOR', 'Live packet capture stopped.');
            } else {
                const selectedIface = interfaceSelect ? interfaceSelect.value : '';
                const url = selectedIface ? `/api/monitor/start?interface=${encodeURIComponent(selectedIface)}` : '/api/monitor/start';
                const startRes = await fetch(url, { method: 'POST' });
                const data = await startRes.json();

                if (!startRes.ok || data.error) {
                    const errMsg = data.detail || data.message || 'Live network sniffing requires root/sudo privileges (e.g. sudo ./run.sh on Kali Linux). In web/cloud mode, use PCAP analysis or Demo mode!';
                    alert(`⚠️ Sniffing Notice: ${errMsg}`);
                    appendTerminalLog('t-red', 'MONITOR_ERR', errMsg);
                } else {
                    appendTerminalLog('t-green', 'MONITOR', `Started live packet capture on interface '${selectedIface || 'default'}'`);
                }
            }

            await checkMonitorStatus();
        } catch (err) {
            console.error('Error toggling monitor:', err);
            alert(`⚠️ Sniffing Error: ${err.message}`);
        } finally {
            toggleMonitorBtn.disabled = false;
        }
    }

    // Chart Initialization
    function initCharts() {
        if (typeof Chart === 'undefined') return;

        const queriesCtx = document.getElementById('queriesChart');
        if (queriesCtx) {
            charts.queries = new Chart(queriesCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Total Queries',
                        data: [],
                        borderColor: '#4f46e5',
                        backgroundColor: 'rgba(79, 70, 229, 0.1)',
                        fill: true,
                        tension: 0.3
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false }
            });
        }

        const severityCtx = document.getElementById('severityChart');
        if (severityCtx) {
            charts.severity = new Chart(severityCtx, {
                type: 'doughnut',
                data: {
                    labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#10b981', '#f59e0b', '#f97316', '#ef4444']
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false }
            });
        }

        const suspiciousCtx = document.getElementById('suspiciousChart');
        if (suspiciousCtx) {
            charts.suspicious = new Chart(suspiciousCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Suspicious Events',
                        data: [],
                        backgroundColor: '#ef4444'
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false }
            });
        }

        const domainsCtx = document.getElementById('domainsChart');
        if (domainsCtx) {
            charts.domains = new Chart(domainsCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Query Count',
                        data: [],
                        backgroundColor: '#6366f1'
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, indexAxis: 'y' }
            });
        }
    }

    function updateTimeSeriesCharts(data) {
        if (!data || !Array.isArray(data)) return;
        const labels = data.map(d => d.time ? d.time.split(' ')[1] || d.time : '');
        const totals = data.map(d => d.total);
        const suspicious = data.map(d => d.suspicious);

        if (charts.queries) {
            charts.queries.data.labels = labels;
            charts.queries.data.datasets[0].data = totals;
            charts.queries.update();
        }

        if (charts.suspicious) {
            charts.suspicious.data.labels = labels;
            charts.suspicious.data.datasets[0].data = suspicious;
            charts.suspicious.update();
        }
    }

    function updateSeverityChart(dist) {
        if (charts.severity) {
            charts.severity.data.datasets[0].data = [
                dist.LOW || 0,
                dist.MEDIUM || 0,
                dist.HIGH || 0,
                dist.CRITICAL || 0
            ];
            charts.severity.update();
        }
    }

    function updateDomainsChart(domains) {
        if (charts.domains) {
            charts.domains.data.labels = domains.map(d => d.domain);
            charts.domains.data.datasets[0].data = domains.map(d => d.count);
            charts.domains.update();
        }
    }

    // 3D Technical Logo Canvas (Three.js)
    function initThreeLogoCanvas() {
        const canvas = document.getElementById('three-logo-canvas');
        if (!canvas || typeof THREE === 'undefined') return;

        try {
            const scene = new THREE.Scene();
            const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
            camera.position.z = 2.8;

            const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
            renderer.setSize(48, 48);

            // Outer 3D wireframe cyber sphere
            const geometry = new THREE.IcosahedronGeometry(1.0, 1);
            const material = new THREE.MeshBasicMaterial({
                color: 0x39d3c3,
                wireframe: true,
                transparent: true,
                opacity: 0.8
            });
            const sphere = new THREE.Mesh(geometry, material);
            scene.add(sphere);

            // Inner glowing core
            const coreGeo = new THREE.OctahedronGeometry(0.45, 0);
            const coreMat = new THREE.MeshBasicMaterial({
                color: 0x38bdf8,
                wireframe: false,
                transparent: true,
                opacity: 0.9
            });
            const core = new THREE.Mesh(coreGeo, coreMat);
            scene.add(core);

            function animate() {
                requestAnimationFrame(animate);
                sphere.rotation.x += 0.01;
                sphere.rotation.y += 0.015;
                core.rotation.x -= 0.02;
                core.rotation.y -= 0.01;
                renderer.render(scene, camera);
            }
            animate();
        } catch (err) {
            console.warn('Three.js canvas init skipped:', err);
        }
    }

    // 3D Hacker Matrix Background Canvas Renderer
    function init3DHackerMatrixBackground() {
        const canvas = document.getElementById('hacker-bg-canvas');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        let width = canvas.width = window.innerWidth;
        let height = canvas.height = window.innerHeight;

        window.addEventListener('resize', () => {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
        });

        // Matrix Cyber Glyphs & Hex Tokens
        const chars = '01ABCDEFGHJKLMNPQRSTUVWXYZ0123456789$#@%&*[]{}<>/\\|:=+~T1557T1568DNS'.split('');
        const fontSize = 14;
        const columns = Math.floor(width / fontSize);
        const drops = [];

        // Initialize drop positions & 3D z-depth opacity
        for (let i = 0; i < columns; i++) {
            drops[i] = {
                y: Math.random() * -100,
                speed: 1 + Math.random() * 2,
                opacity: 0.2 + Math.random() * 0.8,
                color: Math.random() > 0.85 ? '#39d3c3' : (Math.random() > 0.95 ? '#38bdf8' : '#34d399')
            };
        }

        function drawMatrix() {
            // Translucent fade overlay for trailing effect
            ctx.fillStyle = 'rgba(9, 13, 20, 0.12)';
            ctx.fillRect(0, 0, width, height);

            ctx.font = `${fontSize}px 'JetBrains Mono', monospace`;

            for (let i = 0; i < drops.length; i++) {
                const drop = drops[i];
                const char = chars[Math.floor(Math.random() * chars.length)];
                const x = i * fontSize;
                const y = drop.y * fontSize;

                ctx.fillStyle = drop.color;
                ctx.globalAlpha = drop.opacity;
                ctx.fillText(char, x, y);

                // Reset drop when hitting bottom
                if (y > height && Math.random() > 0.975) {
                    drop.y = 0;
                    drop.speed = 1 + Math.random() * 2;
                }
                drop.y += drop.speed * 0.5;
            }
            ctx.globalAlpha = 1.0;
            requestAnimationFrame(drawMatrix);
        }

        drawMatrix();

        // Start periodic terminal CLI log streaming simulation
        setInterval(streamRandomHackerLog, 3000);
    }

    function appendTerminalLog(tagClass, tagText, msg) {
        const stream = document.getElementById('live-terminal-stream');
        if (!stream) return;

        const timeStr = new Date().toLocaleTimeString();
        const line = document.createElement('div');
        line.className = 'terminal-line';
        line.innerHTML = `<span class="${tagClass}">[${timeStr} ${tagText}]</span> ${escapeHtml(msg)}`;

        stream.appendChild(line);

        // Keep last 50 lines
        while (stream.children.length > 50) {
            stream.removeChild(stream.firstChild);
        }

        stream.scrollTop = stream.scrollHeight;
    }

    function streamRandomHackerLog() {
        const logs = [
            { class: 't-green', tag: 'PACKET_SNIFFER', msg: 'Captured DNS response query (UDP/53) -> A record validated' },
            { class: 't-cyan', tag: 'ANOMALY_ENGINE', msg: 'Evaluating Shannon Entropy H(X)... Label entropy within baseline threshold' },
            { class: 't-yellow', tag: 'CACHE_CHECK', msg: 'Querying in-memory trusted domain cache... Match hit (0.001ms)' },
            { class: 't-purple', tag: 'MITRE_MATRIX', msg: 'T1557.006 rule verification complete: 0 threat indicators triggered' },
            { class: 't-green', tag: 'SQLITE_WAL', msg: 'Flushed batch logs to SQLite WAL journal mode [64MB Page Cache OK]' }
        ];

        const randomLog = logs[Math.floor(Math.random() * logs.length)];
        appendTerminalLog(randomLog.class, randomLog.tag, randomLog.msg);
    }

    // Helper functions
    function getRiskLevel(score) {
        if (score >= 80) return 'critical';
        if (score >= 60) return 'high';
        if (score >= 30) return 'medium';
        return 'low';
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
});