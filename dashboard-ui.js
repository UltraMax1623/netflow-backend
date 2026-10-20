/* Real capture charts, graph aggregation, and readable evidence. */
const chartInstances = {};
let latestResult = null;
const byId = id => document.getElementById(id);
const numberText = value => value == null ? 'Not available' : Number(value).toLocaleString(undefined, {maximumFractionDigits: 2});
const dateText = value => value == null ? 'Not available' : new Date(value * 1000).toLocaleString();
function byteText(value) {
    if (value == null) return 'Unknown';
    const units = ['B', 'KiB', 'MiB', 'GiB'];
    let index = 0;
    while (value >= 1024 && index < 3) { value /= 1024; index++; }
    return `${numberText(value)} ${units[index]}`;
}
function textElement(tag, text, className = '') {
    const node = document.createElement(tag);
    node.textContent = text;
    node.className = className;
    return node;
}
function initCharts() {
    if (typeof Chart !== 'function') {
        byId('chart-note').textContent = 'Chart library unavailable. Check your internet connection and reload.';
        return;
    }
    Chart.defaults.font.family = "'Inter', sans-serif";
    const definitions = [
        ['trafficChart', 'line', 'Throughput (Mbps)'], ['protocolChart', 'bar', 'Packets'],
        ['usageChart', 'doughnut', 'Packets'], ['packetSizeChart', 'bar', 'Packets'],
        ['rateChart', 'line', 'Packets/s'], ['destinationChart', 'bar', 'Packets to destination'],
        ['handshakeChart', 'bar', 'Count'], ['sourceChart', 'bar', 'Packets from source']
    ];
    for (const [id, type, label] of definitions) {
        chartInstances[id] = new Chart(byId(id), {
            type, data: {labels: [], datasets: [{label, data: [], borderColor: '#2563eb',
                backgroundColor: type === 'doughnut' ? ['#2563eb','#0d9488','#f59e0b','#e11d48','#8b5cf6','#64748b'] : '#60a5fa',
                borderWidth: 2, pointRadius: 0, tension: 0.15}]},
            options: {responsive: true, maintainAspectRatio: false, animation: false,
                plugins: {legend: {display: type === 'doughnut', position: 'right'}},
                ...(type === 'doughnut' ? {} : {scales: {y: {beginAtZero: true}, x: {ticks: {maxTicksLimit: 6}}}})}
        });
    }
}
function setChart(id, labels, values) {
    const chart = chartInstances[id];
    if (!chart) return;
    chart.data.labels = labels;
    chart.data.datasets[0].data = values;
    chart.update();
}
function renderAnalytics(result) {
    latestResult = result;
    const data = result?.analytics;
    const summary = data?.summary;
    const timeline = data?.timeline || [];
    const times = timeline.map(b => new Date(b.time * 1000).toLocaleTimeString());
    const tcp = data?.tcp;
    setChart('trafficChart', times, timeline.map(b => b.mbps));
    setChart('rateChart', times, timeline.map(b => b.pps));
    if (chartInstances.rateChart) {
        const chart = chartInstances.rateChart;
        chart.data.datasets[0].label = 'All packets/s';
        chart.data.datasets.splice(1);
        for (const [key, label, color] of [['syn','SYN/s','#e11d48'], ['icmp','ICMP/s','#d97706']]) {
            chart.data.datasets.push({label, data: timeline.map(b => (b[key] || 0) / data.bin_seconds),
                borderColor: color, backgroundColor: color, pointRadius: 0, borderWidth: 2});
        }
        chart.options.plugins.legend.display = true;
        chart.update();
    }
    for (const [id, values] of [['protocolChart', data?.protocols], ['usageChart', data?.protocols],
        ['packetSizeChart', data?.packet_sizes], ['destinationChart', data?.top_destinations], ['sourceChart', data?.top_sources]]) {
        setChart(id, Object.keys(values || {}), Object.values(values || {}));
    }
    setChart('handshakeChart', ['SYN packets', 'SYN-ACK packets', 'Unique attempts', 'Completed', 'RST packets'],
        tcp ? [tcp.syn_packets, tcp.syn_ack_packets, tcp.unique_syn_attempts, tcp.completed_handshakes, tcp.resets] : []);
    byId('chart-note').textContent = summary
        ? `${dateText(summary.start_time)} → ${dateText(summary.end_time)} · ${numberText(data.bin_seconds)}s chart bins · charts cover the whole capture window; graph filters do not change these totals.`
        : 'Upload a capture or start live capture. Charts contain no sample data.';
    const metrics = byId('capture-metrics');
    metrics.replaceChildren();
    for (const [label, value] of [['Packets', summary ? numberText(summary.total_packets) : '—'],
        ['Captured bytes', summary ? byteText(summary.total_bytes) : '—'],
        ['Average packets/s', summary ? numberText(summary.average_pps) : '—'],
        ['Source IPs', summary ? numberText(summary.unique_sources) : '—']]) {
        const card = textElement('div', '', 'metric');
        card.append(textElement('span', label), textElement('strong', value));
        metrics.append(card);
    }
    document.querySelectorAll('[data-protocol-count]').forEach(node => {
        const kind = node.dataset.protocolCount;
        const aliases = {DHCP: 'DHCP port'};
        const value = data ? data.protocols[kind] ?? data.services[aliases[kind] || kind] ?? 0 : null;
        node.textContent = value == null ? 'No capture' : `${numberText(value)} packets`;
    });
    renderSecurity(data?.security, summary);
    byId('download-report').disabled = !result;
    byId('download-json').disabled = !result;
    byId('use-baseline').disabled = !(summary?.average_pps > 0);
    byId('report-summary').textContent = result
        ? `${result.summary.pcap}: ${numberText(summary?.total_packets)} packets, ${result.analytics?.security.findings.length || 0} security indicators. Exports include capture scope and limitations.`
        : 'Analyze a capture to export its report.';
    const select = byId('graph-device');
    const previous = select.value;
    select.replaceChildren(new Option('All devices', ''));
    const devices = new Set((result?.connections || []).map(c => c.source_ip));
    (result?.activities || []).forEach(a => devices.add(a.source_ip));
    [...devices].sort().forEach(ip => select.add(new Option(ip, ip)));
    select.value = devices.has(previous) ? previous : '';
}
function renderSecurity(security, summary) {
    const panel = byId('traffic-health');
    panel.dataset.state = security?.status || 'unknown';
    byId('health-title').textContent = !security ? 'Traffic summary — waiting for capture'
        : security.status === 'high' ? 'Red flags detected — investigate'
        : security.status === 'warning' ? 'Traffic needs review'
        : security.status === 'unknown' ? 'No packets available to assess'
        : 'No configured red flags found';
    byId('health-description').textContent = summary
        ? `${numberText(summary.total_packets)} packets over ${numberText(summary.duration)} seconds; ${numberText(summary.unique_sources)} source IPs and ${numberText(summary.unique_destinations)} destination IPs. ${security.status === 'clear' ? 'Green does not confirm that the network is safe.' : 'Indicators are not confirmed attack verdicts.'}`
        : 'The summary will show measured traffic and evidence-based investigation leads.';
    const findings = byId('security-findings');
    findings.replaceChildren();
    for (const finding of security?.findings || []) {
        const item = textElement('details', '', 'finding');
        item.append(textElement('summary', `${finding.severity === 'high' ? 'RED FLAG' : 'REVIEW'} · ${finding.title}`),
            textElement('p', finding.explanation));
        const list = textElement('dl', '', 'detail-grid');
        for (const [key, value] of Object.entries(finding.evidence)) {
            list.append(textElement('dt', key.replaceAll('_', ' ')),
                textElement('dd', key === 'time' ? dateText(value) : typeof value === 'number' ? numberText(value) : String(value)));
        }
        item.append(list); findings.append(item);
    }
    for (const warning of security?.warnings || []) findings.append(textElement('p', warning, 'finding'));
    byId('security-coverage').replaceChildren(...(security?.coverage || [
        'Detection checks run after analysis. Settings control the thresholds for subsequent captures.'
    ]).map(line => textElement('li', line)));
}
function showAnalysisError(message) {
    byId('traffic-health').dataset.state = 'error';
    byId('health-title').textContent = 'Capture / analysis error';
    byId('health-description').textContent = message + ' This is a processing error, not an attack verdict.';
}
function readSettings() {
    const form = byId('detection-settings');
    if (!form.reportValidity()) throw new Error('Check the detection settings.');
    const data = Object.fromEntries(new FormData(form));
    for (const key of ['pps_threshold', 'icmp_pps_threshold', 'syn_min', 'completion_threshold', 'ssh_attempts'])
        data[key] = Number(data[key]);
    data.baseline_pps = data.baseline_pps ? Number(data.baseline_pps) : null;
    data.gateway_mac = data.gateway_mac.trim().toLowerCase();
    data.gateway_ip = data.gateway_ip.trim();
    return data;
}
function buildDisplayGraph(result, options = {}) {
    const device = options.device ?? byId('graph-device').value;
    const search = (options.search ?? byId('graph-search').value).trim().toLowerCase();
    const hideDNS = options.hideDNS ?? byId('hide-dns').checked;
    const limit = options.limit ?? Number(byId('graph-limit').value);
    const groups = new Map();
    function group(source, target, kind) {
        const key = JSON.stringify([source, target]);
        if (!groups.has(key)) groups.set(key, {source, target, kind, connections: [], dns: new Set(), services: new Set()});
        return groups.get(key);
    }
    const seen = new Set();
    for (const connection of result.connections || []) {
        if (seen.has(connection.id)) continue;
        seen.add(connection.id);
        if (hideDNS && (connection.destination_port === 53 || connection.service === 'dns')) continue;
        const target = connection.domain || connection.destination_ip;
        const item = group(connection.source_ip, target, connection.domain ? 'domain' : 'server');
        item.connections.push(connection);
        item.services.add(connection.service === 'ssl' ? 'TLS' : connection.service?.toUpperCase() || connection.protocol?.toUpperCase() || 'Connection');
    }
    if (!hideDNS) for (const activity of result.activities || []) {
        for (const event of activity.evidence || []) {
            if (event.type === 'DNS_QUERY' && event.data.domain) {
                group(event.source.ip, event.data.domain, 'domain').dns.add(event.id);
            }
        }
    }
    const matching = [...groups.values()].filter(g => (!device || g.source === device) &&
        (!search || [g.source, g.target, ...g.services, ...g.connections.map(c => c.destination_ip)].join(' ').toLowerCase().includes(search)));
    const totalBytes = g => g.connections.reduce((sum, c) => sum + (c.bytes_sent || 0) + (c.bytes_received || 0), 0);
    matching.sort((a, b) => totalBytes(b) - totalBytes(a) || b.connections.length - a.connections.length || a.target.localeCompare(b.target));
    const nodes = new Map(), edges = [];
    const hosts = new Set(matching.map(g => g.source));
    function node(label, kind) {
        const id = JSON.stringify([kind === 'domain' ? 'domain' : 'ip', label]);
        if (!nodes.has(id)) nodes.set(id, {id, label, type: kind, data: {}});
        return id;
    }
    for (const item of matching.slice(0, limit)) {
        const source = node(item.source, 'host');
        const target = node(item.target, item.kind === 'server' && hosts.has(item.target) ? 'host' : item.kind);
        const bytes = totalBytes(item);
        const known = item.connections.every(c => c.bytes_sent != null && c.bytes_received != null);
        const label = item.connections.length
            ? `${[...item.services].join(' / ')} · ${item.connections.length} connection${item.connections.length === 1 ? '' : 's'}\n${known ? byteText(bytes) : 'Bytes incomplete'}`
            : `DNS · ${item.dns.size} observation${item.dns.size === 1 ? '' : 's'}`;
        edges.push({id: JSON.stringify([source, target]), source, target, label, type: item.connections.length ? 'CONNECTION' : 'DNS',
            data: {flow_ids: item.connections.map(c => c.id), dns_count: item.dns.size}});
    }
    return {nodes: [...nodes.values()], edges, total: matching.length};
}
function sumKnown(values) { return values.length && values.every(v => v != null) ? values.reduce((a, b) => a + b, 0) : null; }
function showDetails(element) {
    const panel = byId('graph-details');
    panel.replaceChildren(textElement('h3', element.data('label'), 'font-semibold mb-3'));
    const edges = element.isNode() ? element.connectedEdges() : [element];
    const flowIDs = new Set();
    let dnsCount = 0;
    edges.forEach(edge => {
        (edge.data('flow_ids') || []).forEach(id => flowIDs.add(id));
        dnsCount += edge.data('dns_count') || 0;
    });
    const flows = (graphResult.connections || []).filter(c => flowIDs.has(c.id));
    const activities = graphResult.activities.filter(a => a.flow_ids.some(id => flowIDs.has(id)) ||
        (element.isNode() && a.domains.includes(element.data('label'))));
    const rows = [
        ['Connections', flows.length], ['DNS observations', dnsCount],
        ['First seen', flows.length ? dateText(flows.reduce((t, c) => Math.min(t, c.start), Infinity)) : 'See DNS evidence'],
        ['Last seen', flows.length ? dateText(flows.reduce((t, c) => Math.max(t, c.end), -Infinity)) : 'See DNS evidence'],
        ['Initiator → responder', byteText(sumKnown(flows.map(c => c.bytes_sent)))],
        ['Responder → initiator', byteText(sumKnown(flows.map(c => c.bytes_received)))],
        ['Destination ports', [...new Set(flows.map(c => c.destination_port))].join(', ') || '—'],
        ['Server IPs', [...new Set(flows.map(c => c.destination_ip))].slice(0, 20).join(', ') || 'DNS lookup only']
    ];
    const list = textElement('dl', '', 'detail-grid');
    rows.forEach(([label, value]) => list.append(textElement('dt', label), textElement('dd', String(value))));
    panel.append(list);
    if (dnsCount) panel.append(textElement('p', 'A DNS query requests a name lookup; it does not prove a website visit.', 'text-sm mt-3'));
    for (const activity of activities.slice(0, 10)) {
        const details = textElement('details', '', 'finding');
        const names = {dns_activity: 'DNS lookup', network_connection: 'Network connection', web_activity: 'HTTP / TLS evidence'};
        details.append(textElement('summary', names[activity.type] || activity.title),
            textElement('p', activity.reason),
            textElement('p', `${dateText(activity.start_time)} → ${dateText(activity.end_time)}`));
        const facts = activity.evidence.filter(e => ['HTTP_REQUEST','TLS_CONNECTION','DNS_QUERY'].includes(e.type)).slice(0, 8);
        facts.forEach(e => details.append(textElement('p',
            `${e.type.replaceAll('_', ' ')} · ${e.data.domain || e.destination.ip} · ${dateText(e.timestamp)}`, 'text-xs mt-2')));
        panel.append(details);
    }
    if (activities.length > 10) panel.append(textElement('p', `Showing 10 of ${activities.length} related activities. Export JSON for all evidence.`));
    const raw = textElement('details', '', 'finding');
    raw.append(textElement('summary', 'View raw data'));
    const pre = textElement('pre', '', 'raw-data');
    raw.append(pre);
    raw.addEventListener('toggle', () => {
        if (raw.open && !pre.textContent) pre.textContent = JSON.stringify({connections: flows, activities}, null, 2);
    });
    panel.append(raw);
}
function exportReport(raw) {
    if (!latestResult) return;
    const a = latestResult.analytics;
    const text = raw ? JSON.stringify(latestResult, null, 2) : [
        `NetFlow capture report: ${latestResult.summary.pcap}`,
        `${dateText(a.summary.start_time)} — ${dateText(a.summary.end_time)}`,
        `${numberText(a.summary.total_packets)} packets | ${byteText(a.summary.total_bytes)} | average ${numberText(a.summary.average_pps)} packets/s`,
        `Assessment: ${a.security.status}. Indicators are not confirmed attacks.`,
        ...a.security.findings.map(f => `${f.title}\n${f.explanation}\n${JSON.stringify(f.evidence)}`),
        ...a.security.warnings, ...a.security.coverage, ...latestResult.summary.warnings,
        `Thresholds: ${JSON.stringify(a.security.thresholds)}`
    ].join('\n\n');
    const url = URL.createObjectURL(new Blob([text], {type: raw ? 'application/json' : 'text/plain'}));
    const anchor = document.createElement('a');
    anchor.href = url; anchor.download = raw ? 'netflow-report.json' : 'netflow-report.txt';
    anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function setupDashboard() {
    renderAnalytics(null);
    byId('download-report').onclick = () => exportReport(false);
    byId('download-json').onclick = () => exportReport(true);
    byId('use-baseline').onclick = () => {
        if (latestResult?.analytics?.summary.average_pps > 0) {
            byId('detection-settings').elements.baseline_pps.value = String(Math.max(1e-9, latestResult.analytics.summary.average_pps));
            byId('settings-status').textContent = 'Current capture marked as normal baseline. Future rate alerts require both the fixed threshold and 3× this baseline.';
        }
    };
    for (const id of ['graph-device','hide-dns','graph-limit']) byId(id).onchange = () => { if (graphResult) renderGraph(graphResult); };
    let searchTimer;
    byId('graph-search').oninput = () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => { if (graphResult) renderGraph(graphResult); }, 200);
    };
    byId('global-search').oninput = event => {
        byId('graph-search').value = event.target.value;
        byId('graph-search').dispatchEvent(new Event('input'));
    };
    document.querySelectorAll('nav a').forEach(link => link.addEventListener('click', () => {
        document.querySelectorAll('nav a').forEach(a => {
            a.removeAttribute('aria-current');
            a.classList.remove('bg-blue-50', 'text-blue-700');
        });
        link.setAttribute('aria-current', 'page');
    }));
    byId('detection-settings').onsubmit = event => {
        event.preventDefault();
        try { readSettings(); byId('settings-status').textContent = 'Settings will apply to the next upload or live session.'; }
        catch (error) { byId('settings-status').textContent = error.message; }
    };
}
