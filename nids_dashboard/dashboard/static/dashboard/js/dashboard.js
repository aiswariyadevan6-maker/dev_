/* Zero Day Hunter — dashboard.js
   7 Features:
   1. Live Detection Panel       — fetchLiveFeed() every 4s
   2. Recent Alerts Table        — rendered server-side + live_recent
   3. Processing Speed Display   — updateSpeed() every 5s
   4. Detection Summary          — loadSummary() with severity breakdown
   5. Statistics Cards           — updateSpeed() updates stat-total etc
   6. Severity Colours           — badge-low/medium/high/critical + row classes
   7. Decision Explanation       — toggleExp() per live row
*/

const C = {
  text:     '#7A8BA8',
  grid:     '#1E2E4A',
  brand:    '#00D4FF',
  accent:   '#7C3AED',
  low:      '#10B981',
  medium:   '#F59E0B',
  high:     '#F97316',
  critical: '#EF4444',
};

Chart.defaults.color     = C.text;
Chart.defaults.font.family = "'Inter', sans-serif";

let trafficChart, distChart, compChart, summaryChart;
let liveRunning = true;

async function api(url) {
  const r = await fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } });
  if (!r.ok) throw new Error(`${url} -> ${r.status}`);
  return r.json();
}

/* ── Feature 6: Severity colour helpers ── */
const SEV_COLOR = { LOW: C.low, MEDIUM: C.medium, HIGH: C.high, CRITICAL: C.critical };
const VERDICT_CLASS = {
  CONFIRMED_ATTACK: 'verdict-confirmed_attack',
  KNOWN_ATTACK:     'verdict-known_attack',
  ZERO_DAY:         'verdict-zero_day',
  BENIGN:           'verdict-benign',
};

/* ── Feature 3: Processing Speed ── */
async function updateSpeed() {
  try {
    const d = await api('/dashboard/api/stats/');
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('speed-ms',   d.avg_processing_ms + ' ms');
    set('speed-us',   d.avg_processing_us);
    set('throughput', d.throughput_per_sec);
    set('stat-total', Number(d.total_processed).toLocaleString());
    set('stat-alerts',d.active_alerts);
    set('stat-blocked', d.blocked_ips);
  } catch(e) { console.warn('stats', e); }
}

/* ── Traffic Overview ── */
async function loadTraffic() {
  const d = await api('/dashboard/api/traffic-overview/');
  const ctx = document.getElementById('trafficChart');
  if (!ctx) return;
  const cfg = {
    type: 'line',
    data: { labels: d.labels, datasets: [
      { label: 'Benign',    data: d.benign,    borderColor: C.low,      backgroundColor: 'rgba(16,185,129,.07)', tension: .4, fill: true, pointRadius: 0, borderWidth: 2 },
      { label: 'Malicious', data: d.malicious, borderColor: C.critical, backgroundColor: 'rgba(239,68,68,.07)',  tension: .4, fill: true, pointRadius: 0, borderWidth: 2 },
    ]},
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: { grid: { color: C.grid }, ticks: { maxTicksLimit: 12 } },
        y: { beginAtZero: true, grid: { color: C.grid }, ticks: { precision: 0 } },
      },
      plugins: { legend: { position: 'top', align: 'end', labels: { boxWidth: 10, boxHeight: 10, padding: 14 } } },
    },
  };
  if (trafficChart) { trafficChart.data = cfg.data; trafficChart.update(); }
  else trafficChart = new Chart(ctx, cfg);
}

/* ── Attack Distribution ── */
async function loadDistribution() {
  const d = await api('/dashboard/api/attack-distribution/');
  const ctx = document.getElementById('distributionChart');
  if (!ctx) return;
  const cfg = {
    type: 'doughnut',
    data: { labels: d.labels, datasets: [{ data: d.counts,
      backgroundColor: [C.low, C.high, C.medium, C.critical],
      borderWidth: 0, hoverOffset: 6 }]},
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '65%',
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, boxHeight: 12, padding: 14, font: { size: 12 } } } },
    },
  };
  if (distChart) { distChart.data = cfg.data; distChart.update(); }
  else distChart = new Chart(ctx, cfg);
}

/* ── Algorithm Comparison — side-by-side grouped bars, deduplicated ── */
async function loadComparison() {
  const d = await api('/dashboard/api/algorithm-comparison/');
  const ctx = document.getElementById('comparisonChart');
  if (!ctx) return;

  // Deduplicate labels
  const seen = new Set(), idx = [];
  d.labels.forEach((l, i) => { if (!seen.has(l)) { seen.add(l); idx.push(i); } });
  const labels    = idx.map(i => d.labels[i]);
  const accuracy  = idx.map(i => d.accuracy[i]);
  const precision = idx.map(i => d.precision[i]);
  const recall    = idx.map(i => d.recall[i]);

  const cfg = {
    type: 'bar',
    data: {
      labels,
      datasets: [
        { label: 'Accuracy %',  data: accuracy,  backgroundColor: C.brand,   borderRadius: 4, barPercentage: 0.28, categoryPercentage: 0.9 },
        { label: 'Precision %', data: precision, backgroundColor: C.medium,  borderRadius: 4, barPercentage: 0.28, categoryPercentage: 0.9 },
        { label: 'Recall %',    data: recall,    backgroundColor: C.high,    borderRadius: 4, barPercentage: 0.28, categoryPercentage: 0.9 },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      // Group bars side by side
      grouped: true,
      scales: {
        x: {
          grid: { display: false },
          ticks: { maxRotation: 15, font: { size: 12 } },
        },
        y: {
          beginAtZero: true,
          max: 105,
          grid: { color: C.grid },
          ticks: { callback: v => v + '%', font: { size: 12 } },
        },
      },
      plugins: {
        legend: {
          position: 'top',
          align: 'end',
          labels: { boxWidth: 12, boxHeight: 12, padding: 16 },
        },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.dataset.label}: ${ctx.parsed.y.toFixed(2)}%`,
          },
        },
      },
    },
  };
  if (compChart) { compChart.data = cfg.data; compChart.update(); }
  else compChart = new Chart(ctx, cfg);
}

/* ── Feature 4: Detection Summary ── */
async function loadSummary() {
  const d = await api('/dashboard/api/detection-summary/');
  const ctx = document.getElementById('summaryChart');
  if (!ctx) return;

  const cfg = {
    type: 'bar',
    data: {
      labels: d.labels,
      datasets: [
        { label: 'Upload',  data: d.upload_data, backgroundColor: 'rgba(0,212,255,.5)',  borderRadius: 4, barPercentage: 0.4 },
        { label: 'Live',    data: d.live_data,   backgroundColor: 'rgba(239,68,68,.5)',  borderRadius: 4, barPercentage: 0.4 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { grid: { display: false } },
        y: { beginAtZero: true, grid: { color: C.grid }, ticks: { precision: 0 } },
      },
      plugins: { legend: { position: 'top', align: 'end', labels: { boxWidth: 10, boxHeight: 10, padding: 12 } } },
    },
  };

  // Feature 6: Severity colour breakdown
  const s = d.severity;
  const el = document.getElementById('severityBreakdown');
  if (el) {
    el.innerHTML = [
      `<span style="color:var(--critical);font-family:var(--font-mono);font-size:12px">CRITICAL: ${s.CRITICAL}</span>`,
      `<span style="color:var(--high);font-family:var(--font-mono);font-size:12px">HIGH: ${s.HIGH}</span>`,
      `<span style="color:var(--medium);font-family:var(--font-mono);font-size:12px">MEDIUM: ${s.MEDIUM}</span>`,
      `<span style="color:var(--low);font-family:var(--font-mono);font-size:12px">LOW: ${s.LOW}</span>`,
    ].join('');
  }

  if (summaryChart) { summaryChart.data = cfg.data; summaryChart.update(); }
  else summaryChart = new Chart(ctx, cfg);
}

/* ── Feature 7: Toggle Decision Explanation ── */
function toggleExp(btn) {
  const expRow = btn.closest('tr').nextElementSibling;
  if (expRow && expRow.classList.contains('exp-row')) {
    const show = expRow.style.display === 'none';
    expRow.style.display = show ? 'table-row' : 'none';
    btn.textContent = show ? 'Hide' : 'Explain';
  }
}

/* ── Feature 1: Live Detection Panel ── */
async function fetchLiveFeed() {
  if (!liveRunning) return;
  try {
    const d = await api('/dashboard/api/live-feed/?n=3');
    const tbody = document.getElementById('liveTableBody');
    if (!tbody || !d.detections.length) return;

    tbody.innerHTML = d.detections.map(r => {
      const sev = (r.severity || 'low').toLowerCase();
      const vc  = VERDICT_CLASS[r.verdict_code] || '';
      return `
        <tr class="sev-${sev}" style="animation:rowIn .35s ease">
          <td class="mono">${r.timestamp}</td>
          <td class="mono">${r.source_ip}</td>
          <td class="mono">${r.destination_ip}</td>
          <td><span style="font-family:var(--font-mono);font-size:11px;background:var(--surface-3);color:var(--text-muted);padding:2px 7px;border-radius:4px">${r.protocol || 'TCP'}</span></td>
          <td class="${vc}">${r.verdict}</td>
          <td><span class="badge badge-${sev}">${r.severity}</span></td>
          <td class="mono">${r.rf_confidence}%</td>
          <td class="mono">${r.reconstruction_error}</td>
          <td><button class="btn-link" onclick="toggleExp(this)">Explain</button></td>
        </tr>
        <tr class="exp-row" style="display:none">
          <td colspan="9">
            <div class="explanation-box ${sev}">${r.decision_explanation}</div>
          </td>
        </tr>`;
    }).join('');
  } catch(e) { console.warn('live feed', e); }
}

function toggleLive() {
  liveRunning = !liveRunning;
  const btn = document.getElementById('liveToggle');
  if (btn) btn.textContent = liveRunning ? 'Pause' : 'Resume';
}

/* ── Recent Activity (upload-based) ── */
async function loadActivity() {
  const d = await api('/dashboard/api/recent-activity/');
  const tbody = document.querySelector('#activityTable tbody');
  if (!tbody || !d.rows.length) return;
  tbody.innerHTML = d.rows.map(r => `
    <tr class="sev-${r.severity.toLowerCase()}">
      <td class="mono">${r.timestamp}</td>
      <td class="mono">${r.source_ip}</td>
      <td class="${VERDICT_CLASS[r.verdict_code] || ''}">${r.verdict}</td>
      <td><span class="badge badge-${r.severity.toLowerCase()}">${r.severity}</span></td>
      <td class="mono">${r.confidence}%</td>
    </tr>`).join('');
}

/* ── CVE Threat Intelligence ── */
const CVE_DB = {
  CONFIRMED_ATTACK: [
    { id: 'CVE-2017-0144', name: 'EternalBlue (MS17-010)', score: 9.8, level: 'critical', desc: 'Remote code execution via SMB. Used by WannaCry and NotPetya ransomware.' },
    { id: 'CVE-2021-44228', name: 'Log4Shell', score: 10.0, level: 'critical', desc: 'Critical RCE in Apache Log4j via JNDI injection. Affects millions of Java applications.' },
    { id: 'CVE-2021-26855', name: 'ProxyLogon (Exchange)', score: 9.8, level: 'critical', desc: 'Microsoft Exchange SSRF enabling unauthenticated remote code execution.' },
  ],
  KNOWN_ATTACK: [
    { id: 'CVE-2022-30190', name: 'Follina (MSDT)', score: 7.8, level: 'high', desc: 'Microsoft Windows MSDT RCE via Office documents without macros.' },
    { id: 'CVE-2020-1472', name: 'Zerologon', score: 10.0, level: 'critical', desc: 'Privilege escalation via Netlogon allowing domain controller compromise.' },
    { id: 'CVE-2019-19781', name: 'Citrix ADC RCE', score: 9.8, level: 'critical', desc: 'Path traversal in Citrix ADC allowing unauthenticated remote code execution.' },
  ],
  ZERO_DAY: [
    { id: 'CVE-UNKNOWN-ZD', name: 'Zero-Day Anomaly', score: 8.5, level: 'high', desc: 'Novel traffic pattern deviating significantly from trained normal baseline. No known signature match.' },
    { id: 'CVE-2023-23397', name: 'Outlook Zero-Click RCE', score: 9.8, level: 'critical', desc: 'Microsoft Outlook RCE exploitable with zero user interaction.' },
    { id: 'CVE-2022-41082', name: 'ProxyNotShell', score: 8.8, level: 'high', desc: 'Authenticated RCE in Exchange via SSRF and deserialization chain.' },
  ],
  BENIGN: [],
};

async function loadCVE() {
  const grid = document.getElementById('cveGrid');
  if (!grid) return;
  try {
    const d = await api('/dashboard/api/attack-distribution/');
    const lm = { 'Benign': 'BENIGN', 'Known Attack': 'KNOWN_ATTACK', 'Zero-Day Anomaly': 'ZERO_DAY', 'Confirmed Attack': 'CONFIRMED_ATTACK' };
    let cves = CVE_DB.CONFIRMED_ATTACK;
    for (const key of ['CONFIRMED_ATTACK', 'KNOWN_ATTACK', 'ZERO_DAY']) {
      const i = d.labels.findIndex(l => lm[l] === key);
      if (i >= 0 && d.counts[i] > 0) { cves = CVE_DB[key]; break; }
    }
    if (!cves.length) {
      grid.innerHTML = `<div class="cve-card" style="grid-column:1/-1"><div class="empty-row">No threats detected — upload a CSV to populate threat intelligence.</div></div>`;
      return;
    }
    grid.innerHTML = cves.map(c => `
      <div class="cve-card">
        <div class="cve-id">${c.id}</div>
        <div class="cve-name">${c.name}</div>
        <div class="cve-score-row">
          <span class="cve-score cve-score-${c.level}">CVSS ${c.score}</span>
          <span class="badge badge-${c.level}">${c.level.toUpperCase()}</span>
        </div>
        <div class="cve-desc">${c.desc}</div>
      </div>`).join('');
  } catch(e) {
    grid.innerHTML = `<div class="cve-card"><div class="cve-desc">Could not load threat intelligence.</div></div>`;
  }
}

/* ── Row animation ── */
const s = document.createElement('style');
s.textContent = '@keyframes rowIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}';
document.head.appendChild(s);

/* ── Main init ── */
async function refreshCharts() {
  await Promise.allSettled([loadTraffic(), loadDistribution(), loadComparison(), loadSummary(), loadActivity(), loadCVE()]);
}

document.addEventListener('DOMContentLoaded', () => {
  refreshCharts();
  setInterval(refreshCharts, 20000);   // charts every 20s
  fetchLiveFeed();
  setInterval(fetchLiveFeed, 4000);    // live panel every 4s
  updateSpeed();
  setInterval(updateSpeed, 5000);      // speed every 5s
});
