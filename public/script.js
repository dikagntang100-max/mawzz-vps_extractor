const form = document.getElementById('connectForm');
const connectBtn = document.getElementById('connectBtn');
const disconnectBtn = document.getElementById('disconnectBtn');
const clearBtn = document.getElementById('clearBtn');
const statusMsg = document.getElementById('statusMsg');
const dashboard = document.getElementById('dashboard');

let currentData = null;

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const ip = document.getElementById('ip').value.trim();
  const port = document.getElementById('port').value;
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;

  if (!ip || !username || !password) {
    showStatus('All fields are required.', 'error');
    return;
  }

  connectBtn.disabled = true;
  connectBtn.textContent = 'CONNECTING...';
  showStatus('Establishing SSH connection and extracting data...', 'info');
  dashboard.classList.add('hidden');

  try {
    const response = await fetch('/api/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, port, username, password }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Connection failed');

    document.getElementById('password').value = '';
    currentData = result.data;
    renderDashboard(currentData);
    dashboard.classList.remove('hidden');
    disconnectBtn.disabled = false;
    showStatus(`Connected successfully to ${currentData.hostname}`, 'success');
    loadHistory();
  } catch (err) {
    showStatus(err.message, 'error');
    document.getElementById('password').value = '';
  } finally {
    connectBtn.disabled = false;
    connectBtn.textContent = 'CONNECT VPS';
  }
});

disconnectBtn.addEventListener('click', () => {
  currentData = null;
  dashboard.classList.add('hidden');
  disconnectBtn.disabled = true;
  showStatus('Disconnected. Data cleared from view.', 'info');
  document.getElementById('password').value = '';
});

clearBtn.addEventListener('click', () => {
  form.reset();
  document.getElementById('port').value = '22';
  currentData = null;
  dashboard.classList.add('hidden');
  disconnectBtn.disabled = true;
  statusMsg.className = 'status-msg';
  statusMsg.textContent = '';
});

function renderDashboard(data) {
  document.getElementById('vpsInfo').innerHTML = `
    <div class="label">IP Address</div><div class="value">${escapeHtml(data.ip)}</div>
    <div class="label">Username</div><div class="value">${escapeHtml(data.username)}</div>
    <div class="label">Hostname</div><div class="value">${escapeHtml(data.hostname)}</div>
    <div class="label">Operating System</div><div class="value">${escapeHtml(data.os)}</div>
    <div class="label">Linux Version</div><div class="value">${escapeHtml(data.linuxVersion)}</div>
    <div class="label">Architecture</div><div class="value">${escapeHtml(data.architecture)}</div>
    <div class="label">Kernel Version</div><div class="value">${escapeHtml(data.kernelVersion)}</div>
    <div class="label">Server Status</div><div class="value" style="color:var(--success)">${escapeHtml(data.serverStatus)}</div>
  `;

  const load = data.loadAvg;
  document.getElementById('cpuInfo').innerHTML = `
    <div class="metric-row"><span class="metric-label">CPU Model</span><span class="metric-value">${escapeHtml(data.cpuModel)}</span></div>
    <div class="metric-row"><span class="metric-label">CPU Cores</span><span class="metric-value">${data.cpuCores}</span></div>
    <div class="metric-row"><span class="metric-label">Load (1m/5m/15m)</span><span class="metric-value">${load.one} / ${load.five} / ${load.fifteen}</span></div>
  `;

  const ramPct = data.ram.total > 0 ? ((data.ram.used / data.ram.total) * 100).toFixed(1) : 0;
  document.getElementById('ramInfo').innerHTML = `
    <div class="metric-row"><span class="metric-label">Total</span><span class="metric-value">${data.ram.totalFormatted}</span></div>
    <div class="metric-row"><span class="metric-label">Used</span><span class="metric-value">${data.ram.usedFormatted}</span></div>
    <div class="metric-row"><span class="metric-label">Free</span><span class="metric-value">${data.ram.freeFormatted}</span></div>
    <div class="progress-bar"><div class="progress-fill ram" style="width:${ramPct}%"></div></div>
    <div class="metric-row"><span class="metric-label">Usage</span><span class="metric-value">${ramPct}%</span></div>
  `;

  document.getElementById('diskInfo').innerHTML = `
    <div class="metric-row"><span class="metric-label">Total</span><span class="metric-value">${data.disk.totalFormatted}</span></div>
    <div class="metric-row"><span class="metric-label">Used</span><span class="metric-value">${data.disk.usedFormatted}</span></div>
    <div class="metric-row"><span class="metric-label">Available</span><span class="metric-value">${data.disk.availableFormatted}</span></div>
    <div class="progress-bar"><div class="progress-fill disk" style="width:${data.disk.usedPercent}%"></div></div>
    <div class="metric-row"><span class="metric-label">Usage</span><span class="metric-value">${data.disk.usedPercent}%</span></div>
  `;

  document.getElementById('networkInfo').textContent = data.network;

  document.getElementById('serverDetails').innerHTML = `
    <div class="label">Uptime</div><div class="value">${escapeHtml(data.uptime)}</div>
    <div class="label">Kernel</div><div class="value">${escapeHtml(data.kernelVersion)}</div>
    <div class="label">Architecture</div><div class="value">${escapeHtml(data.architecture)}</div>
    <div class="label">OS</div><div class="value">${escapeHtml(data.os)}</div>
  `;
}

async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const { history } = await res.json();
    const list = document.getElementById('historyList');
    if (!history || history.length === 0) {
      list.innerHTML = '<p style="color:var(--muted)">No connection history.</p>';
      return;
    }
    list.innerHTML = history.map(h => `
      <div class="history-item">
        <span>${new Date(h.created_at).toLocaleString()}</span>
        <span>${escapeHtml(h.ip_address)} / ${escapeHtml(h.username)}</span>
        <span class="status-badge ${h.status}">${h.status.toUpperCase()}</span>
      </div>
    `).join('');
  } catch {}
}

function showStatus(msg, type) {
  statusMsg.textContent = msg;
  statusMsg.className = `status-msg ${type}`;
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
