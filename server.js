require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Client } = require('ssh2');
const { createClient } = require('@supabase/supabase-js');
const ipaddr = require('ipaddr.js');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ============ SECURITY MIDDLEWARE ============
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '10kb' }));

const connectLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many connection attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ============ SUPABASE CLIENT ============
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ============ SSRF PROTECTION ============
function getAllowedRanges() {
  const raw = process.env.ALLOWED_VPS_IPS || '';
  return raw.split(',').map(s => s.trim()).filter(Boolean).map(cidr => {
    try {
      if (cidr.includes('/')) return ipaddr.parseCIDR(cidr);
      const addr = ipaddr.parse(cidr);
      const bits = addr.kind() === 'ipv4' ? 32 : 128;
      return [addr, bits];
    } catch {
      throw new Error(`Invalid CIDR/IP: ${cidr}`);
    }
  });
}

let ALLOWED_RANGES = [];
try { ALLOWED_RANGES = getAllowedRanges(); } catch (e) { console.error(e.message); }

function isAllowedTarget(ip) {
  try {
    const addr = ipaddr.parse(ip);
    const range = addr.range();
    const blocked = ['private', 'loopback', 'linkLocal', 'uniqueLocal', 'unspecified', 'broadcast', 'carrierGradeNat', 'reserved'];
    if (blocked.includes(range)) return false;
    return ALLOWED_RANGES.some(([r, bits]) => r.kind() === addr.kind() && addr.match(r, bits));
  } catch { return false; }
}

// ============ READ-ONLY DIAGNOSTIC COMMANDS ============
const DIAGNOSTIC_COMMANDS = {
  hostname: 'hostname',
  osRelease: 'cat /etc/os-release 2>/dev/null || echo "unknown"',
  uname: 'uname -a',
  cpuModel: 'grep -m1 "model name" /proc/cpuinfo 2>/dev/null || echo "unknown"',
  cpuCores: 'nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo "1"',
  memInfo: 'cat /proc/meminfo',
  diskInfo: 'df -B1 / 2>/dev/null || df -k /',
  uptime: 'uptime -p 2>/dev/null || uptime',
  kernel: 'uname -r',
  arch: 'uname -m',
  network: 'ip -brief addr show 2>/dev/null || ifconfig -a 2>/dev/null || echo "unavailable"',
  loadAvg: 'cat /proc/loadavg',
};

// ============ HELPERS ============
function execCommand(conn, cmd) {
  return new Promise((resolve, reject) => {
    conn.exec(cmd, (err, stream) => {
      if (err) return reject(err);
      let stdout = '', stderr = '';
      stream.on('data', d => { stdout += d.toString(); });
      stream.stderr.on('data', d => { stderr += d.toString(); });
      stream.on('close', code => resolve({ stdout: stdout.trim(), stderr: stderr.trim(), code }));
    });
  });
}

function parseOsRelease(raw) {
  const r = {};
  raw.split('\n').forEach(line => {
    const m = line.match(/^(\w+)=(.*)$/);
    if (m) r[m[1]] = m[2].replace(/^"|"$/g, '');
  });
  return {
    name: r.PRETTY_NAME || r.NAME || 'Unknown',
    version: r.VERSION || r.VERSION_ID || 'Unknown',
  };
}

function parseMemInfo(raw) {
  const r = {};
  raw.split('\n').forEach(line => {
    const m = line.match(/^(\w+):\s+(\d+)\s+kB/);
    if (m) r[m[1]] = parseInt(m[2], 10) * 1024;
  });
  const total = r.MemTotal || 0;
  const free = r.MemFree || 0;
  const available = r.MemAvailable || free;
  return { total, free, available, used: total - available };
}

function parseDiskInfo(raw) {
  const lines = raw.trim().split('\n');
  if (lines.length < 2) return { total: 0, used: 0, available: 0 };
  const p = lines[1].split(/\s+/);
  return {
    total: parseInt(p[1], 10) || 0,
    used: parseInt(p[2], 10) || 0,
    available: parseInt(p[3], 10) || 0,
  };
}

function parseLoadAvg(raw) {
  const p = raw.trim().split(/\s+/);
  return {
    one: parseFloat(p[0]) || 0,
    five: parseFloat(p[1]) || 0,
    fifteen: parseFloat(p[2]) || 0,
  };
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ============ ROUTES ============
app.use(express.static('public'));

app.post('/api/connect', connectLimiter, async (req, res) => {
  const { ip, port = 22, username, password } = req.body;

  if (!ip || !username || !password) {
    return res.status(400).json({ error: 'IP, username, and password are required.' });
  }

  const sshPort = parseInt(port, 10) || 22;
  if (sshPort < 1 || sshPort > 65535) {
    return res.status(400).json({ error: 'Invalid SSH port.' });
  }

  if (!isAllowedTarget(ip)) {
    return res.status(403).json({ error: 'Target IP is not allowed by security policy.' });
  }

  const conn = new Client();
  let connected = false;

  try {
    await new Promise((resolve, reject) => {
      conn.on('ready', () => { connected = true; resolve(); })
          .on('error', reject)
          .connect({
            host: ip,
            port: sshPort,
            username,
            password,
            readyTimeout: 15000,
            hostVerifier: (key) => {
              const fp = 'SHA256:' + crypto.createHash('sha256').update(key).digest('base64');
              if (process.env.KNOWN_HOST_FINGERPRINT) {
                return fp === process.env.KNOWN_HOST_FINGERPRINT;
              }
              console.log(`[HOSTKEY] ${ip} fingerprint: ${fp}`);
              return true;
            },
          });
    });

    const data = {};
    for (const [key, cmd] of Object.entries(DIAGNOSTIC_COMMANDS)) {
      try {
        const r = await execCommand(conn, cmd);
        data[key] = r.stdout;
      } catch { data[key] = ''; }
    }

    const osInfo = parseOsRelease(data.osRelease);
    const memInfo = parseMemInfo(data.memInfo);
    const diskInfo = parseDiskInfo(data.diskInfo);
    const loadAvg = parseLoadAvg(data.loadAvg);
    const cpuCores = parseInt(data.cpuCores, 10) || 1;

    const vpsInfo = {
      ip, username,
      hostname: data.hostname || 'unknown',
      os: osInfo.name,
      linuxVersion: osInfo.version,
      kernelVersion: data.kernel || data.uname || 'unknown',
      architecture: data.arch || 'unknown',
      cpuModel: data.cpuModel || 'unknown',
      cpuCores,
      ram: {
        total: memInfo.total, used: memInfo.used, free: memInfo.free, available: memInfo.available,
        totalFormatted: formatBytes(memInfo.total),
        usedFormatted: formatBytes(memInfo.used),
        freeFormatted: formatBytes(memInfo.free),
        availableFormatted: formatBytes(memInfo.available),
      },
      disk: {
        total: diskInfo.total, used: diskInfo.used, available: diskInfo.available,
        totalFormatted: formatBytes(diskInfo.total),
        usedFormatted: formatBytes(diskInfo.used),
        availableFormatted: formatBytes(diskInfo.available),
        usedPercent: diskInfo.total > 0 ? ((diskInfo.used / diskInfo.total) * 100).toFixed(1) : '0',
      },
      uptime: data.uptime || 'unknown',
      network: data.network || 'unavailable',
      loadAvg,
      serverStatus: 'Online',
    };

    try {
      await supabase.from('connection_history').insert({
        ip_address: ip, username,
        hostname: vpsInfo.hostname,
        os_info: vpsInfo.os,
        status: 'success',
        connected_at: new Date().toISOString(),
      });
    } catch (e) { console.error('Log failed:', e.message); }

    res.json({ success: true, data: vpsInfo });

  } catch (err) {
    try {
      await supabase.from('connection_history').insert({
        ip_address: ip, username,
        status: 'failed',
        error_message: err.message.substring(0, 500),
        connected_at: new Date().toISOString(),
      });
    } catch (e) { console.error('Log failed:', e.message); }

    res.status(401).json({
      error: 'SSH connection failed. Check credentials and network.',
      detail: err.message.substring(0, 200),
    });
  } finally {
    if (connected) conn.end();
  }
});

app.get('/api/history', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('connection_history')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(50);
    if (error) throw error;
    res.json({ history: data });
  } catch { res.status(500).json({ error: 'Failed to fetch history' }); }
});

app.delete('/api/history', async (req, res) => {
  try {
    const { error } = await supabase.from('connection_history').delete().neq('id', 0);
    if (error) throw error;
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Failed to clear history' }); }
});

app.listen(PORT, () => {
  console.log(`MAWZZ VPS EXTRACTOR running on port ${PORT}`);
  console.log(`Allowed ranges: ${process.env.ALLOWED_VPS_IPS || 'NONE — all connections blocked'}`);
});
