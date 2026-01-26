const http = require('http');
const { URL } = require('url');
const WebSocket = require('ws');

let organizations = [
  { id: '1', name: '北京安全运营中心 (SOC)', memberCount: 5, maxMembers: 10, createdAt: '2023-01-15T09:00:00Z', adminPermission: true },
  { id: '2', name: '上海金融防御小组', memberCount: 18, maxMembers: 20, createdAt: '2023-03-10T14:30:00Z', adminPermission: false },
  { id: '3', name: '广州应急响应队', memberCount: 3, maxMembers: 5, createdAt: '2023-06-01T10:00:00Z', adminPermission: false },
];

const threats = [
  { id: 'TH-1001', type: 'DDoS 洪水攻击', sourceIp: '192.168.1.105', targetIp: '10.0.0.5', timestamp: '2023-10-27 10:30', riskLevel: 'High', status: 'Pending', details: '检测到 UDP 协议异常流量峰值，超过基线 500%。' },
  { id: 'TH-1002', type: '勒索软件通信', sourceIp: '45.33.22.11', targetIp: '10.0.0.2', timestamp: '2023-10-27 11:15', riskLevel: 'High', status: 'Resolved', details: '识别到 WannaCry 变种的 C2 服务器通信特征。' },
  { id: 'TH-1003', type: '横向端口扫描', sourceIp: '172.16.0.50', targetIp: '10.0.0.8', timestamp: '2023-10-27 12:00', riskLevel: 'Low', status: 'Blocked', details: '内网主机尝试连接多个未授权端口。' },
  { id: 'TH-1004', type: 'SQL 注入尝试', sourceIp: '203.0.113.1', targetIp: '10.0.0.12', timestamp: '2023-10-27 13:45', riskLevel: 'Medium', status: 'Pending', details: '针对 /api/v1/login 接口的联合查询注入 Payload。' },
  { id: 'TH-1005', type: 'SSH 暴力破解', sourceIp: '198.51.100.2', targetIp: '10.0.0.5', timestamp: '2023-10-27 14:20', riskLevel: 'Medium', status: 'Pending', details: '源 IP 在 1 分钟内发起了 120 次 SSH 认证请求。' },
  { id: 'TH-1006', type: 'XSS 跨站脚本', sourceIp: '114.25.1.5', targetIp: '10.0.0.15', timestamp: '2023-10-27 15:10', riskLevel: 'Low', status: 'Resolved', details: '在评论区检测到存储型 XSS 脚本标签。' },
];

function send(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(body);
}

function parseBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', chunk => raw += chunk);
    req.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); } catch { resolve({}); }
    });
  });
}

const server = http.createServer(async (req, res) => {
  const urlObj = new URL(req.url, 'http://localhost');
  const pathname = urlObj.pathname;

  if (req.method === 'OPTIONS') return send(res, 204, {});

  // Auth
  if (req.method === 'POST' && pathname === '/api/auth/login') {
    const body = await parseBody(req);
    if (!body.username || !body.password) {
      return send(res, 400, { message: '缺少账号或密码' });
    }
    return send(res, 200, { token: 'mock-token-' + Date.now() });
  }

  // Organizations
  if (req.method === 'GET' && pathname === '/api/organizations') {
    return send(res, 200, organizations);
  }
  if (req.method === 'POST' && pathname === '/api/organizations') {
    const body = await parseBody(req);
    const id = String(Date.now());
    const created = { id, name: body.name || '未命名组织', memberCount: body.memberCount ?? 1, maxMembers: body.maxMembers ?? 10, createdAt: new Date().toISOString(), adminPermission: !!body.adminPermission };
    organizations.push(created);
    return send(res, 201, created);
  }
  const orgMatch = pathname.match(/^\/api\/organizations\/(.+)$/);
  if (orgMatch) {
    const id = orgMatch[1];
    if (req.method === 'PUT') {
      const body = await parseBody(req);
      const idx = organizations.findIndex(o => o.id === id);
      if (idx === -1) return send(res, 404, { message: '组织不存在' });
      organizations[idx] = { ...organizations[idx], ...body };
      return send(res, 200, organizations[idx]);
    }
    if (req.method === 'DELETE') {
      const before = organizations.length;
      organizations = organizations.filter(o => o.id !== id);
      if (organizations.length === before) return send(res, 404, { message: '组织不存在' });
      return send(res, 204, {});
    }
  }

  // Threats
  if (req.method === 'GET' && pathname === '/api/threats/history') {
    return send(res, 200, threats);
  }
  const blockMatch = pathname.match(/^\/api\/threats\/(.+)\/block$/);
  if (req.method === 'POST' && blockMatch) {
    const id = blockMatch[1];
    return send(res, 200, { id, status: 'Blocked' });
  }
  const resolveMatch = pathname.match(/^\/api\/threats\/(.+)\/resolve$/);
  if (req.method === 'POST' && resolveMatch) {
    const id = resolveMatch[1];
    return send(res, 200, { id, status: 'Resolved' });
  }

  // Collection config
  if ((req.method === 'POST' || req.method === 'PUT') && pathname === '/api/collection/config') {
    const body = await parseBody(req);
    return send(res, 200, { ok: true, configId: body.id || '1' });
  }

  send(res, 404, { message: 'Not Found' });
});

const PORT = 8080;
server.listen(PORT, () => {
  console.log(`[Mock] HTTP server listening on http://localhost:${PORT}/api`);
});

const wss = new WebSocket.Server({ port: 8081, path: '/ids/stream' });

function randomThreat() {
  const types = ['DDoS 洪水攻击', 'SQL 注入尝试', 'SSH 暴力破解', '横向端口扫描', 'XSS 跨站脚本'];
  const src = [`192.168.1.${Math.floor(Math.random()*200)+1}`, `10.0.0.${Math.floor(Math.random()*200)+1}`, `${Math.floor(Math.random()*220)}.${Math.floor(Math.random()*220)}.${Math.floor(Math.random()*220)}.${Math.floor(Math.random()*220)}`];
  const dst = [`10.0.0.${Math.floor(Math.random()*50)+1}`, `172.16.0.${Math.floor(Math.random()*50)+1}`];
  const severities = ['Low','Medium','High'];
  const t = types[Math.floor(Math.random()*types.length)];
  return {
    event_id: 'EV-' + Date.now() + '-' + Math.floor(Math.random()*1000),
    attack_type: t,
    src_ip: src[Math.floor(Math.random()*src.length)],
    dst_ip: dst[Math.floor(Math.random()*dst.length)],
    timestamp: new Date().toLocaleTimeString(),
    severity: severities[Math.floor(Math.random()*severities.length)],
    payload: `attack=${t}&metric=${Math.floor(Math.random()*1000)}`
  };
}

wss.on('connection', (ws) => {
  let authed = false;
  let timer = null;

  function start() {
    if (timer) return;
    timer = setInterval(() => {
      const ev = randomThreat();
      ws.send(JSON.stringify(ev));
    }, 2000);
  }

  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg.toString());
      if (data.type === 'AUTH') {
        authed = true;
        start();
      }
    } catch {}
  });

  ws.on('close', () => {
    if (timer) clearInterval(timer);
  });
});

console.log('[Mock] WS server listening on ws://localhost:8081/ids/stream');

