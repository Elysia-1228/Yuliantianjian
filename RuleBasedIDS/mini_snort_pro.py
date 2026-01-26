#!/usr/bin/env python3
"""
mini_snort_pro.py - 专业一点的微型入侵检测（签名式）Demo（优化版）

功能：
- 从 JSON 加载规则：
  {
    "sid": 100001,
    "msg": "HTTP suspicious keyword",
    "protocol": "tcp",        # tcp / udp / ip / any
    "src_ip": "any",          # any / 单IP / CIDR 如 192.168.1.0/24
    "src_port": "any",        # any / 单端口 / 区间 "1000-2000"
    "dst_ip": "any",
    "dst_port": "80",
    "content": "malicious",   # 正则表达式（按 bytes 匹配）
    "severity": 3,            # 1-5，数字越大越严重
    "enabled": true,          # 是否启用
    "tags": ["http", "demo"]  # 任意字符串标签
  }

运行模式：
- 实时抓包：   --mode live -i eth0 -R rules.json
- 回放 pcap：  --mode pcap -r sample.pcap -R rules.json
- 仅开 REST：  --api --api-port 5001 （依赖 Flask）

注意：教学/演示用途，不替代 Snort/Suricata。
"""

import argparse
import json
import re
import time
import logging
import ipaddress
import os
import socket
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

import requests  # 用于调用对方的大模型 IDS HTTP 接口

import uuid
from datetime import datetime

# -------------------------
# Backnode API Configuration
# -------------------------
BACKNODE_API_URL = "http://localhost:8081/api/analysis/alert"
BLOCKED_IPS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../blocked_ips.json")
TRUSTED_IPS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../trusted_ips.json")

# -------------------------
# scapy 用于抓包/解析
# -------------------------
from scapy.sendrecv import sniff
from scapy.utils import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

# -------------------------
# flask（可选）用于 REST API
# -------------------------
try:
    from flask import Flask, request, jsonify, Response
    _HAS_FLASK = True
except Exception:
    _HAS_FLASK = False

# -------------------------
# 日志配置
# -------------------------
ALERT_LOGFILE = "alerts.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("mini_snort_pro")


# -------------------------
# 规则与统计数据结构
# -------------------------
@dataclass
class Rule:
    sid: int
    msg: str
    protocol: str            # 'tcp'/'udp'/'ip'/'any'
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    content_regex: Optional[re.Pattern] = None
    severity: int = 1        # 1-5
    enabled: bool = True
    tags: List[str] = field(default_factory=list)


@dataclass
class Stats:
    total_packets: int = 0
    matched_packets: int = 0
    alerts_per_rule: Dict[int, int] = field(default_factory=dict)

    def record_hits(self, hits: List[Dict[str, Any]]):
        if not hits:
            return
        self.matched_packets += 1
        for h in hits:
            sid = h["sid"]
            self.alerts_per_rule[sid] = self.alerts_per_rule.get(sid, 0) + 1


# -------------------------
# 规则加载
# -------------------------
def load_rules_from_json(path: str) -> List[Rule]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rules: List[Rule] = []
    for r in data:
        if not r.get("enabled", True):
            # 支持 enabled=false 的规则
            continue

        cre = None
        content = r.get("content")
        if content:
            # 统一按 bytes 正则处理
            if isinstance(content, str):
                cre = re.compile(content.encode(), re.DOTALL)
            else:
                cre = re.compile(content, re.DOTALL)

        rule = Rule(
            sid=int(r.get("sid", 0)),
            msg=r.get("msg", ""),
            protocol=r.get("protocol", "any").lower(),
            src_ip=r.get("src_ip", "any"),
            src_port=str(r.get("src_port", "any")),
            dst_ip=r.get("dst_ip", "any"),
            dst_port=str(r.get("dst_port", "any")),
            content_regex=cre,
            severity=int(r.get("severity", 1)),
            enabled=bool(r.get("enabled", True)),
            tags=r.get("tags", []),
        )
        rules.append(rule)

    logger.info(f"Loaded {len(rules)} active rules from {path}")
    return rules


# -------------------------
# 匹配辅助函数：IP / 端口 / payload
# -------------------------
def port_match(port_rule: str, pkt_port: Optional[int]) -> bool:
    if port_rule == "any":
        return True
    if pkt_port is None:
        return False

    try:
        if "-" in port_rule:
            a, b = port_rule.split("-", 1)
            return int(a) <= pkt_port <= int(b)
        return int(port_rule) == pkt_port
    except ValueError:
        # 规则写坏了就直接不匹配
        return False


def ip_match(ip_rule: str, pkt_ip: Optional[str]) -> bool:
    if ip_rule == "any":
        return True
    if pkt_ip is None:
        return False

    # 支持单 IP / CIDR
    try:
        if "/" in ip_rule:
            net = ipaddress.ip_network(ip_rule, strict=False)
            return ipaddress.ip_address(pkt_ip) in net
        else:
            return ip_rule == pkt_ip
    except ValueError:
        # 解析失败时回退为字符串比较
        return ip_rule == pkt_ip


def extract_payload(packet) -> bytes:
    """
    提取 Raw 层负载，统一转换为 bytes。
    """
    try:
        if Raw in packet:
            raw = packet[Raw].load
            if isinstance(raw, bytes):
                return raw
            return str(raw).encode(errors="ignore")
        return b""
    except Exception:
        return b""


# -------------------------
# 核心匹配引擎（纯函数）
# -------------------------
def match_packet(packet, rules: List[Rule]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []

    proto = None
    src_ip = dst_ip = None
    src_port = dst_port = None

    # L3
    if IP in packet:
        ip_layer = packet[IP]
        proto = "ip"
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    elif IPv6 in packet:
        ip_layer = packet[IPv6]
        proto = "ip"
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    else:
        # 非 IP 报文暂不处理（如 ARP）
        return hits

    # L4
    if TCP in packet:
        proto = "tcp"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif UDP in packet:
        proto = "udp"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    # 其他协议（ICMP 等）保留 proto="ip"

    payload = extract_payload(packet)

    for rule in rules:
        # 协议匹配
        if rule.protocol != "any" and rule.protocol != proto and not (
                rule.protocol == "ip" and proto in ("tcp", "udp", "ip")
        ):
            continue

        # IP/端口匹配
        if not ip_match(rule.src_ip, src_ip):
            continue
        if not ip_match(rule.dst_ip, dst_ip):
            continue
        if not port_match(rule.src_port, src_port):
            continue
        if not port_match(rule.dst_port, dst_port):
            continue

        # payload 内容匹配
        if rule.content_regex:
            try:
                if not rule.content_regex.search(payload):
                    continue
            except re.error:
                # 正则异常时退回为普通字符串匹配
                try:
                    patt = (
                        rule.content_regex.pattern.decode(errors="ignore")
                        if isinstance(rule.content_regex.pattern, (bytes, bytearray))
                        else str(rule.content_regex.pattern)
                    )
                    if patt.encode() not in payload:
                        continue
                except Exception:
                    continue

        # 匹配命中
        hits.append(
            {
                "sid": rule.sid,
                "msg": rule.msg,
                "rule": rule,
                "proto": proto,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": payload[:512],  # 截断预览
            }
        )

    return hits


# -------------------------
# 告警记录
# -------------------------
def record_alert(hit: Dict[str, Any], packet_time, logfile: str = ALERT_LOGFILE):
    try:
        ts = float(packet_time)
    except Exception:
        ts = time.time()

    tstr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    rule: Rule = hit["rule"]

    line = {
        "timestamp": tstr,
        "sid": hit["sid"],
        "msg": hit["msg"],
        "severity": rule.severity,
        "tags": rule.tags,
        "proto": hit["proto"],
        "src": f"{hit['src_ip']}:{hit['src_port']}",
        "dst": f"{hit['dst_ip']}:{hit['dst_port']}",
        "payload_preview": hit["payload"].hex()[:200],
    }

    # 写一次文件（JSON 行）
    with open(logfile, "a", encoding="utf-8") as f:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")

    # 控制台打印
    logger.warning(
        f"[ALERT][sev={line['severity']}][sid={line['sid']}] "
        f"{line['msg']} | {line['src']} -> {line['dst']} | "
        f"time={line['timestamp']} | tags={','.join(line['tags'])}"
    )
    logger.info(f"payload_preview(hex)={line['payload_preview']}")

    # -------------------------
    # 发送到 Backnode
    # -------------------------
    try:
        # 构造适配 Backnode 的 Payload
        # 注意：Backnode 需要 threatId, threatLevel, impactScope (session | attack_type), occurTime, createTime
        impact_scope = f"{line['src']} -> {line['dst']} | {line['msg']}"
        
        backnode_payload = {
            "threatId": str(uuid.uuid4()),
            "threatLevel": line['severity'],
            "impactScope": impact_scope, 
            "occurTime": line['timestamp'],
            "createTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # 发送 POST 请求
        # timeout 设置为 2 秒，避免阻塞主检测循环太久
        response = requests.post(BACKNODE_API_URL, json=backnode_payload, timeout=2)
        
        if response.status_code == 200:
            logger.info(f"Alert sent to Backnode successfully: {backnode_payload['threatId']}")
        else:
            logger.error(f"Failed to send alert to Backnode: {response.status_code} - {response.text}")
            
    except Exception as e:
        logger.error(f"Error sending alert to Backnode: {str(e)}")


# -------------------------
# 引擎类：封装 packet 回调 + 统计
# -------------------------
class MiniSnortEngine:
    def __init__(self, rules: List[Rule], alert_logfile: str = ALERT_LOGFILE):
        self.rules = rules
        self.alert_logfile = alert_logfile
        self.stats = Stats()
        self.blocked_ips = set()
        self.trusted_ips = set()
        self.last_reload_time = 0
        self.reload_ips()

    def reload_ips(self):
        try:
            # Reload every 3 seconds
            if time.time() - self.last_reload_time < 3:
                return
            
            # Load Blocked IPs
            if os.path.exists(BLOCKED_IPS_FILE):
                with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
                    ips = json.load(f)
                    self.blocked_ips = set(ips)
            else:
                self.blocked_ips = set()

            # Load Trusted IPs (File)
            file_trusted_ips = set()
            if os.path.exists(TRUSTED_IPS_FILE):
                with open(TRUSTED_IPS_FILE, "r", encoding="utf-8") as f:
                    ips = json.load(f)
                    file_trusted_ips = set(ips)
            
            # Auto-detect Local IPs (Dynamic)
            local_ips = set()
            local_ips.add("127.0.0.1")
            local_ips.add("::1")
            try:
                # Method 1: Hostname resolution
                hostname = socket.gethostname()
                for ip in socket.gethostbyname_ex(hostname)[2]:
                    local_ips.add(ip)
            except:
                pass
            try:
                # Method 2: Connect probe
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ips.add(s.getsockname()[0])
                s.close()
            except:
                pass
            
            # Merge both
            self.trusted_ips = file_trusted_ips.union(local_ips)
            
            self.last_reload_time = time.time()
        except Exception as e:
            # Silent fail or debug log to avoid spam
            pass

    def process_packet(self, packet):
        self.reload_ips()

        # Check for blocked source IP
        src_ip = None
        if IP in packet:
            src_ip = packet[IP].src
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            
        if src_ip:
            if src_ip in self.blocked_ips:
                # Ignore traffic from blocked IPs
                return
            if src_ip in self.trusted_ips:
                # Ignore traffic from trusted IPs (Whitelist)
                return

        self.stats.total_packets += 1
        hits = match_packet(packet, self.rules)
        if hits:
            self.stats.record_hits(hits)
            pkt_time = getattr(packet, "time", time.time())
            for hit in hits:
                record_alert(hit, pkt_time, self.alert_logfile)


# -------------------------
# 运行函数（live / pcap）
# -------------------------
def run_live(interface: str, rules_path: str, count: int = 0, bpf_filter: Optional[str] = None) -> Stats:
    rules = load_rules_from_json(rules_path)
    engine = MiniSnortEngine(rules)

    logger.info(
        f"Starting live capture on {interface} "
        f"(count={count if count else 'infinite'}, filter={bpf_filter!r})"
    )

    try:
        sniff(
            iface=interface,
            prn=engine.process_packet,
            store=False,
            count=count,
            filter=bpf_filter,
        )
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user (Ctrl+C).")

    return engine.stats


def run_pcap(pcap_path: str, rules_path: str, replay_delay: float = 0.0) -> Stats:
    rules = load_rules_from_json(rules_path)
    engine = MiniSnortEngine(rules)

    logger.info(f"Reading PCAP {pcap_path} ...")
    packets = rdpcap(pcap_path)
    logger.info(f"Total {len(packets)} packets in pcap")

    try:
        for p in packets:
            engine.process_packet(p)
            if replay_delay > 0:
                time.sleep(replay_delay)
    except KeyboardInterrupt:
        logger.info("PCAP replay interrupted by user (Ctrl+C).")

    return engine.stats


# -------------------------
# 调用对方大模型 IDS
# -------------------------
def call_llm_ids(packet_info: Dict[str, Any], llm_url: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    调用对方的大模型 IDS 服务。
    约定：
      POST {llm_url}
      body: JSON，格式与 packet_info 一致
    返回：对方返回的 JSON（例如 { "label": "attack", "score": 0.97, ... }）
    """
    try:
        resp = requests.post(llm_url, json=packet_info, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.error(f"LLM IDS call failed: {e}")
        return {"error": str(e)}


# -------------------------
# Flask API + 调试 UI（可选）
# -------------------------
def start_api(rules_path: str, host: str = "0.0.0.0", port: int = 5001):
    if not _HAS_FLASK:
        logger.error("Flask is not installed. 请先 `pip install flask`")
        return

    app = Flask("mini_snort_api")
    rules = load_rules_from_json(rules_path)

    # 对方大模型 IDS 的 HTTP 地址（你到时候换成自己的）
    app.config["LLM_IDS_URL"] = "http://127.0.0.1:8000/analyze"

    # ---- 简易 Web UI ----
    UI_HTML = r"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>mini_snort_pro 调试控制台</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #101316;
      color: #f5f5f5;
    }
    header {
      padding: 10px 16px;
      background: #151a1f;
      border-bottom: 1px solid #262b33;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    header h1 {
      margin: 0;
      font-size: 18px;
    }
    header span {
      font-size: 12px;
      color: #9ca3af;
    }
    main {
      display: flex;
      height: calc(100vh - 52px);
    }
    section {
      padding: 10px;
      overflow: auto;
    }
    #left {
      width: 40%;
      border-right: 1px solid #262b33;
    }
    #right {
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    h2 {
      font-size: 14px;
      margin: 6px 0 8px;
      color: #e5e7eb;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }
    th, td {
      border: 1px solid #262b33;
      padding: 4px 6px;
      text-align: left;
      vertical-align: top;
    }
    th {
      background: #1f2933;
    }
    tr:nth-child(even) td {
      background: #141820;
    }
    tr:nth-child(odd) td {
      background: #10141b;
    }
    .alert-high   { background: #3b0000 !important; }
    .alert-medium { background: #3b2a00 !important; }
    .small {
      font-size: 11px;
      color: #9ca3af;
    }
    input, textarea {
      width: 100%;
      padding: 4px 6px;
      border-radius: 4px;
      border: 1px solid #374151;
      background: #020617;
      color: #e5e7eb;
      font-size: 12px;
      font-family: monospace;
    }
    textarea {
      resize: vertical;
      min-height: 90px;
      max-height: 240px;
    }
    button {
      padding: 6px 12px;
      border-radius: 4px;
      border: none;
      cursor: pointer;
      font-size: 12px;
      margin-right: 6px;
      background: #2563eb;
      color: white;
    }
    button.secondary {
      background: #4b5563;
    }
    button:disabled {
      opacity: .5;
      cursor: default;
    }
    pre {
      background: #020617;
      border-radius: 4px;
      border: 1px solid #374151;
      padding: 6px;
      font-size: 12px;
      max-height: 260px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .flex-row {
      display: flex;
      gap: 8px;
    }
    .flex-1 { flex: 1; }
    .badge {
      display: inline-block;
      padding: 1px 6px;
      border-radius: 999px;
      font-size: 11px;
      background: #1f2937;
      color: #e5e7eb;
      margin-left: 4px;
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>mini_snort_pro 调试控制台</h1>
      <span id="status-text" class="small">加载中...</span>
    </div>
    <div class="small">
      API: <code>/rules</code>, <code>/alerts</code>, <code>/debug</code>, <code>/hybrid_score</code>
    </div>
  </header>
  <main>
    <section id="left">
      <h2>规则列表 <span class="badge" id="rule-count">0</span></h2>
      <button class="secondary" onclick="loadRules()">刷新规则</button>
      <table id="rules-table">
        <thead>
          <tr>
            <th>SID</th>
            <th>协议</th>
            <th>描述</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>

      <h2 style="margin-top:14px;">实时告警 <span class="badge" id="alert-count">0</span></h2>
      <div class="small" style="margin-bottom:4px;">每 3 秒自动刷新，可配合 live 模式使用。</div>
      <table id="alerts-table">
        <thead>
          <tr>
            <th>时间 & 级别</th>
            <th>内容</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </section>

    <section id="right">
      <div>
        <h2>调试请求（POST /debug）</h2>
        <div class="small" style="margin-bottom:4px;">
          这里不会真的发网卡报文，只是把数据构造成“虚拟包”走一遍规则引擎，方便后端调试字段格式。
        </div>
        <div class="flex-row">
          <div class="flex-1">
            <label class="small">src_ip</label>
            <input id="src_ip" value="192.168.1.10">
          </div>
          <div class="flex-1">
            <label class="small">dst_ip</label>
            <input id="dst_ip" value="192.168.1.100">
          </div>
        </div>
        <div class="flex-row" style="margin-top:4px;">
          <div class="flex-1">
            <label class="small">src_port</label>
            <input id="src_port" value="12345">
          </div>
          <div class="flex-1">
            <label class="small">dst_port</label>
            <input id="dst_port" value="80">
          </div>
        </div>
        <div style="margin-top:4px;">
          <label class="small">payload</label>
          <textarea id="payload">GET /etc/passwd HTTP/1.1\r\nHost: test\r\n\r\n</textarea>
        </div>
        <div style="margin-top:6px;">
          <button id="btn-send" onclick="sendDebug()">发送调试请求</button>
          <button class="secondary" onclick="fillSampleLFI()">示例：LFI /etc/passwd</button>
        </div>
      </div>

      <div>
        <h2>调试结果</h2>
        <pre id="debug-result">{}</pre>
      </div>
    </section>
  </main>

  <script>
    async function loadStatus() {
      try {
        const res = await fetch('/debug');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        document.getElementById('status-text').innerText =
          'status: ' + data.status + ' | 规则数量: ' + data.rule_count + ' | 时间: ' + (data.time || '');
      } catch (e) {
        document.getElementById('status-text').innerText = '无法连接 /debug：' + e;
      }
    }

    async function loadRules() {
      try {
        const res = await fetch('/rules');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const rules = await res.json();
        const tbody = document.querySelector('#rules-table tbody');
        tbody.innerHTML = '';
        rules.forEach(r => {
          const tr = document.createElement('tr');
          tr.innerHTML =
            '<td>' + r.sid + '</td>' +
            '<td>' + r.protocol + '</td>' +
            '<td>' + (r.msg || '') + '</td>' +
            '<td>' + (r.severity || '') + '</td>';
          tbody.appendChild(tr);
        });
        document.getElementById('rule-count').innerText = rules.length;
      } catch (e) {
        console.error(e);
      }
    }

    async function loadAlerts() {
      try {
        const res = await fetch('/alerts');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json(); // {"lines": [...]}
        const lines = data.lines || [];
        const tbody = document.querySelector('#alerts-table tbody');
        tbody.innerHTML = '';
        lines.forEach(line => {
          if (!line.trim()) return;
          const tr = document.createElement('tr');
          const lower = line.toLowerCase();
          let cls = '';
          if (lower.includes('sev=5')) cls = 'alert-high';
          else if (lower.includes('sev=3') || lower.includes('sev=4')) cls = 'alert-medium';
          tr.className = cls;
          tr.innerHTML =
            '<td><div class="small">' + line + '</div></td>' +
            '<td><div class="small"></div></td>';
          tbody.appendChild(tr);
        });
        document.getElementById('alert-count').innerText = lines.length;
      } catch (e) {
        console.error(e);
      }
    }

    async function sendDebug() {
      const btn = document.getElementById('btn-send');
      btn.disabled = true;
      try {
        const body = {
          proto: 'tcp',
          src_ip: document.getElementById('src_ip').value || '0.0.0.0',
          dst_ip: document.getElementById('dst_ip').value || '0.0.0.0',
          src_port: parseInt(document.getElementById('src_port').value || '0', 10),
          dst_port: parseInt(document.getElementById('dst_port').value || '0', 10),
          payload: document.getElementById('payload').value || ''
        };
        const res = await fetch('/debug', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        const data = await res.json();
        document.getElementById('debug-result').innerText =
          JSON.stringify(data, null, 2);
      } catch (e) {
        document.getElementById('debug-result').innerText = '调用失败: ' + e;
      } finally {
        btn.disabled = false;
      }
    }

    function fillSampleLFI() {
      document.getElementById('payload').value =
        'GET /etc/passwd HTTP/1.1\\r\\nHost: victim\\r\\n\\r\\n';
      document.getElementById('src_ip').value = '192.168.1.10';
      document.getElementById('dst_ip').value = '192.168.1.100';
      document.getElementById('src_port').value = '12345';
      document.getElementById('dst_port').value = '80';
    }

    // 初始化
    loadStatus();
    loadRules();
    loadAlerts();
    setInterval(loadAlerts, 3000);
  </script>
</body>
</html>
    """

    @app.route("/")
    @app.route("/ui")
    def ui_page():
        return Response(UI_HTML, mimetype="text/html")

    # ---------------- RULES ----------------
    @app.route("/rules", methods=["GET"])
    def get_rules():
        return jsonify([
            {
                "sid": r.sid,
                "msg": r.msg,
                "protocol": r.protocol,
                "src_ip": r.src_ip,
                "src_port": r.src_port,
                "dst_ip": r.dst_ip,
                "dst_port": r.dst_port,
                "severity": r.severity,
                "enabled": r.enabled,
                "tags": r.tags,
            }
            for r in rules
        ])

    # ---------------- SCORE ----------------
    @app.route("/score", methods=["POST"])
    def score_packet():
        """
        输入 JSON：
        {
          "proto": "tcp",
          "src_ip": "1.1.1.1",
          "dst_ip": "2.2.2.2",
          "src_port": 12345,
          "dst_port": 80,
          "payload": "string bytes"
        }
        """
        pkt = request.json or {}
        src_ip = pkt.get("src_ip", "0.0.0.0")
        dst_ip = pkt.get("dst_ip", "0.0.0.0")
        src_port = int(pkt.get("src_port") or 0)
        dst_port = int(pkt.get("dst_port") or 0)
        payload = pkt.get("payload", "")

        if isinstance(payload, str):
            payload_bytes = payload.encode(errors="ignore")
        else:
            payload_bytes = bytes(payload)

        # 构造一个假的 scapy 报文进行匹配
        scapy_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port) / Raw(load=payload_bytes)
        hits = match_packet(scapy_pkt, rules)

        return jsonify(
            {
                "hit_count": len(hits),
                "hits": [
                    {
                        "sid": h["sid"],
                        "msg": h["msg"],
                        "severity": h["rule"].severity,
                        "tags": h["rule"].tags,
                    }
                    for h in hits
                ],
            }
        )

    # ---------------- ALERTS ----------------
    @app.route("/alerts", methods=["GET"])
    def get_alerts():
        """
        返回最近 200 条告警的“可读字符串”，用于 UI 展示：
        {
          "lines": [
            "2025-11-25 [sev=5][sid=10001] ...",
            ...
          ]
        }
        """
        try:
            with open(ALERT_LOGFILE, "r", encoding="utf-8") as f:
                lines = f.readlines()[-200:]
        except FileNotFoundError:
            return jsonify({"lines": []})

        render_lines: List[str] = []
        for raw in lines:
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
                line = (
                    f"{rec.get('timestamp', '')} "
                    f"[sev={rec.get('severity', '')}][sid={rec.get('sid', '')}] "
                    f"{rec.get('msg', '')} | "
                    f"{rec.get('src', '')} -> {rec.get('dst', '')} | "
                    f"tags={','.join(rec.get('tags', []) or [])}"
                )
            except Exception:
                line = raw
            render_lines.append(line)

        return jsonify({"lines": render_lines})

    # ---------------- HYBRID: 本地签名 + LLM IDS ----------------
    @app.route("/hybrid_score", methods=["POST"])
    def hybrid_score():
        """
        混合检测接口：同时返回本地签名 IDS 命中结果 + 远端大模型 IDS 结果。
        """
        pkt = request.json or {}
        proto = pkt.get("proto", "tcp")
        src_ip = pkt.get("src_ip", "0.0.0.0")
        dst_ip = pkt.get("dst_ip", "0.0.0.0")
        src_port = int(pkt.get("src_port") or 0)
        dst_port = int(pkt.get("dst_port") or 0)
        payload = pkt.get("payload", "")

        if isinstance(payload, str):
            payload_bytes = payload.encode(errors="ignore")
        else:
            payload_bytes = bytes(payload)

        # 1. 本地规则引擎跑一遍
        scapy_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port) / Raw(load=payload_bytes)
        hits = match_packet(scapy_pkt, rules)
        signature_result = {
            "hit_count": len(hits),
            "hits": [
                {
                    "sid": h["sid"],
                    "msg": h["msg"],
                    "severity": h["rule"].severity,
                    "tags": h["rule"].tags,
                }
                for h in hits
            ],
        }

        # 2. 调用对方 LLM IDS
        packet_info = {
            "proto": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "payload": payload,  # 保持字符串，方便对方做 NLP 处理
        }
        llm_url = app.config.get("LLM_IDS_URL")
        if llm_url:
            llm_result = call_llm_ids(packet_info, llm_url)
        else:
            llm_result = {"error": "LLM_IDS_URL not configured"}

        return jsonify({"signature_ids": signature_result, "llm_ids": llm_result})

    # ---------------- DEBUG ----------------
    @app.route("/debug", methods=["GET", "POST"])
    def debug():
        """
        调试接口：
        - GET：返回服务状态、规则数量，用于健康检查。
        - POST：使用与 /score 相同格式的 JSON 做一次规则匹配，并返回详细调试信息。
        """
        if request.method == "GET":
            return jsonify(
                {
                    "status": "ok",
                    "rule_count": len(rules),
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                    "sample_sid": rules[0].sid if rules else None,
                    "sample_msg": rules[0].msg if rules else None,
                }
            )

        pkt = request.json or {}
        proto = pkt.get("proto", "tcp")
        src_ip = pkt.get("src_ip", "0.0.0.0")
        dst_ip = pkt.get("dst_ip", "0.0.0.0")
        src_port = int(pkt.get("src_port") or 0)
        dst_port = int(pkt.get("dst_port") or 0)
        payload = pkt.get("payload", "")

        if isinstance(payload, str):
            payload_bytes = payload.encode(errors="ignore")
        else:
            payload_bytes = bytes(payload)

        scapy_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port) / Raw(load=payload_bytes)
        hits = match_packet(scapy_pkt, rules)

        return jsonify(
            {
                "parsed_packet": {
                    "proto": proto,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "payload_preview": payload[:200] if isinstance(payload, str) else str(payload)[:200],
                },
                "hit_count": len(hits),
                "hits": [
                    {
                        "sid": h["sid"],
                        "msg": h["msg"],
                        "severity": h["rule"].severity,
                        "tags": h["rule"].tags,
                    }
                    for h in hits
                ],
            }
        )

    logger.info(f"Starting API on {host}:{port}")
    app.run(host=host, port=port, debug=False)


# -------------------------
# 运行统计打印
# -------------------------
def print_stats(stats: Stats):
    logger.info("========= mini_snort_pro statistics =========")
    logger.info(f"Total packets captured: {stats.total_packets}")
    logger.info(f"Packets with alerts:    {stats.matched_packets}")
    if not stats.alerts_per_rule:
        logger.info("No alerts generated.")
        return

    logger.info("Alerts per rule SID:")
    for sid, count in sorted(stats.alerts_per_rule.items()):
        logger.info(f"  SID {sid}: {count} alerts")


# -------------------------
# CLI 入口
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="mini_snort_pro - tiny signature-based IDS demo")
    parser.add_argument("--mode", choices=["live", "pcap"], default="pcap", help="运行模式: live 或 pcap")
    parser.add_argument("--interface", "-i", help="网卡 (live 模式需要)")
    parser.add_argument("--pcap", "-r", help="pcap 文件 (pcap 模式需要)")
    parser.add_argument("--rules", "-R", required=True, help="规则 JSON 文件路径")
    parser.add_argument("--count", type=int, default=0, help="抓包数量，0 表示无限 (live 模式)")
    parser.add_argument("--replay-delay", type=float, default=0.0, help="回放 pcap 时每包延迟 (秒)")
    parser.add_argument("--bpf", help="BPF 抓包过滤表达式（如 'tcp port 80'）", default=None)
    parser.add_argument("--api", action="store_true", help="仅开启 REST API (需要 flask)")
    parser.add_argument("--api-port", type=int, default=5001, help="API 端口")

    args = parser.parse_args()

    # 每次运行清空 alert 文件（演示用；真实系统一般不会清）
    open(ALERT_LOGFILE, "w", encoding="utf-8").close()

    if args.api:
        start_api(args.rules, host="0.0.0.0", port=args.api_port)
        return

    if args.mode == "live":
        if not args.interface:
            parser.error("--interface is required for live mode")
        stats = run_live(args.interface, args.rules, count=args.count, bpf_filter=args.bpf)
    else:
        if not args.pcap:
            parser.error("--pcap is required for pcap mode")
        stats = run_pcap(args.pcap, args.rules, replay_delay=args.replay_delay)

    print_stats(stats)


if __name__ == "__main__":
    main()
