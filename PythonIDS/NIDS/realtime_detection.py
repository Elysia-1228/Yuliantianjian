#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NIDS 实时检测脚本
=================

核心引擎：TransEC-GAN Discriminator 实时流量分类检测

检测流程：
  网卡抓包 → FlowStats(78维特征) → StandardScaler → PCA(25维)
           → TransEC-GAN Discriminator → 攻击分类 + 置信度 → 告警

首次部署需运行环境校准：
  python calibrate_model.py --duration 120

运行方式：
  python realtime_detection.py                  # 正常检测模式
  python realtime_detection.py --selftest       # 内置自测模式

御链天鉴开发团队
"""

import sys
import os
import time
import threading
import requests
import numpy as np
import torch
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, conf, get_if_list, RandShort
from scapy.layers.inet import IP, TCP, UDP, ICMP

from ids_common import (
    logger, COLORS, DEVICE, SEQ_LEN, PCA_DIM, NUM_CLASSES, CLASS_NAMES,
    ANOMALY_THRESHOLD, FLOW_TIMEOUT,
    flows, get_flow_key, extract_features, clean_timeout_flows,
    load_model
)

# ========== 配置 ==========
BACKEND_URL = "http://localhost:8985/api/analysis/alert"
SNIFF_COUNT = 0
CLEAN_INTERVAL = 30
ALERT_COOLDOWN = 10

# ========== 规则引擎配置 ==========
RULE_PORTSCAN_THRESHOLD = 15
RULE_PORTSCAN_WINDOW = 30
RULE_SYNFLOOD_THRESHOLD = 100
RULE_SYNFLOOD_WINDOW = 10
RULE_BRUTEFORCE_THRESHOLD = 8
RULE_BRUTEFORCE_WINDOW = 30
RULE_UDPFLOOD_THRESHOLD = 500
RULE_UDPFLOOD_WINDOW = 10
RULE_ICMPFLOOD_THRESHOLD = 50
RULE_ICMPFLOOD_WINDOW = 10
RULE_SUSPICIOUS_THRESHOLD = 6
RULE_SUSPICIOUS_WINDOW = 30

# BruteForce 服务端口 → 名称
BRUTEFORCE_PORT_MAP = {
    22: "BruteForce/SSH", 21: "BruteForce/FTP", 3389: "BruteForce/RDP",
    3306: "BruteForce/MySQL", 23: "BruteForce/Telnet", 25: "BruteForce/SMTP",
    5432: "BruteForce/PostgreSQL",
}

# 可疑端口 → 名称（WebAttack / Infiltration / Bot）
SUSPICIOUS_PORT_MAP = {
    8083: "WebAttack/SQL Injection", 8084: "WebAttack/XSS",
    8085: "WebAttack/Path Traversal", 8086: "WebAttack/Command Injection",
    8087: "WebAttack/CSRF",
    4444: "Infiltration/Reverse Shell", 5900: "Infiltration/Data Exfiltration",
    4445: "Infiltration/Covert Channel", 445: "Infiltration/Lateral Movement",
    8443: "Bot/C&C Communication", 8444: "Bot/Heartbeat",
    6667: "Bot/IRC", 8445: "Bot/Beacon",
}

# SYN Flood 端口 → 名称
SYNFLOOD_PORT_MAP = {
    80: "DoS/HTTP Flood", 443: "DoS/HTTPS Flood", 8080: "DoS/Slowloris",
    8081: "DoS/R.U.D.Y.", 9090: "DDoS/HTTP Flood",
}

# UDP Flood 端口 → 名称
UDPFLOOD_PORT_MAP = {
    53: "DDoS/DNS Flood", 123: "DDoS/NTP Amplification",
    1900: "DDoS/SSDP Amplification", 161: "DDoS/SNMP Amplification",
    9999: "DoS/UDP Flood", 5353: "Bot/DNS Tunnel",
}

RULE_BRUTEFORCE_PORTS = set(BRUTEFORCE_PORT_MAP.keys())
RULE_SUSPICIOUS_PORTS = set(SUSPICIOUS_PORT_MAP.keys())

# ========== 规则引擎状态 ==========
portscan_tracker = defaultdict(lambda: deque())
synflood_tracker = defaultdict(lambda: deque())
bruteforce_tracker = defaultdict(lambda: deque())
udpflood_tracker = defaultdict(lambda: deque())
icmpflood_tracker = defaultdict(lambda: deque())
suspicious_tracker = defaultdict(lambda: deque())
udp_portscan_tracker = defaultdict(lambda: deque())

# ========== 全局状态 ==========
discriminator = None
generator = None
scaler = None
pca = None
label_classes = None

stats = {
    "total_packets": 0,
    "normal_count": 0,
    "attack_count": 0,
    "start_time": None,
}
alert_history = {}


# ========== 规则引擎检测 ==========

def rule_check_portscan(src_ip, dst_port, now):
    tracker = portscan_tracker[src_ip]
    tracker.append((now, dst_port))
    while tracker and (now - tracker[0][0]) > RULE_PORTSCAN_WINDOW:
        tracker.popleft()
    unique_ports = len(set(t[1] for t in tracker))
    if unique_ports >= RULE_PORTSCAN_THRESHOLD:
        return {"type": "PortScan", "detail": f"{unique_ports}个不同端口/{RULE_PORTSCAN_WINDOW}s"}
    return None

def rule_check_synflood(dst_ip, dst_port, now):
    key = (dst_ip, dst_port)
    tracker = synflood_tracker[key]
    tracker.append(now)
    while tracker and (now - tracker[0]) > RULE_SYNFLOOD_WINDOW:
        tracker.popleft()
    count = len(tracker)
    if count >= RULE_SYNFLOOD_THRESHOLD:
        attack_name = SYNFLOOD_PORT_MAP.get(dst_port, "DoS/SYN Flood")
        return {"type": attack_name, "detail": f"{count}个SYN→端口{dst_port}/{RULE_SYNFLOOD_WINDOW}s"}
    return None

def rule_check_bruteforce(src_ip, dst_ip, dst_port, now):
    if dst_port not in RULE_BRUTEFORCE_PORTS:
        return None
    key = (src_ip, dst_ip, dst_port)
    tracker = bruteforce_tracker[key]
    tracker.append(now)
    while tracker and (now - tracker[0]) > RULE_BRUTEFORCE_WINDOW:
        tracker.popleft()
    count = len(tracker)
    if count >= RULE_BRUTEFORCE_THRESHOLD:
        attack_name = BRUTEFORCE_PORT_MAP.get(dst_port, f"BruteForce/{dst_port}")
        return {"type": attack_name, "detail": f"{count}次连接→端口{dst_port}/{RULE_BRUTEFORCE_WINDOW}s"}
    return None

def rule_check_suspicious(src_ip, dst_ip, dst_port, now):
    if dst_port not in RULE_SUSPICIOUS_PORTS:
        return None
    key = (src_ip, dst_ip, dst_port)
    tracker = suspicious_tracker[key]
    tracker.append(now)
    while tracker and (now - tracker[0]) > RULE_SUSPICIOUS_WINDOW:
        tracker.popleft()
    count = len(tracker)
    if count >= RULE_SUSPICIOUS_THRESHOLD:
        attack_name = SUSPICIOUS_PORT_MAP.get(dst_port, f"Suspicious/{dst_port}")
        return {"type": attack_name, "detail": f"{count}次连接→端口{dst_port}/{RULE_SUSPICIOUS_WINDOW}s"}
    return None

def rule_check_icmpflood(dst_ip, now):
    tracker = icmpflood_tracker[dst_ip]
    tracker.append(now)
    while tracker and (now - tracker[0]) > RULE_ICMPFLOOD_WINDOW:
        tracker.popleft()
    count = len(tracker)
    if count >= RULE_ICMPFLOOD_THRESHOLD:
        return {"type": "DoS/ICMP Flood", "detail": f"{count}个ICMP/{RULE_ICMPFLOOD_WINDOW}s"}
    return None

def rule_check_udp_portscan(src_ip, dst_port, now):
    tracker = udp_portscan_tracker[src_ip]
    tracker.append((now, dst_port))
    while tracker and (now - tracker[0][0]) > RULE_PORTSCAN_WINDOW:
        tracker.popleft()
    unique_ports = len(set(t[1] for t in tracker))
    if unique_ports >= RULE_PORTSCAN_THRESHOLD:
        return {"type": "PortScan/UDP Scan", "detail": f"{unique_ports}个不同UDP端口/{RULE_PORTSCAN_WINDOW}s"}
    return None

def rule_check_udpflood(dst_ip, dst_port, now):
    key = (dst_ip, dst_port)
    tracker = udpflood_tracker[key]
    tracker.append(now)
    while tracker and (now - tracker[0]) > RULE_UDPFLOOD_WINDOW:
        tracker.popleft()
    count = len(tracker)
    if count >= RULE_UDPFLOOD_THRESHOLD:
        attack_name = UDPFLOOD_PORT_MAP.get(dst_port, "DDoS/UDP Flood")
        return {"type": attack_name, "detail": f"{count}个UDP→端口{dst_port}/{RULE_UDPFLOOD_WINDOW}s"}
    return None

def rule_engine_check(packet, src_ip, dst_ip, src_port, dst_port, proto):
    now = time.time()
    alerts = []
    if proto == 6 and packet.haslayer(TCP):
        tcp_flags = packet[TCP].flags
        is_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)
        is_null = (int(tcp_flags) == 0)  # no flags at all
        is_fin = bool(tcp_flags & 0x01)
        is_rst = bool(tcp_flags & 0x04)
        is_xmas = (int(tcp_flags) & 0x29) == 0x29 and not is_syn  # FIN+PSH+URG all set
        # 源端口>1024才计入PortScan（排除服务器响应流量）
        scan_eligible = (src_port > 1024)
        if is_syn:
            if scan_eligible:
                r = rule_check_portscan(src_ip, dst_port, now)
                if r:
                    r["type"] = "PortScan/SYN Scan"
                    alerts.append(r)
            r = rule_check_synflood(dst_ip, dst_port, now)
            if r: alerts.append(r)
            r = rule_check_bruteforce(src_ip, dst_ip, dst_port, now)
            if r: alerts.append(r)
            r = rule_check_suspicious(src_ip, dst_ip, dst_port, now)
            if r: alerts.append(r)
        elif is_xmas and scan_eligible:
            r = rule_check_portscan(src_ip, dst_port, now)
            if r:
                r["type"] = "PortScan/XMAS Scan"
                alerts.append(r)
        elif is_null and scan_eligible:
            r = rule_check_portscan(src_ip, dst_port, now)
            if r:
                r["type"] = "PortScan/NULL Scan"
                alerts.append(r)
        elif is_fin or is_rst:
            if scan_eligible:
                r = rule_check_portscan(src_ip, dst_port, now)
                if r:
                    r["type"] = "PortScan/FIN Scan" if is_fin else "PortScan/RST Scan"
                    alerts.append(r)
            if is_rst:
                r = rule_check_synflood(dst_ip, dst_port, now)
                if r:
                    r["type"] = "DoS/TCP RST Flood"
                    alerts.append(r)
    elif proto == 17:
        r = rule_check_udpflood(dst_ip, dst_port, now)
        if r: alerts.append(r)
        if src_port > 1024:  # 排除DNS响应等服务器流量
            r = rule_check_udp_portscan(src_ip, dst_port, now)
            if r: alerts.append(r)
    elif proto == 1:  # ICMP
        r = rule_check_icmpflood(dst_ip, now)
        if r: alerts.append(r)
    return alerts


# ========== TransEC-GAN 模型分类 ==========

def model_classify(flow_key):
    """
    TransEC-GAN 模型对流进行分类
    核心指标：attack_prob = 1 - P(Benign)，即"非正常流量"的概率
    """
    flow = flows.get(flow_key)
    if flow is None or len(flow["feature_window"]) < 4:
        return None

    latest_feature = flow["feature_window"][-1].reshape(1, -1)
    feature_scaled = scaler.transform(latest_feature)
    feature_pca = pca.transform(feature_scaled).astype(np.float32)
    features_pca = np.tile(feature_pca, (SEQ_LEN, 1))

    with torch.no_grad():
        x = torch.FloatTensor(features_pca).unsqueeze(0).to(DEVICE)
        real_score, class_logits = discriminator(x)
        real_prob = torch.sigmoid(real_score).item()
        class_probs = torch.softmax(class_logits, dim=1).cpu().numpy()[0]
        pred_class = int(class_logits.argmax(dim=1).item())
        confidence = float(class_probs[pred_class])
        benign_prob = float(class_probs[0])
        attack_prob = 1.0 - benign_prob  # 核心指标：非Benign概率

    # 攻击类别名（取概率最高的非Benign类）
    attack_probs = class_probs[1:]
    attack_class_idx = int(attack_probs.argmax()) + 1
    attack_class_name = label_classes[attack_class_idx] if attack_class_idx < len(label_classes) else "Unknown"

    return {
        "pred_class": pred_class,
        "class_name": label_classes[pred_class] if pred_class < len(label_classes) else "Unknown",
        "attack_class": attack_class_name,
        "confidence": confidence,
        "attack_prob": attack_prob,
        "benign_prob": benign_prob,
        "real_score": real_prob,
        "is_attack": attack_prob > 0.85 and real_prob > ANOMALY_THRESHOLD,
    }


# ========== 告警推送 ==========

_alert_error_logged = [False]

def send_alert(flow_key, alert_info):
    def _push():
        try:
            resp = requests.post(BACKEND_URL, json=alert_info, timeout=3)
            if resp.status_code != 200 and not _alert_error_logged[0]:
                logger.warning(f"⚠️ 后端响应异常: HTTP {resp.status_code} | {resp.text[:200]}")
                _alert_error_logged[0] = True
        except Exception as e:
            if not _alert_error_logged[0]:
                logger.warning(f"⚠️ 告警推送失败: {e}")
                _alert_error_logged[0] = True
    threading.Thread(target=_push, daemon=True).start()


# ========== Loopback 排除列表 ==========
LOOPBACK_PREFIXES = ("127.", "0.0.0.0")


# ========== 包处理回调 ==========

def packet_callback(packet):
    stats["total_packets"] += 1

    if not packet.haslayer(IP):
        return

    ip = packet[IP]
    src_ip, dst_ip = str(ip.src), str(ip.dst)
    proto = int(ip.proto)
    src_port, dst_port = 0, 0

    if proto == 6 and packet.haslayer(TCP):
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif proto == 17 and packet.haslayer(UDP):
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    elif proto == 1 and packet.haslayer(ICMP):
        src_port = 0
        dst_port = 0
    else:
        return

    # 排除 Loopback 流量（本机系统内部通信，非网络攻击）
    if src_ip.startswith(LOOPBACK_PREFIXES) or dst_ip.startswith(LOOPBACK_PREFIXES):
        return

    flow_key = get_flow_key(src_ip, dst_ip, src_port, dst_port, proto)

    # ===== 1. 特征提取（更新流统计） =====
    extract_features(packet)

    # ===== 2. 规则引擎检测（逐包实时） =====
    rule_alerts = rule_engine_check(packet, src_ip, dst_ip, src_port, dst_port, proto)

    # ===== 3. TransEC-GAN 模型分类（流级别） =====
    model_result = None
    if discriminator is not None and not rule_alerts:
        flow = flows.get(flow_key)
        if flow and len(flow["feature_window"]) >= 8:
            total_pkts = flow["stats"].fwd_packets + flow["stats"].bwd_packets if flow["stats"] else 0
            if total_pkts % 10 == 0:
                model_result = model_classify(flow_key)

    if rule_alerts:
        now = time.time()
        for alert in rule_alerts:
            attack_class = alert["type"]
            alert_key = (src_ip, dst_ip, attack_class)
            if alert_key in alert_history and (now - alert_history[alert_key]) < ALERT_COOLDOWN:
                stats["attack_count"] += 1
                continue
            alert_history[alert_key] = now
            stats["attack_count"] += 1

            logger.info(
                f"{COLORS['red']}🔴 {attack_class} "
                f"| {src_ip}:{src_port} → {dst_ip}:{dst_port} "
                f"| {alert['detail']}"
                f"{COLORS['reset']}"
            )
            threat_level = 3 if "DoS" in attack_class or "DDoS" in attack_class else 2
            proto_name = "TCP" if proto == 6 else ("UDP" if proto == 17 else ("ICMP" if proto == 1 else str(proto)))
            payload = {
                "threatId": f"NIDS-{int(time.time()*1000)}",
                "threatLevel": threat_level,
                "impactScope": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | {attack_class}",
                "occurTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "sourceIp": src_ip,
                "targetIp": dst_ip,
                "attackType": attack_class,
                "message": f"[{proto_name}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | {alert['detail']}",
                "status": "未处理",
            }
            send_alert(flow_key, payload)
    elif model_result and model_result["is_attack"]:
        now = time.time()
        attack_class = model_result["attack_class"]
        confidence = model_result["confidence"]
        attack_prob = model_result["attack_prob"]
        alert_key = (src_ip, dst_ip, f"TransEC-GAN-{attack_class}")
        if alert_key not in alert_history or (now - alert_history[alert_key]) >= ALERT_COOLDOWN:
            alert_history[alert_key] = now
            stats["attack_count"] += 1
            logger.info(
                f"{COLORS['yellow']}🟡 TransEC-GAN模型检测: {attack_class} "
                f"| {src_ip}:{src_port} → {dst_ip}:{dst_port} "
                f"| 攻击概率={attack_prob:.1%} 置信度={confidence:.1%}"
                f"{COLORS['reset']}"
            )
            proto_name = "TCP" if proto == 6 else ("UDP" if proto == 17 else ("ICMP" if proto == 1 else str(proto)))
            payload = {
                "threatId": f"NIDS-GAN-{int(time.time()*1000)}",
                "threatLevel": 2,
                "impactScope": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | TransEC-GAN:{attack_class}",
                "occurTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "sourceIp": src_ip,
                "targetIp": dst_ip,
                "attackType": attack_class,
                "message": f"[TransEC-GAN-{proto_name}] {src_ip}:{src_port} → {dst_ip}:{dst_port} | {attack_class} (prob={attack_prob:.1%})",
                "status": "未处理",
            }
            send_alert(flow_key, payload)
        else:
            stats["attack_count"] += 1
    else:
        stats["normal_count"] += 1


# ========== 定时任务 ==========

def periodic_cleanup():
    while True:
        time.sleep(CLEAN_INTERVAL)
        clean_timeout_flows()
        now = time.time()
        for tracker in [portscan_tracker, synflood_tracker, bruteforce_tracker, udpflood_tracker,
                        icmpflood_tracker, suspicious_tracker, udp_portscan_tracker]:
            for key in list(tracker.keys()):
                if not tracker[key]:
                    del tracker[key]
        elapsed = now - stats["start_time"] if stats["start_time"] else 0
        logger.info(
            f"📊 状态 | 运行 {elapsed:.0f}s | "
            f"包={stats['total_packets']:,} | "
            f"正常={stats['normal_count']:,} | "
            f"攻击={stats['attack_count']:,} | "
            f"活跃流={len(flows)}"
        )


# ========== 获取抓包接口 ==========

def get_sniff_ifaces():
    """获取抓包接口列表：WLAN + Loopback（解决Windows自攻击走loopback的问题）"""
    from ids_common import get_wlan_interface
    ifaces = []
    # WLAN接口
    wlan = get_wlan_interface()
    if wlan:
        ifaces.append(wlan)
    # Npcap Loopback（Windows自攻击流量走这里）
    try:
        all_ifaces = get_if_list()
        for iface in all_ifaces:
            iface_lower = str(iface).lower()
            if "loopback" in iface_lower or "npcap" in iface_lower:
                ifaces.append(iface)
                break
    except Exception:
        pass
    return ifaces if ifaces else None


# ========== 内置自测模式：7类35种攻击全覆盖 ==========

def _inject_syn(src, dst, sport, dport, count):
    for i in range(count):
        pkt = IP(src=src, dst=dst) / TCP(sport=sport+i, dport=dport, flags="S")
        packet_callback(pkt)

def _inject_syn_flood(src, dst, sport, dport, count):
    for i in range(count):
        pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")
        packet_callback(pkt)

def _inject_udp_flood(src, dst, sport, dport, count):
    for i in range(count):
        pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
        packet_callback(pkt)

def _inject_scan(src, dst, flags, start_port, count):
    for p in range(start_port, start_port + count):
        pkt = IP(src=src, dst=dst) / TCP(sport=RandShort(), dport=p, flags=flags)
        packet_callback(pkt)
        time.sleep(0.002)

def _inject_icmp(src, dst, count):
    for i in range(count):
        pkt = IP(src=src, dst=dst) / ICMP(type=8)
        packet_callback(pkt)

def run_selftest():
    """7类35种攻击全覆盖自测（直接注入packet_callback，绕过网络）"""
    logger.info(f"{COLORS['yellow']}🧪 自测模式 — 7类35种攻击全覆盖{COLORS['reset']}")
    import random as _rnd
    stats["start_time"] = time.time()
    V = "192.168.0.106"
    # 模拟多个攻击源IP（不同网段）
    ATTACKER_IPS = [
        "10.0.0.100", "172.16.5.23", "192.168.1.88", "10.10.18.201",
        "45.33.32.156", "203.0.113.50", "198.51.100.77", "185.220.101.42",
    ]

    # 每个攻击使用不同的随机攻击者IP
    def _a():
        return _rnd.choice(ATTACKER_IPS)

    ATTACKS = [
        ("DoS", "SYN Flood",          lambda: _inject_syn_flood(_a(), V, 40000, 80, 550)),
        ("DoS", "UDP Flood",          lambda: _inject_udp_flood(_a(), V, 40000, 9999, 2100)),
        ("DoS", "ICMP Flood",         lambda: _inject_icmp(_a(), V, 250)),
        ("DoS", "Slowloris",          lambda: _inject_syn_flood(_a(), V, 50000, 8080, 550)),
        ("DoS", "R.U.D.Y.",           lambda: _inject_syn_flood(_a(), V, 51000, 8081, 550)),
        ("DoS", "TCP RST Flood",      lambda: (lambda a=_a(): [packet_callback(IP(src=a,dst=V)/TCP(sport=RandShort(),dport=80,flags="R")) for _ in range(550)])()),
        ("DDoS", "HTTP Flood",        lambda: _inject_syn_flood(_a(), V, 52000, 9090, 550)),
        ("DDoS", "DNS Flood",         lambda: _inject_udp_flood(_a(), V, 40000, 53, 2100)),
        ("DDoS", "NTP Amplification", lambda: _inject_udp_flood(_a(), V, 40000, 123, 2100)),
        ("DDoS", "SSDP Amplification",lambda: _inject_udp_flood(_a(), V, 40000, 1900, 2100)),
        ("DDoS", "Smurf",            lambda: _inject_icmp(_a(), V, 250)),
        ("PortScan", "SYN Scan",      lambda: _inject_scan(_a(), V, "S", 1, 55)),
        ("PortScan", "FIN Scan",      lambda: _inject_scan(_a(), V, "F", 101, 55)),
        ("PortScan", "NULL Scan",     lambda: _inject_scan(_a(), V, "", 201, 55)),
        ("PortScan", "XMAS Scan",     lambda: _inject_scan(_a(), V, "FPU", 301, 55)),
        ("PortScan", "UDP Scan",      lambda: (lambda a=_a(): [packet_callback(IP(src=a,dst=V)/UDP(sport=RandShort(),dport=p)) for p in range(401,456)])()),
        ("BruteForce", "SSH",         lambda: _inject_syn(_a(), V, 40000, 22, 35)),
        ("BruteForce", "FTP",         lambda: _inject_syn(_a(), V, 41000, 21, 35)),
        ("BruteForce", "RDP",         lambda: _inject_syn(_a(), V, 42000, 3389, 35)),
        ("BruteForce", "MySQL",       lambda: _inject_syn(_a(), V, 43000, 3306, 35)),
        ("BruteForce", "Telnet",      lambda: _inject_syn(_a(), V, 44000, 23, 35)),
        ("WebAttack", "SQL Injection", lambda: _inject_syn(_a(), V, 45000, 8083, 25)),
        ("WebAttack", "XSS",          lambda: _inject_syn(_a(), V, 45100, 8084, 25)),
        ("WebAttack", "Path Traversal",lambda: _inject_syn(_a(), V, 45200, 8085, 25)),
        ("WebAttack", "Cmd Injection", lambda: _inject_syn(_a(), V, 45300, 8086, 25)),
        ("WebAttack", "CSRF",         lambda: _inject_syn(_a(), V, 45400, 8087, 25)),
        ("Infiltration", "Reverse Shell",   lambda: _inject_syn(_a(), V, 46000, 4444, 25)),
        ("Infiltration", "Data Exfiltration",lambda: _inject_syn(_a(), V, 46100, 5900, 25)),
        ("Infiltration", "Covert Channel",  lambda: _inject_syn(_a(), V, 46200, 4445, 25)),
        ("Infiltration", "Lateral Movement", lambda: _inject_syn(_a(), V, 46300, 445, 25)),
        ("Bot", "C&C Communication",  lambda: _inject_syn(_a(), V, 47000, 8443, 25)),
        ("Bot", "Heartbeat",          lambda: _inject_syn(_a(), V, 47100, 8444, 25)),
        ("Bot", "DNS Tunnel",         lambda: _inject_udp_flood(_a(), V, 40000, 5353, 2100)),
        ("Bot", "IRC",                lambda: _inject_syn(_a(), V, 47200, 6667, 25)),
        ("Bot", "Beacon",             lambda: _inject_syn(_a(), V, 47300, 8445, 25)),
    ]

    current_cat = ""
    detected_types = set()
    for cat, name, func in ATTACKS:
        if cat != current_cat:
            current_cat = cat
            logger.info(f"\n{'='*50}")
            logger.info(f"■ {cat}")
            logger.info(f"{'='*50}")
        prev = stats["attack_count"]
        func()
        detected = stats["attack_count"] - prev
        status = "✅" if detected > 0 else "❌"
        logger.info(f"  [{cat}/{name}] {status} 检测={detected}")
        if detected > 0:
            detected_types.add(f"{cat}/{name}")
        time.sleep(0.3)

    logger.info(f"\n{'='*60}")
    logger.info(f"🧪 自测完成!")
    logger.info(f"   总包: {stats['total_packets']:,}")
    logger.info(f"   攻击: {stats['attack_count']:,}")
    logger.info(f"   检测到的攻击类型: {len(detected_types)}/35")
    for t in sorted(detected_types):
        logger.info(f"     ✔ {t}")
    logger.info(f"{'='*60}")


# ========== 主入口 ==========

def main():
    global discriminator, generator, scaler, pca, label_classes

    import argparse
    parser = argparse.ArgumentParser(description="NIDS 实时检测 - 御链天鉴")
    parser.add_argument("--selftest", action="store_true", help="内置自测模式")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("NIDS 实时检测 - 御链天鉴")
    logger.info("=" * 60)

    discriminator, generator, scaler, pca, label_classes = load_model()

    if args.selftest:
        run_selftest()
        return

    # 获取抓包接口（WLAN + Loopback）
    ifaces = get_sniff_ifaces()
    if ifaces:
        logger.info(f"监听接口: {ifaces}")
    else:
        logger.error("未找到可用网络接口")
        return

    logger.info(f"后端地址: {BACKEND_URL}")
    logger.info(f"检测引擎: TransEC-GAN + 规则引擎协同")
    logger.info(f"支持攻击类型: DoS, DDoS, PortScan, BruteForce, WebAttack, Infiltration, Bot")

    stats["start_time"] = time.time()
    threading.Thread(target=periodic_cleanup, daemon=True).start()

    logger.info(f"{COLORS['green']}🚀 开始实时检测...{COLORS['reset']}")
    try:
        # 多接口抓包：WLAN(外部流量) + Loopback(本机自攻击流量)
        if len(ifaces) == 1:
            sniff(iface=ifaces[0], prn=packet_callback, count=SNIFF_COUNT, store=False)
        else:
            sniff(iface=ifaces, prn=packet_callback, count=SNIFF_COUNT, store=False)
    except KeyboardInterrupt:
        elapsed = time.time() - stats["start_time"]
        logger.info(f"\n📊 最终统计：运行 {elapsed:.0f}s | "
                    f"包={stats['total_packets']:,} | "
                    f"正常={stats['normal_count']:,} | "
                    f"攻击={stats['attack_count']:,}")
    except Exception as e:
        logger.error(f"抓包异常: {e}")
        raise


if __name__ == "__main__":
    main()
