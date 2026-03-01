#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速攻击演示脚本 — 7类35种攻击全覆盖
========================================

依次执行 7 大类 35 种攻击（全部 Scapy 原始包，同机 NIDS 可检测）：
  DoS(6) / DDoS(5) / PortScan(5) / BruteForce(5)
  WebAttack(5) / Infiltration(4) / Bot(5)

用法：
  python quick_attack.py                    # 攻击默认目标
  python quick_attack.py --target 10.0.0.1  # 指定目标

⚠️ 仅用于授权测试环境！

御链天鉴开发团队
"""

import argparse
import random
import time
import sys
from config import TARGET_IP
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, send, RandShort, conf

conf.verb = 0

# ========== 模拟攻击源IP池（不同网段，模拟真实多源攻击） ==========
ATTACKER_IPS = [
    "10.0.0.100",       # 内网段A
    "172.16.5.23",      # 内网段B
    "192.168.1.88",     # 内网段C
    "10.10.18.201",     # 内网段D
    "45.33.32.156",     # 外网 — 扫描器
    "203.0.113.50",     # 外网 — C&C
    "198.51.100.77",    # 外网 — 僵尸网络
    "185.220.101.42",   # 外网 — Tor出口
]

# 每个攻击大类分配不同的源IP段，保证同类攻击源IP一致、不同类攻击源IP不同
_CATEGORY_IP = {
    "DoS":          ["10.0.0.100", "172.16.5.23"],
    "DDoS":         ["45.33.32.156", "198.51.100.77", "185.220.101.42"],
    "PortScan":     ["10.10.18.201"],
    "BruteForce":   ["192.168.1.88"],
    "WebAttack":    ["203.0.113.50"],
    "Infiltration": ["185.220.101.42"],
    "Bot":          ["198.51.100.77", "203.0.113.50"],
}

# 当前攻击使用的源IP（由 main 中按类别设置）
_current_src = [None]

def _get_src():
    """获取当前攻击源IP"""
    return _current_src[0] or random.choice(ATTACKER_IPS)


# ========== 快速发包工具 ==========

def _flood_syn(target, dport, count, sport_base=40000):
    """快速 SYN Flood"""
    src = _get_src()
    sports = [sport_base + i for i in range(5)]
    sent = 0
    while sent < count:
        n = min(100, count - sent)
        pkt = IP(src=src, dst=target) / TCP(sport=random.choice(sports), dport=dport, flags="S",
                                    seq=random.randint(0, 2**32 - 1))
        send(pkt, count=n, inter=0)
        sent += n

def _flood_udp(target, dport, count, payload_size=128):
    """快速 UDP Flood"""
    src = _get_src()
    sent = 0
    while sent < count:
        n = min(100, count - sent)
        pkt = IP(src=src, dst=target) / UDP(sport=RandShort(), dport=dport) / Raw(load=bytes(payload_size))
        send(pkt, count=n, inter=0)
        sent += n

def _scan_ports(target, flags, start, count):
    """端口扫描"""
    src = _get_src()
    for p in range(start, start + count):
        send(IP(src=src, dst=target) / TCP(sport=RandShort(), dport=p, flags=flags))
        time.sleep(0.01)

def _brute(target, dport, count, sport_base=40000):
    """暴力破解/连接尝试 — 批量发送确保被抓到"""
    src = _get_src()
    pkts = [IP(src=src, dst=target) / TCP(sport=sport_base + i, dport=dport, flags="S") for i in range(count)]
    send(pkts)


# ========== 35 种攻击函数 ==========

# ────────── DoS (6种) ──────────
def dos_syn_flood(t):
    _flood_syn(t, 80, 550)
def dos_udp_flood(t):
    _flood_udp(t, 9999, 2100)
def dos_icmp_flood(t):
    src = _get_src()
    for _ in range(250):
        send(IP(src=src, dst=t) / ICMP(type=8) / Raw(load=bytes(512)))
def dos_slowloris(t):
    _flood_syn(t, 8080, 550, 50000)
def dos_rudy(t):
    _flood_syn(t, 8081, 550, 51000)
def dos_tcp_rst(t):
    src = _get_src()
    sent = 0
    while sent < 550:
        n = min(100, 550 - sent)
        send(IP(src=src, dst=t) / TCP(sport=RandShort(), dport=80, flags="R"), count=n, inter=0)
        sent += n

# ────────── DDoS (5种) ──────────
def ddos_http_flood(t):
    _flood_syn(t, 9090, 550, 52000)
def ddos_dns_flood(t):
    _flood_udp(t, 53, 2100, 64)
def ddos_ntp_amp(t):
    _flood_udp(t, 123, 2100, 48)
def ddos_ssdp_amp(t):
    _flood_udp(t, 1900, 2100, 128)
def ddos_smurf(t):
    src = _get_src()
    for _ in range(250):
        send(IP(src=src, dst=t) / ICMP(type=8) / Raw(load=b"SMURF" * 20))

# ────────── PortScan (5种) ──────────
def scan_syn(t):
    _scan_ports(t, "S", 1, 35)
def scan_fin(t):
    _scan_ports(t, "F", 1, 35)
def scan_null(t):
    _scan_ports(t, "", 1, 35)
def scan_xmas(t):
    _scan_ports(t, "FPU", 1, 35)
def scan_udp(t):
    src = _get_src()
    for p in range(1, 36):
        send(IP(src=src, dst=t) / UDP(sport=RandShort(), dport=p) / Raw(load=b"\x00"))
        time.sleep(0.01)

# ────────── BruteForce (5种) ──────────
def brute_ssh(t):
    _brute(t, 22, 35)
def brute_ftp(t):
    _brute(t, 21, 35, 41000)
def brute_rdp(t):
    _brute(t, 3389, 35, 42000)
def brute_mysql(t):
    _brute(t, 3306, 35, 43000)
def brute_telnet(t):
    _brute(t, 23, 35, 44000)

# ────────── WebAttack (5种) ──────────
def web_sql_injection(t):
    _brute(t, 8083, 25, 45000)
def web_xss(t):
    _brute(t, 8084, 25, 45100)
def web_path_traversal(t):
    _brute(t, 8085, 25, 45200)
def web_cmd_injection(t):
    _brute(t, 8086, 25, 45300)
def web_csrf(t):
    _brute(t, 8087, 25, 45400)

# ────────── Infiltration (4种) ──────────
def infil_reverse_shell(t):
    _brute(t, 4444, 25, 46000)
def infil_data_exfil(t):
    _brute(t, 5900, 25, 46100)
def infil_covert_channel(t):
    _brute(t, 4445, 25, 46200)
def infil_lateral_move(t):
    _brute(t, 445, 25, 46300)

# ────────── Bot (5种) ──────────
def bot_cnc(t):
    _brute(t, 8443, 25, 47000)
def bot_heartbeat(t):
    _brute(t, 8444, 25, 47100)
def bot_dns_tunnel(t):
    _flood_udp(t, 5353, 2100, 64)
def bot_irc(t):
    _brute(t, 6667, 25, 47200)
def bot_beacon(t):
    _brute(t, 8445, 25, 47300)


# ========== 攻击清单 ==========

ATTACKS = [
    # (序号, 大类, 子类型名, 函数)
    ( 1, "DoS",          "SYN Flood",            dos_syn_flood),
    ( 2, "DoS",          "UDP Flood",            dos_udp_flood),
    ( 3, "DoS",          "ICMP Flood",           dos_icmp_flood),
    ( 4, "DoS",          "Slowloris",            dos_slowloris),
    ( 5, "DoS",          "R.U.D.Y.",             dos_rudy),
    ( 6, "DoS",          "TCP RST Flood",        dos_tcp_rst),
    ( 7, "DDoS",         "HTTP Flood",           ddos_http_flood),
    ( 8, "DDoS",         "DNS Amplification",    ddos_dns_flood),
    ( 9, "DDoS",         "NTP Amplification",    ddos_ntp_amp),
    (10, "DDoS",         "SSDP Amplification",   ddos_ssdp_amp),
    (11, "DDoS",         "Smurf",                ddos_smurf),
    (12, "PortScan",     "SYN Scan",             scan_syn),
    (13, "PortScan",     "FIN Scan",             scan_fin),
    (14, "PortScan",     "NULL Scan",            scan_null),
    (15, "PortScan",     "XMAS Scan",            scan_xmas),
    (16, "PortScan",     "UDP Scan",             scan_udp),
    (17, "BruteForce",   "SSH",                  brute_ssh),
    (18, "BruteForce",   "FTP",                  brute_ftp),
    (19, "BruteForce",   "RDP",                  brute_rdp),
    (20, "BruteForce",   "MySQL",                brute_mysql),
    (21, "BruteForce",   "Telnet",               brute_telnet),
    (22, "WebAttack",    "SQL Injection",         web_sql_injection),
    (23, "WebAttack",    "XSS",                  web_xss),
    (24, "WebAttack",    "Path Traversal",        web_path_traversal),
    (25, "WebAttack",    "Command Injection",     web_cmd_injection),
    (26, "WebAttack",    "CSRF",                 web_csrf),
    (27, "Infiltration", "Reverse Shell",         infil_reverse_shell),
    (28, "Infiltration", "Data Exfiltration",     infil_data_exfil),
    (29, "Infiltration", "Covert Channel",        infil_covert_channel),
    (30, "Infiltration", "Lateral Movement",      infil_lateral_move),
    (31, "Bot",          "C&C Communication",     bot_cnc),
    (32, "Bot",          "Heartbeat",             bot_heartbeat),
    (33, "Bot",          "DNS Tunnel",            bot_dns_tunnel),
    (34, "Bot",          "IRC",                   bot_irc),
    (35, "Bot",          "Beacon",                bot_beacon),
]


def main():
    parser = argparse.ArgumentParser(description="快速攻击演示(35种) - 御链天鉴")
    parser.add_argument("--target", "-t", default=TARGET_IP, help=f"目标IP (默认: {TARGET_IP})")
    args = parser.parse_args()
    target = args.target

    print(f"{'='*60}")
    print(f"  快速攻击演示 — 7类35种攻击 — 御链天鉴")
    print(f"  目标: {target}")
    print(f"  全部使用Scapy原始包（同机NIDS可检测）")
    print(f"{'='*60}")

    t0 = time.time()
    current_cat = ""
    for idx, cat, name, func in ATTACKS:
        if cat != current_cat:
            current_cat = cat
            # 按攻击大类切换源IP，模拟不同攻击者
            cat_ips = _CATEGORY_IP.get(cat, ATTACKER_IPS)
            _current_src[0] = random.choice(cat_ips)
            print(f"\n{'─'*60}")
            print(f"  ■ {cat}  (攻击源: {_current_src[0]})")
            print(f"{'─'*60}")
        print(f"  [{idx:2d}/35] {cat}/{name} ... ", end="", flush=True)
        try:
            func(target)
            print("✓")
        except Exception as e:
            print(f"✗ ({e})")
        time.sleep(0.5)

    elapsed = time.time() - t0
    print(f"\n{'='*60}")
    print(f"  全部 35 种攻击完成! 耗时: {elapsed:.1f}s")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
