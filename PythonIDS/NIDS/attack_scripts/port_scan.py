#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端口扫描攻击脚本（5种扫描方式）
================================

包含：SYN扫描、FIN扫描、NULL扫描、XMAS扫描、UDP扫描

用法：
  python port_scan.py --target <IP> --scan <syn|fin|null|xmas|udp|all> [--ports 1-1024]

⚠️ 仅用于授权测试环境，禁止用于未授权目标！

御链天鉴开发团队
"""

import argparse
import random
import time
import sys
from config import TARGET_IP, SCAN_PORTS
from scapy.all import IP, TCP, UDP, ICMP, sr1, sr, send, conf, RandShort

conf.verb = 0


def parse_ports(port_str):
    """解析端口范围字符串，如 '1-1024' 或 '22,80,443'"""
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


# ========== 1. SYN 半开扫描 ==========
def syn_scan(target, ports, delay=0.01):
    """
    SYN扫描（半开扫描）：快速发送SYN包，不等待响应
    特征：大量SYN包，无完整三次握手
    """
    print(f"[SYN扫描] 目标={target}, 端口数={len(ports)}")
    fixed_sport = random.randint(40000, 50000)
    for port in ports:
        for _ in range(3):
            pkt = IP(dst=target) / TCP(sport=fixed_sport, dport=port, flags="S")
            send(pkt, verbose=0)
            time.sleep(delay)
    print(f"[SYN扫描] 完成，已发送 {len(ports)*3} 个SYN探测包")


# ========== 2. FIN 扫描 ==========
def fin_scan(target, ports, delay=0.01):
    """
    FIN扫描：快速发送FIN包
    特征：FIN标志位，绕过简单防火墙
    """
    print(f"[FIN扫描] 目标={target}, 端口数={len(ports)}")
    for port in ports:
        pkt = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="F")
        send(pkt, verbose=0)
        time.sleep(delay)
    print(f"[FIN扫描] 完成，已发送 {len(ports)} 个FIN探测包")


# ========== 3. NULL 扫描 ==========
def null_scan(target, ports, delay=0.01):
    """
    NULL扫描：快速发送无标志位的TCP包
    特征：flags=0，异常TCP行为
    """
    print(f"[NULL扫描] 目标={target}, 端口数={len(ports)}")
    for port in ports:
        pkt = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="")
        send(pkt, verbose=0)
        time.sleep(delay)
    print(f"[NULL扫描] 完成，已发送 {len(ports)} 个NULL探测包")


# ========== 4. XMAS 扫描 ==========
def xmas_scan(target, ports, delay=0.01):
    """
    XMAS扫描：快速发送FIN+PSH+URG标志包（"圣诞树"）
    特征：FPU标志组合，高度异常
    """
    print(f"[XMAS扫描] 目标={target}, 端口数={len(ports)}")
    for port in ports:
        pkt = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="FPU")
        send(pkt, verbose=0)
        time.sleep(delay)
    print(f"[XMAS扫描] 完成，已发送 {len(ports)} 个XMAS探测包")


# ========== 5. UDP 扫描 ==========
def udp_scan(target, ports, delay=0.01):
    """
    UDP扫描：快速发送空UDP包
    特征：UDP探测包
    """
    print(f"[UDP扫描] 目标={target}, 端口数={len(ports)}")
    for port in ports:
        pkt = IP(dst=target) / UDP(sport=RandShort(), dport=port)
        send(pkt, verbose=0)
        time.sleep(delay)
    print(f"[UDP扫描] 完成，已发送 {len(ports)} 个UDP探测包")


# ========== 主入口 ==========
SCAN_MAP = {
    "syn": ("SYN半开扫描", syn_scan),
    "fin": ("FIN扫描", fin_scan),
    "null": ("NULL扫描", null_scan),
    "xmas": ("XMAS圣诞树扫描", xmas_scan),
    "udp": ("UDP扫描", udp_scan),
}

def main():
    parser = argparse.ArgumentParser(description="端口扫描攻击工具 - 御链天鉴")
    parser.add_argument("--target", "-t", default=TARGET_IP, help=f"目标IP地址 (默认: {TARGET_IP})")
    parser.add_argument("--scan", "-s", default="syn", choices=list(SCAN_MAP.keys()) + ["all"],
                        help="扫描类型 (默认: syn)")
    parser.add_argument("--ports", "-p", default=SCAN_PORTS, help=f"端口范围 (默认: {SCAN_PORTS})")
    parser.add_argument("--delay", "-d", type=float, default=0.05, help="包间延迟(秒)")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    print(f"{'='*60}")
    print(f"端口扫描攻击工具 - 御链天鉴")
    print(f"目标: {args.target}")
    print(f"端口: {args.ports} ({len(ports)}个)")
    print(f"{'='*60}")

    if args.scan == "all":
        for key, (name, func) in SCAN_MAP.items():
            print(f"\n--- {name} ---")
            func(args.target, ports, delay=args.delay)
            time.sleep(1)
    else:
        name, func = SCAN_MAP[args.scan]
        print(f"\n--- {name} ---")
        func(args.target, ports, delay=args.delay)

    print(f"\n{'='*60}")
    print("扫描完成")


if __name__ == "__main__":
    main()
