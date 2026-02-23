#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
攻击测试主启动器
================

统一管理和执行所有攻击测试脚本，支持单项测试、分类测试和全量测试。

用法：
  python attack_launcher.py --target <IP> --category <all|portscan|dos|ddos|bruteforce|web|infiltration|bot>
  python attack_launcher.py --target <IP> --list                    # 列出所有攻击
  python attack_launcher.py --target <IP> --category dos --attack syn_flood  # 指定单个攻击

⚠️ 仅用于授权测试环境，禁止用于未授权目标！

御链天鉴开发团队
"""

import argparse
import importlib
import sys
import os
import time

# 将当前目录加入路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import TARGET_IP, ATTACK_DURATION

# ========== 攻击分类注册表 ==========
CATEGORIES = {
    "portscan": {
        "name": "端口扫描 (PortScan)",
        "module": "port_scan",
        "attacks": {
            "syn": "SYN半开扫描",
            "fin": "FIN扫描",
            "null": "NULL扫描",
            "xmas": "XMAS圣诞树扫描",
            "udp": "UDP扫描",
        },
        "default_port": None,
        "training_samples": 3968,
    },
    "dos": {
        "name": "拒绝服务 (DoS)",
        "module": "dos_attack",
        "attacks": {
            "syn_flood": "SYN Flood洪水攻击",
            "udp_flood": "UDP Flood洪水攻击",
            "icmp_flood": "ICMP Flood洪水攻击",
            "slowloris": "Slowloris慢速攻击",
            "rudy": "R.U.D.Y.慢速POST攻击",
            "tcp_rst": "TCP RST攻击",
        },
        "default_port": 80,
        "training_samples": 8477,
    },
    "ddos": {
        "name": "分布式拒绝服务 (DDoS)",
        "module": "ddos_attack",
        "attacks": {
            "http_flood": "HTTP Flood洪水攻击",
            "dns_amp": "DNS放大攻击",
            "ntp_amp": "NTP放大攻击",
            "tcp_exhaust": "TCP连接耗尽攻击",
            "smurf": "Smurf广播攻击",
        },
        "default_port": 80,
        "training_samples": 5601,
    },
    "bruteforce": {
        "name": "暴力破解 (BruteForce)",
        "module": "brute_force",
        "attacks": {
            "ssh": "SSH暴力破解",
            "ftp": "FTP暴力破解",
            "http": "HTTP登录爆破",
            "rdp": "RDP暴力破解",
            "smtp": "SMTP暴力破解",
        },
        "default_port": None,
        "training_samples": 401,
    },
    "web": {
        "name": "Web攻击 (WebAttack)",
        "module": "web_attack",
        "attacks": {
            "sqli": "SQL注入攻击",
            "xss": "XSS跨站脚本攻击",
            "traversal": "目录遍历攻击",
            "cmdi": "命令注入攻击",
            "webshell": "WebShell上传攻击",
        },
        "default_port": 80,
        "training_samples": 0,
    },
    "infiltration": {
        "name": "渗透攻击 (Infiltration)",
        "module": "infiltration",
        "attacks": {
            "port_fwd": "端口转发攻击",
            "tunnel": "隧道通信攻击",
            "backdoor": "后门通信攻击",
            "exfil": "数据外泄攻击",
        },
        "default_port": 443,
        "training_samples": 2,
    },
    "bot": {
        "name": "僵尸网络 (Bot)",
        "module": "bot_attack",
        "attacks": {
            "cnc": "C&C通信攻击",
            "heartbeat": "心跳包攻击",
            "dns_tunnel": "DNS隧道攻击",
            "irc": "IRC Bot通信",
            "beacon": "Beacon周期回连",
        },
        "default_port": 8443,
        "training_samples": 86,
    },
}


def list_attacks():
    """列出所有可用攻击"""
    total = 0
    print(f"\n{'='*70}")
    print(f"  御链天鉴 NIDS 攻击测试套件 - 攻击列表")
    print(f"{'='*70}")
    for cat_key, cat in CATEGORIES.items():
        n = len(cat["attacks"])
        total += n
        reliability = "✅ 可检测" if cat["training_samples"] >= 50 else "⚠️ 训练样本不足"
        print(f"\n  [{cat_key}] {cat['name']} ({n}种) | 训练样本={cat['training_samples']:,} | {reliability}")
        for atk_key, atk_name in cat["attacks"].items():
            print(f"    - {atk_key:15s} {atk_name}")
    print(f"\n{'='*70}")
    print(f"  总计: 7个类别, {total}种攻击")
    print(f"{'='*70}\n")


def run_category(cat_key, target, port, duration, attack_name=None):
    """运行指定类别的攻击"""
    cat = CATEGORIES[cat_key]
    try:
        mod = importlib.import_module(cat["module"])
    except ImportError as e:
        print(f"❌ 加载模块 {cat['module']} 失败: {e}")
        return

    attack_map = getattr(mod, "ATTACK_MAP", None) or getattr(mod, "SCAN_MAP", None)
    if attack_map is None:
        print(f"❌ 模块 {cat['module']} 中未找到 ATTACK_MAP/SCAN_MAP")
        return

    if attack_name:
        if attack_name not in attack_map:
            print(f"❌ 攻击 '{attack_name}' 不存在于 {cat_key} 类别中")
            print(f"   可用: {', '.join(attack_map.keys())}")
            return
        name, func = attack_map[attack_name]
        print(f"\n{'='*60}")
        print(f"  执行: {name}")
        print(f"  类别: {cat['name']}")
        print(f"  目标: {target}")
        print(f"{'='*60}")
        _run_attack(func, attack_name, target, port or cat.get("default_port", 80), duration)
    else:
        print(f"\n{'='*60}")
        print(f"  执行类别: {cat['name']} ({len(attack_map)}种攻击)")
        print(f"  目标: {target}")
        print(f"{'='*60}")
        for atk_key, (name, func) in attack_map.items():
            print(f"\n--- [{atk_key}] {name} ---")
            _run_attack(func, atk_key, target, port or cat.get("default_port", 80), min(duration, 20))
            time.sleep(3)


def _run_attack(func, attack_key, target, port, duration):
    """执行单个攻击函数"""
    try:
        import inspect
        sig = inspect.signature(func)
        params = sig.parameters

        kwargs = {}
        if "target" in params:
            kwargs["target"] = target
        if "port" in params and port:
            kwargs["port"] = port
        if "duration" in params:
            kwargs["duration"] = duration
        if "ports" in params:
            kwargs["ports"] = list(range(1, 101))

        func(**kwargs)
    except Exception as e:
        print(f"  ⚠️ 攻击执行异常: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="御链天鉴 NIDS 攻击测试主启动器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python attack_launcher.py --list                                    # 列出所有攻击
  python attack_launcher.py -t 192.168.1.100 -c portscan              # 执行所有端口扫描
  python attack_launcher.py -t 192.168.1.100 -c dos -a syn_flood      # 执行SYN Flood
  python attack_launcher.py -t 192.168.1.100 -c all -d 15             # 全量测试(每种15秒)
        """
    )
    parser.add_argument("--target", "-t", default=TARGET_IP, help=f"目标IP地址 (默认: {TARGET_IP})")
    parser.add_argument("--category", "-c", default="all",
                        choices=list(CATEGORIES.keys()) + ["all"], help="攻击类别")
    parser.add_argument("--attack", "-a", default=None, help="指定单个攻击名称")
    parser.add_argument("--port", "-p", type=int, default=None, help="目标端口")
    parser.add_argument("--duration", "-d", type=int, default=30, help="每种攻击持续时间(秒)")
    parser.add_argument("--list", "-l", action="store_true", help="列出所有可用攻击")
    args = parser.parse_args()

    if args.list:
        list_attacks()
        return

    if not args.target:
        parser.error(f"必须指定目标IP: --target <IP> (当前默认: {TARGET_IP})")

    print(f"\n{'='*60}")
    print(f"  御链天鉴 NIDS 攻击测试套件")
    print(f"  目标: {args.target}")
    print(f"  类别: {args.category}")
    print(f"  持续: {args.duration}s/攻击")
    print(f"{'='*60}")

    start_time = time.time()

    if args.category == "all":
        for cat_key in CATEGORIES:
            run_category(cat_key, args.target, args.port, args.duration)
            time.sleep(5)
    else:
        run_category(args.category, args.target, args.port, args.duration, args.attack)

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"  测试完成! 总耗时: {elapsed:.1f}s")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
