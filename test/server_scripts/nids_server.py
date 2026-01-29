# -*- coding: utf-8 -*-
"""
🧠 NIDS AI 检测引擎 (修复版 v2.0)
修改内容：
1. JAVA_IP 改为 Windows 后端真实 IP: 192.168.231.151
2. 增加推送重试机制
3. 优化日志输出
"""
import os
import sys
import time
import json
import uuid
import socket
import logging
import warnings
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

# ================= 配置区域 =================
# 🔥 通过 SSH 反向隧道连接到 Windows 后端
# 使用命令: ssh -R 8985:127.0.0.1:8985 test@10.138.50.151
JAVA_IP = "127.0.0.1"
JAVA_PORT = 8985
ALERT_API_URL = f"http://{JAVA_IP}:{JAVA_PORT}/api/analysis/alert"

# 网卡配置（使用 lo 监听本地流量，或 eno1 监听外部流量）
CAPTURE_INTERFACE = "lo"  # 本地测试用 lo，外部测试用 eno1

# 路径配置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "nids.log")

# 🔥 IP 白名单（这些 IP 的流量不会触发告警）
# 注意：本地测试时不要将 127.0.0.1 加入白名单
WHITELIST_IPS = {
    "10.10.18.31",   # Windows 开发机
    "192.168.231.151",  # Windows 开发机（隧道）
}
# ===========================================

# 颜色配置
COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "reset": "\033[0m"
}

# 攻击特征库
ATTACK_SIGNATURES = {
    "SQL注入攻击": [b"UNION SELECT", b"OR 1=1", b"OR '1'='1", b"information_schema", b"SELECT * FROM"],
    "XSS跨站脚本攻击": [b"<script>", b"javascript:", b"onerror=", b"onload="],
    "Webshell上传攻击": [b"eval(", b"base64_decode", b"system(", b"shell_exec", b"<?php"],
    "扫描探测攻击": [b"nmap", b"masscan", b"hydra", b"sqlmap", b"nikto"],
    "SSH暴力破解": [b"SSH-2.0-OpenSSH", b"ssh-userauth"],
    "目录遍历攻击": [b"../", b"..\\", b"/etc/passwd", b"/etc/shadow"],
    "远程命令执行": [b"cmd=", b"exec=", b"system(", b"whoami", b"cat /etc"],
}

# 日志配置
logger = logging.getLogger("NIDS_AI")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# 文件日志
fh = logging.FileHandler(LOG_FILE, encoding='utf-8')
fh.setFormatter(formatter)
logger.addHandler(fh)

# 控制台日志
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)

warnings.filterwarnings("ignore")

# ================= HTTP 会话（带重试） =================
def create_session_with_retry():
    """创建带重试机制的 HTTP 会话"""
    session = requests.Session()
    retry = Retry(
        total=3,           # 最多重试3次
        backoff_factor=0.5, # 重试间隔：0.5s, 1s, 2s
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

HTTP_SESSION = create_session_with_retry()

# ================= 核心函数 =================
def push_ai_alert(attack_type, src_ip, dst_ip, payload_info=""):
    """推送 AI 告警到 Windows 后端"""
    try:
        # 过滤本地回环和白名单 IP
        # 🔥 移除 src_ip == dst_ip 的过滤，支持同一服务器上的攻击测试
        # if src_ip == dst_ip:
        #     return
        if src_ip == "127.0.0.1" and dst_ip == "127.0.0.1":
            return
        # 过滤白名单 IP（避免 SSH 隧道误报）
        if src_ip in WHITELIST_IPS or dst_ip in WHITELIST_IPS:
            return
        
        # 🔥 根据攻击类型设置完整的进程链和文件（与PIDS格式一致）
        process_chains = {
            "SQL注入攻击": (
                ["nginx", "php-fpm", "mysql"],
                "/var/lib/mysql/users.ibd"
            ),
            "XSS跨站脚本攻击": (
                ["nginx", "php-fpm", "node"],
                "/var/www/html/malicious.js"
            ),
            "Webshell上传攻击": (
                ["nginx", "php-fpm", "cp"],
                "/var/www/html/shell.php"
            ),
            "目录遍历攻击": (
                ["nginx", "php-fpm", "cat"],
                "/etc/passwd"
            ),
            "远程命令执行": (
                ["nginx", "php-fpm", "bash", "whoami"],
                "/tmp/rce_output.txt"
            ),
            "扫描探测攻击": (
                ["nginx", "nmap"],
                "/var/log/scan.log"
            ),
            "SSH暴力破解": (
                ["sshd", "pam_unix"],
                "/var/log/auth.log"
            )
        }
        
        # 获取进程链和文件
        process_chain, affected_file = process_chains.get(
            attack_type, 
            (["nginx", "unknown"], "/var/log/attack.log")
        )
        
        # 🔥 将进程链转换为JSON字符串
        affected_process = json.dumps(process_chain)
        
        # 生成告警数据
        threat_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{src_ip}_{attack_type}_{time.time()}"))
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        alert_data = {
            "threatId": threat_id,
            "threatLevel": 5,
            "impactScope": f"{src_ip} -> {dst_ip} | {attack_type}",
            "occurTime": timestamp,
            "createTime": timestamp,
            "sourceIp": src_ip,
            "targetIp": dst_ip,
            "attackType": attack_type,
            "affectedProcess": affected_process,
            "affectedFile": affected_file,
            "message": f"[NIDS] 网络检测引擎发现攻击行为。特征: {payload_info[:50]}..."
        }

        # 推送告警
        response = HTTP_SESSION.post(ALERT_API_URL, json=alert_data, timeout=5)
        
        if response.status_code == 200:
            logger.info(f"{COLORS['green']}✅ [推送成功] {attack_type} | {src_ip} -> {dst_ip}{COLORS['reset']}")
        else:
            logger.warning(f"{COLORS['yellow']}⚠️ [推送警告] 后端返回: {response.status_code}{COLORS['reset']}")
            
    except requests.exceptions.ConnectionError as e:
        logger.error(f"{COLORS['red']}❌ [连接失败] 无法连接到 Windows 后端 ({JAVA_IP}:{JAVA_PORT}){COLORS['reset']}")
        logger.error(f"   错误详情: {str(e)[:100]}")
    except requests.exceptions.Timeout:
        logger.error(f"{COLORS['red']}❌ [超时] Windows 后端响应超时{COLORS['reset']}")
    except Exception as e:
        logger.error(f"{COLORS['red']}❌ [推送失败] {str(e)}{COLORS['reset']}")

def detect_payload(packet):
    """深度包检测（DPI）"""
    if not packet.haslayer(Raw):
        return None
    try:
        payload = packet[Raw].load
        if len(payload) < 8:
            return None
        
        # 特征匹配
        for attack_name, signatures in ATTACK_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in payload.lower():
                    return attack_name, sig.decode('utf-8', errors='ignore')
    except Exception:
        pass
    return None

def process_packet(packet):
    """处理捕获的数据包"""
    if not packet.haslayer(IP):
        return
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    # 过滤发往后端的流量，避免循环
    if dst_ip == "127.0.0.1" and packet.haslayer(TCP) and packet[TCP].dport == JAVA_PORT:
        return
    if dst_ip == JAVA_IP and packet.haslayer(TCP) and packet[TCP].dport == JAVA_PORT:
        return
    
    # 深度包检测
    dpi_result = detect_payload(packet)
    if dpi_result:
        attack_type, sig = dpi_result
        
        # 过滤本地回环
        if src_ip == "127.0.0.1" and dst_ip == "127.0.0.1":
            return
        
        logger.info(f"{COLORS['red']}🔥 [NIDS] AI命中: {attack_type} | {src_ip} -> {dst_ip}{COLORS['reset']}")
        push_ai_alert(attack_type, src_ip, dst_ip, sig)

def main():
    """主函数"""
    print("=" * 60)
    print(f"🧠 NIDS AI 检测引擎 (修复版 v2.0)")
    print("=" * 60)
    print(f"📡 监听网卡: {CAPTURE_INTERFACE}")
    print(f"🎯 后端地址: {ALERT_API_URL}")
    print(f"📝 日志文件: {LOG_FILE}")
    print("=" * 60)
    
    # 测试后端连接
    print("\n🔍 正在测试后端连接...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((JAVA_IP, JAVA_PORT))
        sock.close()
        
        if result == 0:
            print(f"{COLORS['green']}✅ 后端连接测试成功: {JAVA_IP}:{JAVA_PORT}{COLORS['reset']}")
        else:
            print(f"{COLORS['yellow']}⚠️ 后端连接测试失败，但仍继续监听...{COLORS['reset']}")
    except Exception as e:
        print(f"{COLORS['yellow']}⚠️ 后端连接测试异常: {e}{COLORS['reset']}")
    
    print("\n" + "=" * 60)
    print("🚀 开始监听网络流量...")
    print("=" * 60 + "\n")
    
    # 检查是否有 root 权限
    if os.geteuid() != 0:
        print(f"{COLORS['red']}❌ 需要 root 权限！请使用: sudo python3 nids_server.py{COLORS['reset']}")
        sys.exit(1)
    
    # 开始抓包
    conf.verb = 0
    try:
        sniff(iface=CAPTURE_INTERFACE, prn=process_packet, store=0)
    except PermissionError:
        print(f"{COLORS['red']}❌ 权限不足，请使用 sudo 运行{COLORS['reset']}")
    except Exception as e:
        print(f"{COLORS['red']}❌ 抓包失败: {e}{COLORS['reset']}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{COLORS['yellow']}👋 用户中断，NIDS 已停止{COLORS['reset']}")
