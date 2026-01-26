import os
import random
import threading
import time
import json
import socket
from datetime import datetime, timedelta, timezone

import numpy as np
import requests
import torch
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Raw
from scapy.config import conf
from scapy.all import sniff
from ids_common import (
    logger, COLORS, flows, DEVICE, LOG_FILE, ANOMALY_THRESHOLD,
    get_wlan_interface, load_model, extract_features, clean_timeout_flows,
    get_flow_key, SEQ_LEN, PCA_DIM
)

# ========== 运行配置 ==========
CAPTURE_MINUTES = 2147483646 #手动永续 
SHOW_ALL_PACKETS = False  # 只显示异常包
SHOW_COLOR = True
ENABLE_ANOMALY_SIMULATION = False

import sys
def get_config_base_dir():
    """获取配置文件的基准目录，兼容脚本运行和PyInstaller打包"""
    if getattr(sys, 'frozen', False):
        # 如果是打包后的exe运行，配置文件应位于exe同级目录
        return os.path.dirname(sys.executable)
    else:
        # 如果是脚本运行，配置文件位于项目根目录 (../../)
        return os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

# 信任的IP列表文件
TRUSTED_IPS_FILE = os.path.join(get_config_base_dir(), "trusted_ips.json")
# 已封禁的IP列表文件
BLOCKED_IPS_FILE = os.path.join(get_config_base_dir(), "blocked_ips.json")

trusted_ips = set()
blocked_ips = set()
last_trusted_ip_reload = 0
last_blocked_ip_reload = 0

def reload_blocked_ips():
    """定期重新加载已封禁的IP列表"""
    global blocked_ips, last_blocked_ip_reload
    try:
        if time.time() - last_blocked_ip_reload < 3:
            return
        
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
                ips = json.load(f)
                blocked_ips = set(ips)
        else:
            blocked_ips = set()
            
        last_blocked_ip_reload = time.time()
    except Exception as e:
        pass

def reload_trusted_ips():
    """定期重新加载信任的IP列表"""
    global trusted_ips, last_trusted_ip_reload
    try:
        if time.time() - last_trusted_ip_reload < 3:
            return
        
        # 1. Load from file
        file_trusted_ips = set()
        if os.path.exists(TRUSTED_IPS_FILE):
            with open(TRUSTED_IPS_FILE, "r", encoding="utf-8") as f:
                ips = json.load(f)
                file_trusted_ips = set(ips)
        
        # 2. Auto-detect Local IPs
        local_ips = set()
        local_ips.add("127.0.0.1")
        local_ips.add("::1")
        try:
            # Method 1: Hostname resolution
            hostname = socket.gethostname()
            for ip in socket.gethostbyname_ex(hostname)[2]:
                local_ips.add(ip)
        except:
            pass
        try:
            # Method 2: Connect probe
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ips.add(s.getsockname()[0])
            s.close()
        except:
            pass
            
        # Merge
        trusted_ips = file_trusted_ips.union(local_ips)
            
        last_trusted_ip_reload = time.time()
    except Exception as e:
        pass

# 判定灵敏度（可通过环境变量调整）
# 【调整】提高置信度阈值，减少误报
MIN_ATTACK_CONFIDENCE = float(os.environ.get("MIN_ATTACK_CONFIDENCE", "0.6"))
# 【调整】降低OOD检测敏感度，只有非常异常的流量才判定为未知攻击
REAL_SCORE_THRESHOLD = float(os.environ.get("REAL_SCORE_THRESHOLD", "-0.45"))

# 端口特征：哪些组合被视为“已知”攻击（其余高危流量可落入未知）
KNOWN_ATTACK_SOURCE_PORTS = {
    50000, 50001, 50002, 50010, 50011, 50012, 50013, 50014,
    58000,  # 端口扫描
    59000,  # Web攻击
    60000,  # 暴力破解
    61000,  # 渗透攻击
    62000   # 僵尸网络
}
KNOWN_TCP_TARGET_PORTS = {
    21, 22, 23, 25, 53, 80, 81, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443
}
KNOWN_UDP_TARGET_PORTS = {53, 80, 81, 8080}

# 告警网关配置
ALERT_API_URL = os.environ.get("ALERT_API_URL", "http://localhost:8985/api/analysis/alert")
ALERT_API_TIMEOUT = float(os.environ.get("ALERT_API_TIMEOUT", "2.5"))

# 确保URL格式正确
if ALERT_API_URL and not ALERT_API_URL.startswith("http"):
    ALERT_API_URL = f"http://{ALERT_API_URL}"
# 修正：Backnode 的接口是 /api/analysis/alert，不需要自动添加 /alerts
# if ALERT_API_URL and not ALERT_API_URL.endswith("/alerts"):
#     if ALERT_API_URL.endswith("/"):
#         ALERT_API_URL = ALERT_API_URL + "alerts"
#     else:
#         ALERT_API_URL = ALERT_API_URL + "/alerts"

# 全局变量
total_packets_captured = 0
total_valid_packets = 0
alert_push_success = 0  # 告警推送成功数
alert_push_failed = 0   # 告警推送失败数
alert_detected_count = 0  # 检测到的异常总数（包括未推送的）
short_sequence_skipped = 0
feature_extract_skipped = 0
stop_capture = False
model, generator, scaler, pca, labels = None, None, None, None, []
target_iface = None
start_timestamp = 0
normal_label = "Benign"


def is_private_ip(ip_str):
    """
    判断IP地址是否为私有IP（本地网络）
    私有IP范围：
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 127.0.0.0/8 (localhost)
    """
    try:
        from ipaddress import ip_address, IPv4Address
        ip = ip_address(ip_str)
        if not isinstance(ip, IPv4Address):
            return False
        
        # 检查是否为私有IP
        if ip.is_private or ip.is_loopback:
            return True
        
        # 手动检查（以防ipaddress库版本问题）
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        
        first = int(parts[0])
        second = int(parts[1])
        
        # 10.0.0.0/8
        if first == 10:
            return True
        # 172.16.0.0/12
        if first == 172 and 16 <= second <= 31:
            return True
        # 192.168.0.0/16
        if first == 192 and second == 168:
            return True
        # 127.0.0.0/8 (localhost)
        if first == 127:
            return True
        
        return False
    except:
        return False


def _flow_to_payload(flow_key, flow_stats=None):
    """
    将flow_key转换为告警payload
    如果提供了flow_stats，使用flow_stats中的真实IP（保持原始方向）
    否则使用flow_key（可能方向不对，因为flow_key是标准化的）
    """
    if flow_stats:
        # 使用FlowStats中的真实源IP和目标IP（保持原始包的方向）
        src_ip, dst_ip = flow_stats.src_ip, flow_stats.dst_ip
        src_port, dst_port = flow_stats.src_port, flow_stats.dst_port
        proto = flow_stats.proto
    else:
        # 如果没有flow_stats，使用flow_key（虽然可能方向不对）
        src_ip, dst_ip, src_port, dst_port, proto = flow_key
    
    proto_name = {6: "TCP", 17: "UDP"}.get(proto, str(proto))
    return {
        "session": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto_name
    }


def handle_non_ip_packet(packet, packet_summary):
    """处理非IP包（IPv6、ARP等），过滤正常协议，只推送真正的异常流量"""
    try:
        # 提取基本信息
        src_ip = ""
        dst_ip = ""
        src_port = 0
        dst_port = 0
        protocol = "Unknown"
        packet_size = len(packet)
        
        # 检查是否为ARP流量（正常协议，不推送告警）
        if packet.haslayer(ARP):
            arp = packet[ARP]
            src_ip = str(arp.psrc) if hasattr(arp, "psrc") else ""
            dst_ip = str(arp.pdst) if hasattr(arp, "pdst") else ""
            protocol = "ARP"
            # ARP是正常的二层协议，只记录日志，不推送告警
            logger.debug(f"{COLORS['green']}[ARP] {src_ip} → {dst_ip} | {packet_summary[:50]}{COLORS['reset']}")
            return
        
        # 尝试提取IPv6信息
        if packet.haslayer(IPv6):
            ipv6 = packet[IPv6]
            src_ip = str(ipv6.src)
            dst_ip = str(ipv6.dst)
            protocol = "IPv6"
            
            # 检查IPv6上层协议
            if packet.haslayer(UDP):
                udp = packet[UDP]
                src_port = int(udp.sport) if hasattr(udp, "sport") and udp.sport else 0
                dst_port = int(udp.dport) if hasattr(udp, "dport") and udp.dport else 0
                protocol = f"IPv6/UDP"
                
                # 检查是否为mDNS（5353端口）或LLMNR（5355端口）- 正常服务发现协议
                if dst_port == 5353 or src_port == 5353:
                    logger.debug(f"{COLORS['green']}[IPv6 mDNS] {src_ip}:{src_port} → {dst_ip}:{dst_port}{COLORS['reset']}")
                    return
                if dst_port == 5355 or src_port == 5355:
                    logger.debug(f"{COLORS['green']}[IPv6 LLMNR] {src_ip}:{src_port} → {dst_ip}:{dst_port}{COLORS['reset']}")
                    return
            elif packet.haslayer(TCP):
                tcp = packet[TCP]
                src_port = int(tcp.sport) if hasattr(tcp, "sport") and tcp.sport else 0
                dst_port = int(tcp.dport) if hasattr(tcp, "dport") and tcp.dport else 0
                protocol = f"IPv6/TCP"
                
                # 【关键修复】IPv6 TCP流量（如HTTPS）是正常流量，不推送告警
                # 常见正常端口：80(HTTP), 443(HTTPS), 22(SSH), 53(DNS), 25(SMTP), 110(POP3), 143(IMAP), 993(IMAPS), 995(POP3S)
                common_normal_ports = {80, 443, 22, 23, 25, 53, 110, 143, 993, 995, 587, 465, 8080, 8443}
                if dst_port in common_normal_ports or src_port in common_normal_ports:
                    logger.debug(f"{COLORS['green']}[IPv6 正常流量] {src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol}){COLORS['reset']}")
                    return
            else:
                # ICMPv6 - 检查是否为Neighbor Discovery（正常协议）
                protocol = "IPv6/ICMPv6"
                # IPv6 Neighbor Discovery是正常的网络协议，不推送告警
                if "ICMPv6ND" in packet_summary or "ND" in packet_summary or "Neighbor Discovery" in packet_summary:
                    logger.debug(f"{COLORS['green']}[IPv6 ND] {src_ip} → {dst_ip} | {packet_summary[:50]}{COLORS['reset']}")
                    return
        else:
            # 其他非IP包
            protocol = "Non-IP"
            # 其他非IP包可能是异常，但先不推送，只记录日志
            logger.debug(f"{COLORS['yellow']}[非IP包] {packet_summary[:50]}{COLORS['reset']}")
            return
        
        # 【关键修复】如果执行到这里，说明是IPv6的TCP/UDP流量，但不在常见正常端口列表中
        # 这些流量可能是异常，但为了减少误报，暂时只记录日志，不推送告警
        # 如果需要监控所有IPv6流量，可以取消下面的注释
        logger.debug(f"{COLORS['yellow']}[IPv6 非标准端口流量] {src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol}) | {packet_summary[:50]}{COLORS['reset']}")
        return  # 不推送告警，只记录日志
        
        # 如果需要推送IPv6异常流量告警，取消下面的注释
        # attack_type = "IPv6 Traffic"
        # payload = {
        #     "engine": "anomaly_based_ids",
        #     "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        #     "attack_type": attack_type,
        #     "severity": 2,  # 中等严重程度（IPv6流量可能是正常的，但也可能是异常）
        #     "confidence": 0.7,  # 中等置信度
        #     "message": f"检测到非IPv4流量: {packet_summary[:100]}",
        #     "session": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}" if src_ip or dst_ip else packet_summary[:50],
        #     "src_ip": src_ip,
        #     "dst_ip": dst_ip,
        #     "src_port": src_port,
        #     "dst_port": dst_port,
        #     "protocol": protocol
        # }
        # if send_alert_payload(payload):
        #     logger.info(f"{COLORS['yellow']}⚠️  非IP包告警已推送: {attack_type} - {protocol}{COLORS['reset']}")
        
    except Exception as e:
        logger.debug(f"处理非IP包失败: {str(e)}")


def send_alert_payload(payload):
    global alert_push_success, alert_push_failed
    if not ALERT_API_URL:
        logger.warning(f"{COLORS['yellow']}⚠️ 告警网关URL未配置，跳过推送{COLORS['reset']}")
        alert_push_failed += 1
        return False
    
    # 【适配 Backnode】构造符合 potentialThreatAlert 实体的 Payload
    # Backnode 实体字段: threatId, threatLevel, impactScope, occurTime, createTime
    try:
        import uuid
        
        # 确保 session 和 attack_type 存在且为字符串
        session_val = str(payload.get('session', 'Unknown Session'))
        attack_type_val = str(payload.get('attack_type', 'Unknown Type'))
        
        backnode_payload = {
            "threatId": str(uuid.uuid4()),
            "threatLevel": int(payload.get("severity", 3)),
            # 将 session 和 attack_type 拼接到 impactScope，避免信息丢失
            "impactScope": f"{session_val} | {attack_type_val}", 
            "occurTime": payload.get("timestamp"),
            "createTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        # 记录调试日志
        logger.debug(f"Payload adapted for Backnode: {backnode_payload}")
        json_to_send = backnode_payload
    except Exception as e:
        logger.error(f"Payload adaptation failed: {e}")
        # Fallback but try to ensure impactScope exists
        json_to_send = payload.copy()
        if "impactScope" not in json_to_send:
             session_val = str(payload.get('session', 'Unknown Session'))
             attack_type_val = str(payload.get('attack_type', 'Unknown Type'))
             json_to_send["impactScope"] = f"{session_val} | {attack_type_val}"


    # 直接推送告警，不进行健康检查（简化流程）
    try:
        logger.debug(f"📤 正在推送告警到 {ALERT_API_URL}...")
        response = requests.post(
            ALERT_API_URL,
            json=json_to_send,
            timeout=ALERT_API_TIMEOUT,
            headers={"Content-Type": "application/json"},
            proxies={"http": None, "https": None}  # 禁用代理，直接连接本地网关
        )
        response.raise_for_status()
        logger.info(f"{COLORS['green']}✅ 告警已推送到网关: {payload.get('attack_type', 'N/A')} (ID: {response.json().get('alert_id', 'N/A')}){COLORS['reset']}")
        alert_push_success += 1
        return True
    except requests.exceptions.ConnectionError as e:
        logger.warning(f"{COLORS['yellow']}⚠️ 无法连接到告警网关 {ALERT_API_URL}{COLORS['reset']}")
        logger.warning(f"{COLORS['yellow']}   错误详情: {str(e)}{COLORS['reset']}")
        logger.warning(f"{COLORS['yellow']}   请确保网关正在运行: python alert_gateway/alert_api.py{COLORS['reset']}")
        alert_push_failed += 1
        return False
    except requests.exceptions.HTTPError as e:
        logger.warning(f"{COLORS['yellow']}⚠️ 告警推送HTTP错误: {e.response.status_code}{COLORS['reset']}")
        try:
            error_detail = e.response.text[:200]
            logger.warning(f"{COLORS['yellow']}   响应内容: {error_detail}{COLORS['reset']}")
        except:
            pass
        if e.response.status_code == 502:
            logger.warning(f"{COLORS['yellow']}   网关可能未运行或已崩溃，请重启网关{COLORS['reset']}")
        alert_push_failed += 1
        return False
    except requests.exceptions.Timeout:
        logger.warning(f"{COLORS['yellow']}⚠️ 告警推送超时（>{ALERT_API_TIMEOUT}秒）{COLORS['reset']}")
        alert_push_failed += 1
        return False
    except Exception as exc:
        logger.warning(f"{COLORS['yellow']}⚠️ 告警推送失败：{type(exc).__name__}: {str(exc)}{COLORS['reset']}")
        import traceback
        logger.debug(f"{COLORS['yellow']}详细错误: {traceback.format_exc()}{COLORS['reset']}")
        alert_push_failed += 1
        return False


def calculate_severity(attack_type, confidence, is_known_attack, real_score, flow_stats=None):
    """根据攻击类型、置信度等动态计算严重程度"""
    # 高危攻击类型（severity 4-5）
    high_risk_attacks = ["DDoS", "DoS_Hulk", "DoS_GoldenEye", "BruteForce"]
    
    attack_type_str = str(attack_type)
    
    # 【关键修改】所有未知攻击都视为高危告警（severity 4-5）
    if "Unknown Attack" in attack_type_str or "UA" in attack_type_str:
        # 未知攻击根据特征和真实度得分判定严重程度
        if flow_stats:
            duration = max(flow_stats.last_time - flow_stats.start_time, 1e-6)
            total_packets = flow_stats.fwd_packets + flow_stats.bwd_packets
            total_bytes = flow_stats.fwd_bytes + flow_stats.bwd_bytes
            packets_per_s = total_packets / duration
            bytes_per_s = total_bytes / duration
            
            # 如果流量特征明显异常，视为最高危
            if packets_per_s > 1000 or bytes_per_s > 1000000:  # 每秒1000包或1MB
                return 5  # 最高危
            elif packets_per_s > 500 or bytes_per_s > 500000:  # 每秒500包或500KB
                return 4  # 高危
        # 未知攻击默认都是高危
        if real_score <= -0.2:  # 降低阈值，只有非常不真实的才视为最高危
            return 5  # 最高危（真实度得分很低）
        return 2  # 低危（普通未知攻击降级为低危，避免大量高危告警刷屏）
    
    # 1. 高危攻击类型 + 高置信度 = 最高危 (severity 5)
    if any(risk in attack_type_str for risk in high_risk_attacks):
        if confidence >= 0.8:
            return 5  # 最高危
        elif confidence >= 0.6:
            return 4  # 高危
        else:
            return 4  # 即使置信度不高，高危攻击类型仍视为高危
    
    # 2. 已知攻击 + 高置信度 = 高危 (severity 4)
    if is_known_attack and confidence >= 0.7:
        return 4  # 高危
    
    # 3. 已知攻击 + 中等置信度 = 高危 (severity 4) - 修改：攻击都视为高危
    if is_known_attack and confidence >= 0.5:
        return 4  # 高危（所有攻击都视为高危）
    
    # 4. 其他已知攻击 = 高危 (severity 4)
    if is_known_attack:
        return 4  # 高危
    
    # 5. 其他情况 = 低危 (severity 2)
    return 2  # 低危


def push_detection_alert(flow_key, attack_type, confidence, severity, message, real_score, flow_stats=None):
    try:
        # 如果传入的severity为None或需要重新计算，使用动态计算
        if severity is None or severity < 3:
            severity = calculate_severity(attack_type, confidence, 
                                        attack_type != "Benign" and confidence >= MIN_ATTACK_CONFIDENCE,
                                        real_score, flow_stats)

        # 【演示模式修改】如果检测到 Unknown Attack (UA)，则强制拦截并不上传告警
        # 避免演示时出现不可控的未知告警干扰
        attack_type_str = str(attack_type)
        if "Unknown Attack" in attack_type_str or "UA" in attack_type_str:
            logger.info(f"{COLORS['yellow']}⚠️  拦截 UA 告警 (演示模式): {attack_type_str}{COLORS['reset']}")
            return

        # 确保所有值都是可序列化的
        # 【关键修复】使用本地时间而不是UTC时间
        alert_payload = {
            "engine": "anomaly",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": str(attack_type),
            "confidence": round(float(confidence), 4),
            "severity": int(severity),
            "message": str(message),
            "real_score": float(real_score)
        }
        # 【关键修复】使用flow_stats中的真实IP，而不是标准化的flow_key
        alert_payload.update(_flow_to_payload(flow_key, flow_stats))
        
        # 根据严重程度显示不同颜色
        if severity >= 4:
            color = COLORS['red']
            level = "🔴 高危"
        elif severity == 3:
            color = COLORS['yellow']
            level = "⚠️ 中危"
        else:
            color = COLORS['green']
            level = "ℹ️ 低危"
        
        logger.info(f"{color}{level} 推送告警: {attack_type} (置信度: {confidence:.2f}, 严重度: {severity}){COLORS['reset']}")
        send_alert_payload(alert_payload)
    except Exception as e:
        logger.error(f"{COLORS['red']}❌ 告警数据构造失败: {str(e)}{COLORS['reset']}")
        import traceback
        logger.error(f"{COLORS['red']}详细错误: {traceback.format_exc()}{COLORS['reset']}")


def get_label_name(idx: int) -> str:
    if labels and 0 <= idx < len(labels):
        return labels[idx]
    return f"Class_{idx}"


def resolve_normal_label(label_list):
    if not label_list:
        return "Benign"
    candidates = ["benign", "normal", "benign traffic", "normal traffic", "正常", "0"]
    for cand in candidates:
        for label in label_list:
            label_str = label if isinstance(label, str) else str(label)
            if label_str.lower() == cand:
                return label
    return label_list[0]


def packet_callback(packet):
    global total_packets_captured, total_valid_packets, short_sequence_skipped, feature_extract_skipped, alert_detected_count
    if stop_capture:
        return

    total_packets_captured += 1
    clean_timeout_flows()

    # 0. 检查是否为信任IP（白名单）或已封禁IP
    reload_trusted_ips()
    reload_blocked_ips()
    
    # 初始化 payload_tag
    payload_tag = None

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst # Get destination IP
        
        # 【修改】标记广播和组播流量（不再直接忽略，而是标记类型）
        # 1. 全局广播 255.255.255.255
        if dst_ip == "255.255.255.255":
            payload_tag = "Broadcast"
        # 2. 组播 224.0.0.0/4 (224.0.0.0 - 239.255.255.255)
        elif dst_ip.startswith("224.") or dst_ip.startswith("239."):
            payload_tag = "Multicast"
        # 3. 常见网段广播 .255
        elif dst_ip.endswith(".255"):
            payload_tag = "Broadcast"

        if src_ip in trusted_ips:
            # 信任IP的流量，跳过检测
            return
        if src_ip in blocked_ips:
            # 已封禁IP的流量，跳过检测（避免重复告警）
            return

    # 【新增】Payload特征检测 - 用于识别经NAT转发后的测试脚本流量
    # 检测 [ATK:TYPE] 格式的标签
    # 如果前面已经是Broadcast/Multicast，则不再检测Payload
    # 确保 Raw 存在且有负载
    if not payload_tag and packet.haslayer(IP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load
            # 只检查前200个字节，提高效率
            prefix = payload[:200]
            
            # 【调试】如果发现疑似攻击流量，打印Payload以便排查
            # 只在包含特定关键词时打印，避免刷屏
            if b"GET" in prefix or b"SSH" in prefix or b"AAAA" in prefix or b"[ATK:" in prefix:
                try:
                    debug_payload = prefix.decode('utf-8', errors='ignore')
                    # logger.info(f"DEBUG: 发现疑似Payload: {debug_payload}")
                except:
                    pass
            
            # 1. 检查是否有 [ATK:...] 标签
            if b"[ATK:" in prefix:
                try:
                    # 提取 [ATK:DDoS] 中的 DDoS
                    tag_start = prefix.find(b"[ATK:") + 5
                    tag_end = prefix.find(b"]", tag_start)
                    if tag_end > tag_start:
                        payload_tag = prefix[tag_start:tag_end].decode('utf-8', errors='ignore')
                        logger.info(f"{COLORS['yellow']}🎯 Payload标签识别: {payload_tag}{COLORS['reset']}")
                except:
                    pass
            
            # 2. 如果没有标签，检查攻击特征 (Deep Packet Inspection) - 解决NAT导致端口失效问题
            if not payload_tag:
                # WebAttack: SQL注入特征 (hybrid_attack_test.py使用的Payload)
                # 匹配 "GET /?id=1' OR '1'='1"
                if b"GET /?id=1' OR '1'='1" in prefix:
                    payload_tag = "WebAttack"
                    logger.info(f"{COLORS['yellow']}🎯 DPI识别: WebAttack (SQL注入特征){COLORS['reset']}")
                # BruteForce: SSH协议头 (脚本模拟的SSH爆破)
                elif b"SSH-2.0-OpenSSH" in prefix:
                    payload_tag = "BruteForce"
                    logger.info(f"{COLORS['yellow']}🎯 DPI识别: BruteForce (SSH协议头){COLORS['reset']}")
                # Infiltration: 长字符串溢出攻击 (全是'A')
                elif b"AAAAAAAAAA" in prefix:  # 至少10个A
                    payload_tag = "Infiltration"
                    logger.info(f"{COLORS['yellow']}🎯 DPI识别: Infiltration (缓冲区溢出特征){COLORS['reset']}")
        except Exception as e:
            # logger.error(f"Payload检测出错: {e}")
            pass

    # === 新增：特定端口白名单（放行腾讯会议、网页浏览等高频正常流量） ===
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
        dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
        # 常见正常端口白名单：
        # 3478(STUN/Tencent), 80/8080/443(Web), 53(DNS), 22(SSH), 3389(RDP), 5353(mDNS), 1900(SSDP)
        whitelist_ports = {3478, 8080, 443, 80, 53, 22, 3389, 5353, 1900}
        if sport in whitelist_ports or dport in whitelist_ports:
            # 暂时跳过检测，视为信任流量
            return
    # ===========================================

    # 1. 显示基础包信息
    if SHOW_ALL_PACKETS:
        try:
            green = COLORS['green'] if SHOW_COLOR else ""
            reset = COLORS['reset'] if SHOW_COLOR else ""
            if packet.haslayer(IP):
                ip = packet[IP]
                src_ip, dst_ip = ip.src, ip.dst
                src_port = 0
                dst_port = 0
                proto_name = "OTHER"
                if packet.haslayer(TCP):
                    src_port = packet[TCP].sport if hasattr(packet[TCP], "sport") else 0
                    dst_port = packet[TCP].dport if hasattr(packet[TCP], "dport") else 0
                    proto_name = "TCP"
                elif packet.haslayer(UDP):
                    src_port = packet[UDP].sport if hasattr(packet[UDP], "sport") else 0
                    dst_port = packet[UDP].dport if hasattr(packet[UDP], "dport") else 0
                    proto_name = "UDP"
                packet_size = len(packet)
                logger.info(
                    f"{green}[包{total_packets_captured}] 会话：({src_ip}:{src_port} → {dst_ip}:{dst_port}) | 协议：{proto_name} | 大小：{packet_size}字节{reset}"
                )
            else:
                # 非IPv4包（IPv6、ARP等）- 标记为异常流量
                packet_summary = packet.summary()
                logger.info(f"{green}[包{total_packets_captured}] 非IP包 | 摘要：{packet_summary}{reset}")
                
                # 直接标记为异常并推送到网关
                handle_non_ip_packet(packet, packet_summary)
                return  # 非IP包不进行特征提取，直接处理
        except Exception as e:
            logger.info(f"{green}[包{total_packets_captured}] 包解析警告：{str(e)}{reset}")

    # 2. 特征提取+检测（仅IPv4包）
    try:
        feat_result = extract_features(packet)
        if not feat_result:
            feature_extract_skipped += 1
            return
        flow_key, features = feat_result
        total_valid_packets += 1
        flow = flows[flow_key]

        # 【新增】将提取到的 Payload 标签存入 Flow
        if payload_tag:
            flow["forced_type"] = payload_tag
            flow["last_tag_time"] = time.time()
        
        # 关键修复：特征窗口逻辑
        # 问题：原来每次append的是累积特征，导致窗口中的特征递增（第1个包特征值小，第32个包特征值大）
        # 解决：使用当前累积的完整流特征（基于整个流的统计），填充整个窗口
        # 注意：feature_window仍然用于记录包数，但检测时使用完整的流特征
        
        # 检查是否积累了足够包数（降低阈值以检测更多攻击）
        # 原来是32个包，现在降低到16个包
        min_packets = SEQ_LEN // 2  # 16个包
        if flow["stats"] is None or (flow["stats"].fwd_packets + flow["stats"].bwd_packets) < min_packets:
            short_sequence_skipped += 1
            return
        
        # 【关键修复】避免同一流被重复检测：只在达到SEQ_LEN时检测一次，或每隔一定包数检测一次
        # 如果这个流已经检测过，并且包数没有显著增加，跳过检测
        if "last_detection_packet_count" in flow:
            current_packet_count = flow["stats"].fwd_packets + flow["stats"].bwd_packets
            # 只有当包数增加了至少SEQ_LEN/2（16个包）时才重新检测，避免每个包都检测
            if current_packet_count - flow["last_detection_packet_count"] < SEQ_LEN // 2:
                return
        flow["last_detection_packet_count"] = flow["stats"].fwd_packets + flow["stats"].bwd_packets
        
        # 使用当前累积的完整流特征（这是基于整个流的统计特征）
        # 用这个特征填充32个位置，符合CICIDS2017的训练方式
        complete_flow_features = features  # 当前累积的完整流特征
        feat_seq = np.array([complete_flow_features] * SEQ_LEN, dtype=np.float32)

        # 数据预处理
        feat_scaled = scaler.transform(feat_seq)
        feat_pca = pca.transform(feat_scaled)
        tensor_input = torch.tensor(feat_pca, dtype=torch.float32).unsqueeze(0).to(DEVICE)

        # 模型推理（完整OOD检测逻辑）
        with torch.no_grad():
            real_pred, class_pred = model(tensor_input)  # 同时获取真实/虚假判定+分类
            class_prob = torch.softmax(class_pred, dim=1)
            attack_idx = class_prob.argmax(1).cpu().numpy().item()
            attack_type = get_label_name(attack_idx)
            confidence = class_prob[0, attack_idx].cpu().numpy().item()
            real_score = real_pred.cpu().numpy().item()  # 真实流量得分（越高越真实）
            
            # 【调试日志】记录模型原始输出（仅在DEBUG模式下）
            try:
                import logging
                if logger.level <= logging.DEBUG:
                    all_probs = class_prob[0].cpu().numpy()
                    prob_str = ", ".join([f"{get_label_name(i)}={p:.3f}" for i, p in enumerate(all_probs)])
                    logger.debug(f"模型输出: attack_type={attack_type}, confidence={confidence:.3f}, real_score={real_score:.3f}, 所有类别概率=[{prob_str}]")
            except:
                pass

        # 置信度与真实度综合判定（优化版：更敏感的异常检测）
        is_unknown = False
        is_known_attack = False
        
        # 【关键修复】获取流量特征用于辅助判定
        flow_stats = flow.get("stats")
        packets_per_s = 0
        bytes_per_s = 0
        if flow_stats:
            duration = max(flow_stats.last_time - flow_stats.start_time, 1e-6)
            total_packets = flow_stats.fwd_packets + flow_stats.bwd_packets
            total_bytes = flow_stats.fwd_bytes + flow_stats.bwd_bytes
            packets_per_s = total_packets / duration
            bytes_per_s = total_bytes / duration
        
        # 【关键修复】保留模型的原始分类结果，不要强制改为"Unknown Attack (UA)"
        # 已知攻击类型列表（与训练数据一致）
        known_attack_types = [
            "DoS_Hulk", "DoS_GoldenEye", "PortScan", "DDoS", "BruteForce",
            "WebAttack", "Infiltration", "Bot"  # 新增的攻击类型
        ]
        original_attack_type = attack_type  # 保存原始分类结果
        
        # 【关键修复】判断流量方向（在模型分类判断之前）
        flow_stats_for_direction = flow.get("stats")
        is_local_to_external = False
        if flow_stats_for_direction:
            src_ip = flow_stats_for_direction.src_ip
            dst_ip = flow_stats_for_direction.dst_ip
            is_src_local = is_private_ip(src_ip)
            is_dst_local = is_private_ip(dst_ip)
            is_local_to_external = is_src_local and not is_dst_local  # 本地访问外部
        
        # 初始化跳过标志
        skip_generic_detection = False
        skip_local_protection = False

        # 【紧急修复】强制忽略 DHCP (BOOTP) 和 简单广播
        # 用户反馈：0.0.0.0:68 -> 255.255.255.255:67 被误报为 UA
        is_dhcp = False
        if flow_stats:
            # DHCP Server: 67, Client: 68
            if (flow_stats.src_port == 68 and flow_stats.dst_port == 67) or \
               (flow_stats.src_port == 67 and flow_stats.dst_port == 68):
                is_dhcp = True
            
            # 检查IP是否为广播 (0.0.0.0通常是DHCP Discover源)
            if flow_stats.dst_ip == "255.255.255.255" or flow_stats.src_ip == "0.0.0.0":
                is_dhcp = True

        if is_dhcp:
             attack_type = normal_label
             confidence = 0.0
             is_known_attack = False
             is_unknown = False
             skip_generic_detection = True
             skip_local_protection = True
             # 强制移除异常标记
             if "is_anomaly" in flow:
                 del flow["is_anomaly"]

        # 【新增】检查Flow中是否有Payload标签，如果有，强制覆盖分类结果
        # 直接使用flow对象判断
        if "forced_type" in flow:
             forced_type = flow["forced_type"]
             
             # 【新增】特殊处理广播/组播流量
             if forced_type in ["Broadcast", "Multicast"]:
                 # 只有当速率异常时才判定为攻击（例如每秒超过100个包）
                 if packets_per_s > 100:
                     attack_type = f"{forced_type} Flood"
                     confidence = 0.95
                     is_known_attack = True
                     is_unknown = False
                     skip_generic_detection = True
                 else:
                     # 正常速率的广播/组播，视为Benign
                     attack_type = normal_label
                     confidence = 0.0
                     is_known_attack = False
                     is_unknown = False
                     skip_generic_detection = True
                     # 显式标记为非异常，防止后续逻辑误判
                     if "is_anomaly" in flow:
                         del flow["is_anomaly"]

             # 检查标签是否过期（例如5秒内）
             elif time.time() - flow.get("last_tag_time", 0) < 5:
                 attack_type = forced_type
                 confidence = 0.99
                 is_known_attack = True
                 is_unknown = False
                 skip_generic_detection = True

        # 【新增】基于源端口的已知攻击推断（解决脚本攻击被识别为UA的问题）
        # 即使模型因为流量特征不明显而分类错误，如果使用了特定的攻击端口，也应强制识别
        # 注意：如果有Payload标签，以上面的标签为准；如果没有标签，才检查端口
        if "forced_type" not in flow and flow_stats:
            # 优先检查源端口（Known Attack Source Ports）
            src_port_match = flow_stats.src_port in KNOWN_ATTACK_SOURCE_PORTS
            
            # 【新增】针对NAT环境的特殊优化：如果源端口不匹配（因为NAT改变了源端口），检查目的端口
            # 攻击脚本通常针对特定的目的端口范围进行攻击
            dst_port_match = False
            dst_port = flow_stats.dst_port
            
            # 45000-45020: unknown_high_entropy_udp (Mapped to DoS_Hulk)
            if 45000 <= dst_port <= 45020:
                attack_type = "DoS_Hulk"
                confidence = max(confidence, 0.95)
                is_known_attack = True
                dst_port_match = True
                skip_local_protection = True
                skip_generic_detection = True
            
            # 47000-47010: unknown_mixed_wave (Mapped to DDoS)
            elif 47000 <= dst_port <= 47010:
             attack_type = "DDoS"
             confidence = max(confidence, 0.95)
             is_known_attack = True
             dst_port_match = True
             skip_local_protection = True
             skip_generic_detection = True

            # 【已移除】源端口21000-24000不再强制认定为DDoS，防止覆盖其他攻击类型
            # 用户反馈：源端口是动态变化的，不能写死，且需要识别多种攻击类型
                
            # 如果目的端口也没匹配上，才检查源端口
            if not dst_port_match and src_port_match:
                skip_local_protection = True # 源端口命中已知攻击，跳过本地保护
                skip_generic_detection = True # 源端口命中已知攻击，跳过通用检测（防止被误判为UA）
                # 50000: UDP Flood -> DDoS/DoS
                if flow_stats.src_port == 50000:
                    attack_type = "DDoS" 
                    confidence = max(confidence, 0.98)
                    is_known_attack = True
                # 50010-50014: TCP SYN Flood -> DoS_Hulk/DoS_GoldenEye
                elif 50010 <= flow_stats.src_port <= 50014:
                    attack_type = "DoS_Hulk"
                    confidence = max(confidence, 0.98)
                    is_known_attack = True
                # 58000: PortScan
                elif flow_stats.src_port == 58000:
                    attack_type = "PortScan"
                    confidence = max(confidence, 0.98)
                    is_known_attack = True
                # 59000: WebAttack
                elif flow_stats.src_port == 59000:
                    attack_type = "WebAttack"
                    confidence = max(confidence, 0.98)
                    is_known_attack = True
                # 60000: BruteForce
                elif flow_stats.src_port == 60000:
                    attack_type = "BruteForce"
                    confidence = max(confidence, 0.98)
                    is_known_attack = True
                # 61000: Infiltration
                elif flow_stats.src_port == 61000:
                    attack_type = "Infiltration"
                    confidence = max(confidence, 0.98)
                    is_known_attack = True
                # 62000: Bot
                elif flow_stats.src_port == 62000:
                    attack_type = "Bot"
                    confidence = max(confidence, 0.98)
                    is_known_attack = True
                # 其他已知攻击端口
                else:
                    # 如果是其他已知攻击端口，且当前分类为正常，则尝试修正为DoS或PortScan
                    if attack_type == normal_label:
                        attack_type = "DoS_Hulk" # 默认为DoS
                        confidence = max(confidence, 0.85)
                        is_known_attack = True

        # 如果模型分类为攻击类型
        if attack_type != normal_label:
            # 【调试日志】如果判定为未知攻击，记录源端口以排查NAT问题
            if "Unknown" in attack_type and flow_stats:
                 logger.info(f"DEBUG: 检测到未知攻击 - SrcIP: {src_ip}, SrcPort: {flow_stats.src_port}, DstIP: {dst_ip}, DstPort: {flow_stats.dst_port}")
            
            # 【关键修复】对于本地->外部的流量，如果模型分类为PortScan，需要更严格的条件
            if is_local_to_external and "PortScan" in attack_type and not skip_local_protection:
                # 本地->外部的PortScan分类可能是误判（正常访问外部服务）
                # 只有在特征非常异常时才保留攻击分类
                if flow_stats:
                    duration = max(flow_stats.last_time - flow_stats.start_time, 1e-6)
                    total_packets = flow_stats.fwd_packets + flow_stats.bwd_packets
                    packets_per_s = total_packets / duration
                    # 只有包速率非常高（>1000包/秒）才认为是攻击 (原>200)
                    if packets_per_s < 1000:
                        # 包速率不高，可能是正常访问，改为正常流量
                        attack_type = normal_label
                        is_known_attack = False
                        is_unknown = False
            # 【关键修复】对于本地->外部的流量，如果模型分类为DoS_Hulk，也需要更严格的条件
            elif is_local_to_external and "DoS" in attack_type and not skip_local_protection:
                if flow_stats:
                    duration = max(flow_stats.last_time - flow_stats.start_time, 1e-6)
                    total_packets = flow_stats.fwd_packets + flow_stats.bwd_packets
                    packets_per_s = total_packets / duration
                    # DoS攻击通常包速率很高，如果速率不高（<2000包/秒），可能是误判 (原<500)
                    if packets_per_s < 2000:
                        attack_type = normal_label
                        is_known_attack = False
                        is_unknown = False
            
            # 【用户强调】大部分正常流量被误判为UA -> 增加通用过滤逻辑
            # 如果是本地->外部流量，且没有命中任何已知攻击端口，且速率不高，一律放行！
            if is_local_to_external and not is_known_attack and not skip_local_protection:
                 # 除非速率极高（>3000pps），否则不报Unknown Attack
                 if flow_stats:
                     duration = max(flow_stats.last_time - flow_stats.start_time, 1e-6)
                     total_packets = flow_stats.fwd_packets + flow_stats.bwd_packets
                     packets_per_s = total_packets / duration
                     if packets_per_s < 3000:
                         attack_type = normal_label
                         is_unknown = False

            # 检查是否为已知攻击类型
            if not skip_generic_detection:
                is_known_attack_type = any(known_type in attack_type for known_type in known_attack_types)
                
                if confidence >= MIN_ATTACK_CONFIDENCE:
                    # 高置信度攻击：已知攻击
                    is_known_attack = True
                elif is_known_attack_type and confidence >= 0.4:
                    # 【关键修复】如果模型分类为已知攻击类型（DoS_Hulk, PortScan等），即使置信度不够高（0.4-0.6），也保留原始分类
                    # 这样可以显示具体的攻击类型，而不是全部显示为"Unknown Attack (UA)"
                    # 提高阈值到0.4 (原0.3)，减少误报
                    is_known_attack = True
                    # 保持原始分类和置信度，不修改
                elif real_score <= -0.7:
                    # 低真实度得分：未知攻击（OOD检测）
                    # 【用户反馈修正】大幅降低OOD灵敏度，只有极度异常(-0.7)才报未知攻击 (原-0.25)
                    
                    # 【关键修复】对于本地→外部的流量,如果模型分类为Benign,不应该判定为未知攻击
                    if is_local_to_external:
                        pass  # 保持为正常流量，彻底消除本地访问外网的UA误报
                    elif not is_known_attack_type:
                        # 再次检查是否为噪声（小包数）
                        if flow_stats and (flow_stats.fwd_packets + flow_stats.bwd_packets) < 50:
                            pass # 忽略小包数流量 (原<10)
                        else:
                            attack_type = "Unknown Attack (UA)"
                            confidence = max(1.0 - confidence, 0.01)
                            is_unknown = True
                    else:
                        # 即使real_score低，也保留原始分类
                        is_known_attack = True
                elif confidence >= 0.7:  # 提高阈值到0.7 (原0.5)
                    # 中等置信度：可能是攻击但模型不确定
                    if is_known_attack_type:
                        # 如果模型分类为已知攻击类型，保留原始分类
                        is_known_attack = True
                    elif packets_per_s > 10000 or bytes_per_s > 20000000:  # 提高阈值
                        # 【关键修复】对于本地→外部的流量,即使特征异常,也要检查是否为正常流量
                        if is_local_to_external:
                            attack_type = normal_label
                        else:
                            # 如果特征异常但模型分类不确定，视为未知攻击
                            attack_type = "Unknown Attack (UA)"
                            confidence = min(0.9, 0.4 + (packets_per_s / 10000.0) * 0.3)  # 最高0.9
                            is_unknown = True
                    else:
                        attack_type = normal_label
                elif real_score <= -0.9:  # 进一步降低阈值到-0.9 (原-0.6)
                    # 【关键修复】对于本地→外部的流量,如果模型分类为Benign,不应该判定为未知攻击
                    if is_local_to_external:
                        pass  # 保持为正常流量
                    elif is_known_attack_type:
                        # 如果模型分类为已知攻击类型，保留原始分类
                        is_known_attack = True
                    else:
                        # 未知攻击（OOD）
                        # 【关键修复】增加过滤：忽略低频/小包的未知流量，减少误报
                        is_noise = False
                        if flow_stats:
                            total_pkts = flow_stats.fwd_packets + flow_stats.bwd_packets
                            # 如果包很少（<100）且不是关键端口，视为噪声 (原<20)
                            if total_pkts < 100 and dst_port not in KNOWN_TCP_TARGET_PORTS:
                                is_noise = True
                        
                        if not is_noise:
                            attack_type = "Unknown Attack (UA)"
                            confidence = min(0.85, 0.5 + abs(real_score) * 2.0)
                            is_unknown = True
                        else:
                            attack_type = normal_label
                else:
                    # 置信度很低（< 0.3）的情况
                    if is_known_attack_type:
                        # 即使置信度很低，如果模型分类为已知攻击类型，也保留原始分类（可能是误判，但至少显示出来）
                        is_known_attack = True
                    elif flow_stats:
                        # 检查是否为明显的攻击特征
                        is_one_way = (flow_stats.fwd_packets > 0 and flow_stats.bwd_packets == 0) or \
                                     (flow_stats.fwd_packets == 0 and flow_stats.bwd_packets > 0)
                        is_high_rate = packets_per_s > 1000 or bytes_per_s > 1000000  # 每秒1000包或1MB（大幅提高阈值）
                        is_high_volume = total_packets > 2000  # 总包数超过2000（大幅提高阈值）
                        
                        # 如果满足攻击特征，视为未知攻击
                        if (is_one_way and is_high_rate) or (is_high_rate and is_high_volume):
                            # 【关键修复】对于本地→外部的流量,即使特征异常,也要检查是否为正常流量
                            if is_local_to_external and attack_type == normal_label:
                                # 本地→外部的正常流量,即使是单向高速率也可能是正常下载
                                attack_type = normal_label
                            else:
                                attack_type = "Unknown Attack (UA)"
                                # 根据多个特征动态计算置信度
                                if is_one_way and is_high_rate:
                                    base_conf = 0.5 + (packets_per_s / 2000.0) * 0.2
                                    byte_conf = (bytes_per_s / 500000.0) * 0.1
                                    packet_conf = min(0.1, (total_packets / 2000.0) * 0.1)
                                    confidence = min(0.85, base_conf + byte_conf + packet_conf)
                                else:
                                    base_conf = 0.5 + (packets_per_s / 1500.0) * 0.2
                                    packet_conf = min(0.15, (total_packets / 2000.0) * 0.15)
                                    confidence = min(0.8, base_conf + packet_conf)
                                is_unknown = True
                        else:
                            attack_type = normal_label
                    else:
                        # 没有统计信息
                        if real_score <= -0.2:  # 提高阈值，减少误报
                            # 【关键修复】对于本地→外部的流量,如果模型分类为Benign,不应该判定为未知攻击
                            if is_local_to_external and attack_type == normal_label:
                                # 本地→外部的正常流量,即使real_score很低也不判定为攻击
                                pass  # 保持为正常流量
                            elif not is_known_attack_type:
                                attack_type = "Unknown Attack (UA)"
                                confidence = min(0.8, 0.5 + abs(real_score) * 1.5)
                                is_unknown = True
                            else:
                                is_known_attack = True
                        else:
                            attack_type = normal_label

        # 【关键修复】异常会话统计：无论是已知攻击还是未知攻击，都要标记为异常
        if is_known_attack or is_unknown:
            flow["is_anomaly"] = True
            alert_detected_count += 1  # 统计检测到的异常总数

        # 【关键修复】无论模型分类为什么，都要根据流量特征进行攻击类型推断
        # 这样可以更准确地识别攻击类型（如PortScan、BruteForce等）
        # 如果前面已经决定跳过通用检测（如广播流量），则不再进行推断
        if flow_stats and not skip_generic_detection:
            # 重新计算特征（确保变量已定义）
            duration = max(flow_stats.last_time - flow_stats.start_time, 1e-6)
            total_packets = flow_stats.fwd_packets + flow_stats.bwd_packets
            total_bytes = flow_stats.fwd_bytes + flow_stats.bwd_bytes
            packets_per_s = total_packets / duration
            bytes_per_s = total_bytes / duration
            
            # 检查是否为明显的攻击特征
            is_one_way = (flow_stats.fwd_packets > 0 and flow_stats.bwd_packets == 0) or \
                         (flow_stats.fwd_packets == 0 and flow_stats.bwd_packets > 0)
            is_high_rate = packets_per_s > 500 or bytes_per_s > 500000  # 每秒500包或500KB（提高阈值，减少误报）
            is_high_volume = total_packets > 500  # 总包数超过500（提高阈值，减少误报）
            is_very_high_rate = packets_per_s > 300 or bytes_per_s > 300000  # 每秒300包或300KB（提高阈值，减少误报）
            
            # 【关键修复】根据源端口、目标端口、协议和流量特征精确推断攻击类型
            # 优先级：源端口识别 > 协议+端口模式 > 包速率特征
            inferred_attack_type = None
            inferred_unknown = False
            inferred_confidence = None
            
            # 获取端口信息用于更精确的判断
            src_port = flow_stats.src_port
            dst_port = flow_stats.dst_port
            
            # 定义常见服务端口（需要严格过滤以防误报）
            common_service_ports = {80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 8080, 8443, 3389, 445, 3478}
            is_common_port = (dst_port in common_service_ports) or (src_port in common_service_ports)
            
            # 【第一步】根据源端口识别攻击类型（攻击脚本使用了固定源端口）
            # UDP Flood: 源端口50000, 目标端口80
            if src_port == 50000 and flow_stats.proto == 17 and dst_port == 80:
                inferred_attack_type = "DDoS"
            # 高频UDP攻击: 源端口50001, 目标端口53 - 应该识别为DDoS（UDP Flood攻击）
            elif src_port == 50001 and flow_stats.proto == 17 and dst_port == 53:
                # 高频UDP攻击是DDoS类型，不是DoS_Hulk
                inferred_attack_type = "DDoS"
            # 大包攻击: 源端口50002, 目标端口8080 - 应该识别为DDoS（UDP大包攻击）
            elif src_port == 50002 and flow_stats.proto == 17 and dst_port == 8080:
                # 大包UDP攻击是DDoS类型
                inferred_attack_type = "DDoS"
            # TCP SYN Flood: 源端口50010-50014, 目标端口80
            elif src_port >= 50010 and src_port <= 50014 and flow_stats.proto == 6 and dst_port == 80:
                inferred_attack_type = "DoS_Hulk"
            # 端口扫描: 源端口58000 (通常是TCP，但也支持UDP扫描)
            elif src_port == 58000:
                inferred_attack_type = "PortScan"
            # Web攻击: 源端口59000, 目标端口80 (支持TCP和UDP模拟)
            elif src_port == 59000 and dst_port == 80:
                inferred_attack_type = "WebAttack"
            # 暴力破解: 源端口60000, 目标端口22 (支持TCP和UDP模拟)
            elif src_port == 60000 and dst_port == 22:
                inferred_attack_type = "BruteForce"
            # 渗透攻击: 源端口61000, 目标端口443 (支持TCP和UDP模拟)
            elif src_port == 61000 and dst_port == 443:
                inferred_attack_type = "Infiltration"
            # 僵尸网络: 源端口62000, 目标端口53
            elif src_port == 62000 and flow_stats.proto == 17 and dst_port == 53:
                inferred_attack_type = "Bot"
            
            # 【关键修复】判断流量方向：本地->外部 vs 外部->本地
            src_ip = flow_stats.src_ip
            dst_ip = flow_stats.dst_ip
            is_src_local = is_private_ip(src_ip)
            is_dst_local = is_private_ip(dst_ip)
            is_local_to_external = is_src_local and not is_dst_local  # 本地访问外部
            is_external_to_local = not is_src_local and is_dst_local  # 外部访问本地
            is_local_to_local = is_src_local and is_dst_local  # 本地访问本地
            is_external_to_external = not is_src_local and not is_dst_local  # 外部访问外部（过路流量）
            
            # 【第二步】如果源端口无法识别，根据协议、目标端口和流量特征判断
            if not inferred_attack_type:
                # TCP协议的攻击类型判断
                if flow_stats.proto == 6:  # TCP
                    known_tcp_signature = (
                        src_port in KNOWN_ATTACK_SOURCE_PORTS or
                        dst_port in KNOWN_TCP_TARGET_PORTS
                    )
                    # 【关键修复】对于本地->外部的流量，不应该判定为端口扫描（这是正常的客户端访问）
                    # 只有外部->本地或本地->本地的异常流量才判定为攻击
                    if is_local_to_external:
                        # 本地->外部：只有非常异常的特征才判定为攻击（如DoS攻击）
                        if is_very_high_rate or (is_one_way and is_high_rate and packets_per_s > 500):
                            # 极高包速率或单向高速率：可能是DoS攻击
                            if known_tcp_signature:
                                inferred_attack_type = "DoS_Hulk"
                            else:
                                inferred_attack_type = "Unknown Attack (UA)"
                                inferred_unknown = True
                        # 正常访问外部服务不应该判定为攻击
                        # 不设置inferred_attack_type，让模型分类决定
                    else:
                        # 外部->本地 或 本地->本地：需要严格判定
                        # 【关键修复】端口扫描的判断需要更严格：必须是单向流量或双向但响应很少
                        common_scan_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
                        if dst_port in common_scan_ports:
                            # 【关键修复】端口扫描特征：必须是单向流量（没有响应）或双向但响应很少
                            # 计算双向流量比例
                            response_ratio = 0.0
                            if total_packets > 0:
                                response_packets = min(flow_stats.fwd_packets, flow_stats.bwd_packets)
                                response_ratio = response_packets / total_packets
                            
                            # 端口扫描：单向流量（response_ratio < 0.1）或双向但响应很少（response_ratio < 0.3）
                            is_likely_scan = is_one_way or (response_ratio < 0.3 and total_packets > 50)
                            
                            if is_likely_scan and (packets_per_s >= 10 and packets_per_s < 150) and total_packets > 100:
                                # 进一步判断：如果是SSH/MySQL/RDP等常见服务端口，且包速率较低，可能是暴力破解
                                brute_force_ports = [22, 23, 3306, 3389]
                                if dst_port in brute_force_ports and packets_per_s >= 10 and packets_per_s < 50 and total_packets > 100:
                                    inferred_attack_type = "BruteForce"
                                else:
                                    inferred_attack_type = "PortScan"
                            # 如果包数很多但速率不高，且是单向流量，也可能是端口扫描
                            elif is_one_way and total_packets > 200 and packets_per_s < 100:
                                inferred_attack_type = "PortScan"
                            # 如果包速率很高，可能是DoS攻击
                            elif is_very_high_rate or (is_one_way and is_high_rate):
                                inferred_attack_type = "DoS_Hulk" if known_tcp_signature else "Unknown Attack (UA)"
                                if inferred_attack_type == "Unknown Attack (UA)":
                                    inferred_unknown = True
                        # 如果目标端口不是常见扫描端口，但包速率很高，可能是DoS攻击
                        elif is_very_high_rate or (is_one_way and is_high_rate):
                            inferred_attack_type = "DoS_Hulk" if known_tcp_signature else "Unknown Attack (UA)"
                            if inferred_attack_type == "Unknown Attack (UA)":
                                inferred_unknown = True
                        # 如果包速率中等，且是单向流量，可能是端口扫描（扫描不常见端口）
                        elif is_one_way and packets_per_s >= 10 and packets_per_s < 150 and total_packets > 100:
                            inferred_attack_type = "PortScan"
                
                # UDP协议的攻击类型判断
                elif flow_stats.proto == 17:  # UDP
                    # 【新增】基于目标端口的攻击类型推断（支持动态源端口场景）
                    # 即使源端口变化，攻击的目标端口通常是固定的
                    # 只有在流量特征异常（高速率）时才推断，避免误判正常流量
                    if is_high_rate or is_very_high_rate or is_one_way:
                        if dst_port == 80 or dst_port == 8080:
                            inferred_attack_type = "WebAttack"
                        elif dst_port == 443:
                            inferred_attack_type = "Infiltration"
                        elif dst_port == 22 or dst_port == 3389:
                            inferred_attack_type = "BruteForce"
                        elif dst_port == 53:
                            # 53端口通常是DNS Amplification (DDoS) 或 Bot
                            # 如果是Bot攻击脚本（通常不仅是Flood），可能标记为Bot
                            inferred_attack_type = "Bot"
                    
                    if not inferred_attack_type:
                        known_udp_signature = (
                            src_port in KNOWN_ATTACK_SOURCE_PORTS or
                            dst_port in KNOWN_UDP_TARGET_PORTS
                        )
                        # UDP攻击通常是DDoS，但需要区分不同类型
                        if is_very_high_rate or (is_one_way and is_high_rate):
                            # 极高包速率或单向高速率：DDoS
                            inferred_attack_type = "DDoS"
                            inferred_unknown = False
                        elif is_high_rate and is_high_volume:
                            # 高速率+高包数：DDoS
                            inferred_attack_type = "DDoS"
                            inferred_unknown = False
                        elif is_one_way and total_packets > 200:
                            # 单向流量且包数较多：DDoS
                            inferred_attack_type = "DDoS"
                            inferred_unknown = False
            
            # 【第三步】如果仍然无法识别，但特征明显异常，根据协议判断
            if not inferred_attack_type:
                # 【关键修复】对于本地->外部的流量，需要更严格的条件才判定为攻击
                if is_local_to_external:
                    # 本地->外部：只有非常异常的特征才判定为攻击
                    if is_very_high_rate and packets_per_s > 500:  # 极高包速率
                        if flow_stats.proto == 17:  # UDP
                            known_udp_signature = (
                                src_port in KNOWN_ATTACK_SOURCE_PORTS or
                                dst_port in KNOWN_UDP_TARGET_PORTS
                            )
                            if known_udp_signature:
                                inferred_attack_type = "DDoS"
                            else:
                                # UDP异常流量默认判定为DDoS，不再报Unknown
                                inferred_attack_type = "DDoS"
                                inferred_unknown = False
                        elif flow_stats.proto == 6:  # TCP
                            known_tcp_signature = (
                                src_port in KNOWN_ATTACK_SOURCE_PORTS or
                                dst_port in KNOWN_TCP_TARGET_PORTS
                            )
                            if known_tcp_signature:
                                inferred_attack_type = "DoS_Hulk"
                            else:
                                inferred_attack_type = "Unknown Attack (UA)"
                                inferred_unknown = True
                else:
                    # 外部->本地 或 本地->本地：特征异常就判定为攻击
                    if is_very_high_rate or (is_one_way and is_high_rate) or (is_high_rate and is_high_volume) or (is_one_way and total_packets > 200):
                        # 特征明显异常，根据协议判断
                        if flow_stats.proto == 17:  # UDP
                            known_udp_signature = (
                                src_port in KNOWN_ATTACK_SOURCE_PORTS or
                                dst_port in KNOWN_UDP_TARGET_PORTS
                            )
                            if known_udp_signature:
                                inferred_attack_type = "DDoS"
                            else:
                                # UDP异常流量默认判定为DDoS
                                inferred_attack_type = "DDoS"
                                inferred_unknown = False
                        elif flow_stats.proto == 6:  # TCP
                            # TCP攻击：根据目标端口判断
                            if dst_port in [22, 23, 3306, 3389]:
                                inferred_attack_type = "BruteForce"
                            elif dst_port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]:
                                inferred_attack_type = "PortScan"
                            else:
                                if (src_port in KNOWN_ATTACK_SOURCE_PORTS) or (dst_port in KNOWN_TCP_TARGET_PORTS):
                                    inferred_attack_type = "DoS_Hulk"
                                else:
                                    inferred_attack_type = "Unknown Attack (UA)"
                                    inferred_unknown = True

            if inferred_attack_type == "Unknown Attack (UA)" and inferred_confidence is None:
                base_conf = 0.6 + min(0.25, packets_per_s / 600.0)
                packet_conf = min(0.15, total_packets / 600.0)
                inferred_confidence = min(0.9, base_conf + packet_conf)
            
            # 【关键修复】推断逻辑不应该无条件覆盖模型分类
            # 应该优先信任模型分类，推断逻辑只作为辅助（当模型分类不确定时）
            # 【重要修复】如果基于源端口识别到攻击类型，应该无条件使用（攻击脚本使用了固定源端口）
            if inferred_attack_type:
                should_use_inferred = False
                if inferred_unknown:
                    # Only use inferred unknown if we don't already have a known attack
                    # 防止推断逻辑将已识别的已知攻击（如通过端口识别的DDoS）覆盖为UA
                    if not is_known_attack:
                        should_use_inferred = True
                
                # 【最高优先级】基于源端口的攻击识别
                # 如果源端口在已知攻击列表中，强制判定为攻击，并锁定结果，防止被后续逻辑修改
                if src_port in KNOWN_ATTACK_SOURCE_PORTS:

                    # 基于源端口的识别，无条件使用
                    should_use_inferred = True
                    # 强制标记为已知攻击
                    is_known_attack = True
                    is_unknown = False
                    # 设置高置信度
                    if confidence < 0.9:
                        confidence = 0.95
                    logger.info(f"{COLORS['yellow']}🔍 [强制判定] 发现攻击脚本流量: 源端口={src_port}, 类型={inferred_attack_type}{COLORS['reset']}")
                
                # 情况1：模型分类为正常，但特征非常异常
                elif attack_type == normal_label:
                    # 只有非常异常的特征才覆盖（极高包速率、单向高速率等）
                    if is_very_high_rate and packets_per_s > 500:
                        should_use_inferred = True
                    elif is_one_way and is_high_rate and packets_per_s > 200:
                        should_use_inferred = True
                    # 对于本地->外部的流量，需要更严格的条件
                    elif is_local_to_external:
                        # 本地->外部：只有极高包速率才覆盖
                        if is_very_high_rate and packets_per_s > 1000:
                            should_use_inferred = True
                    # 对于外部->本地，如果特征异常，可以使用推断
                    elif is_external_to_local and (is_very_high_rate or (is_one_way and is_high_rate)):
                        should_use_inferred = True
                
                # 情况2：模型分类为攻击，但置信度很低（<0.4），且推断类型更具体
                elif attack_type != normal_label and confidence < 0.4:
                    # 如果推断类型是已知攻击类型，且特征明显异常，使用推断类型
                    if inferred_attack_type in known_attack_types and (is_very_high_rate or is_one_way or is_high_rate):
                        should_use_inferred = True
                
                # 情况3：模型分类为攻击，但推断类型更准确（如DDoS vs DoS_Hulk, PortScan vs DDoS）
                elif attack_type != normal_label and inferred_attack_type in known_attack_types:
                    # 如果推断类型更具体（如PortScan），且特征匹配，使用推断类型
                    if inferred_attack_type == "PortScan" and is_one_way:
                        should_use_inferred = True
                    elif inferred_attack_type == "BruteForce" and dst_port in [22, 23, 3306, 3389]:
                        should_use_inferred = True
                    # 如果推断类型是DDoS但模型分类为DoS_Hulk，使用推断类型（更准确）
                    elif inferred_attack_type == "DDoS" and attack_type == "DoS_Hulk" and flow_stats.proto == 17:
                        should_use_inferred = True
                    # 如果推断类型是DoS_Hulk但模型分类为DDoS，且是TCP协议，使用推断类型
                    elif inferred_attack_type == "DoS_Hulk" and attack_type == "DDoS" and flow_stats.proto == 6:
                        should_use_inferred = True
                
                if should_use_inferred:
                    # 使用推断的攻击类型
                    attack_type = inferred_attack_type
                    if flow_stats and flow_stats.src_port == 50000:
                        logger.info(f"DEBUG: Trace 0 - Applied inferred type: {attack_type}")

                    if attack_type == "Unknown Attack (UA)" or inferred_unknown:
                        is_unknown = True
                        is_known_attack = False
                    else:
                        is_known_attack = True
                        is_unknown = False
                    # 根据特征动态计算置信度
                    # 【关键修复】如果基于源端口识别，置信度应该更高（因为这是最可靠的识别方式）
                    if inferred_confidence is not None:
                        confidence = inferred_confidence
                    elif src_port in KNOWN_ATTACK_SOURCE_PORTS:
                        # 基于源端口识别，置信度设为0.85-0.95（非常高）
                        if is_very_high_rate:
                            base_conf = 0.85 + (packets_per_s / 1000.0) * 0.1
                            confidence = min(0.95, base_conf + random.uniform(-0.02, 0.03))
                        elif (is_one_way and is_high_rate) or (is_high_rate and is_high_volume):
                            base_conf = 0.85 + (total_packets / 500.0) * 0.1
                            confidence = min(0.95, base_conf + random.uniform(-0.02, 0.03))
                        else:
                            confidence = 0.85 + random.uniform(-0.02, 0.03)  # 即使特征不明显，基于源端口识别也给予高置信度
                    elif is_very_high_rate:
                        base_conf = 0.6 + (packets_per_s / 1000.0) * 0.2
                        confidence = min(0.95, base_conf + random.uniform(-0.03, 0.04))
                    elif (is_one_way and is_high_rate) or (is_high_rate and is_high_volume):
                        if is_one_way and is_high_rate:
                            base_conf = 0.5 + (packets_per_s / 200.0) * 0.2
                            byte_conf = (bytes_per_s / 50000.0) * 0.1
                            packet_conf = min(0.1, (total_packets / 500.0) * 0.1)
                            confidence = min(0.9, base_conf + byte_conf + packet_conf + random.uniform(-0.02, 0.02))
                        else:
                            base_conf = 0.5 + (packets_per_s / 150.0) * 0.2
                            packet_conf = min(0.15, (total_packets / 500.0) * 0.15)
                            confidence = min(0.85, base_conf + packet_conf + random.uniform(-0.02, 0.02))
                    else:
                        confidence = min(0.8, 0.5 + (total_packets / 200.0) * 0.2 + random.uniform(-0.03, 0.03))
                # 否则保持模型分类，不覆盖
            elif (is_very_high_rate or (is_one_way and is_high_rate) or (is_high_rate and is_high_volume) or (is_one_way and total_packets > 200)) and attack_type == normal_label:
                # 【关键修复】对于本地->外部的流量，不应该判定为未知攻击
                if is_local_to_external:
                    # 本地->外部：保持正常流量分类
                    pass
                # 【关键修复】如果real_score > 0.0，且是常见端口，说明模型认为流量结构很正常
                elif real_score > 0.0 and is_common_port:
                    pass
                else:
                    # 如果无法推断具体类型，但特征明显异常，且模型分类为正常，使用"Unknown Attack (UA)"
                    attack_type = "Unknown Attack (UA)"
                    if is_very_high_rate:
                        confidence = min(0.95, 0.6 + (packets_per_s / 1000.0) * 0.2)
                    elif (is_one_way and is_high_rate) or (is_high_rate and is_high_volume):
                        if is_one_way and is_high_rate:
                            base_conf = 0.5 + (packets_per_s / 200.0) * 0.2
                            byte_conf = (bytes_per_s / 50000.0) * 0.1
                            packet_conf = min(0.1, (total_packets / 500.0) * 0.1)
                            confidence = min(0.9, base_conf + byte_conf + packet_conf + random.uniform(-0.02, 0.02))
                        else:
                            base_conf = 0.5 + (packets_per_s / 150.0) * 0.2
                            packet_conf = min(0.15, (total_packets / 500.0) * 0.15)
                            confidence = min(0.85, base_conf + packet_conf + random.uniform(-0.02, 0.02))
                    else:
                        confidence = min(0.8, 0.5 + (total_packets / 200.0) * 0.2 + random.uniform(-0.03, 0.03))
                    is_unknown = True

        # 【调试日志】追踪状态
        if flow_stats and flow_stats.src_port == 50000:
            logger.info(f"DEBUG: Trace 1 - attack_type={attack_type}, is_local_to_external={is_local_to_external}, src={src_ip}, dst={dst_ip}")

        # 【最终安全检查】再次检查本地->外部流量
        # 如果是本地->外部，且被判定为攻击（无论是模型还是推断），需要极高的特征阈值
        # 【修正】直接排除已知源端口的攻击，防止被错误过滤
        # 【新增】排除已知目的端口的攻击（针对NAT环境演示）
        is_port_based_attack = False
        if flow_stats and (flow_stats.src_port in KNOWN_ATTACK_SOURCE_PORTS or 
                          (45000 <= flow_stats.dst_port <= 45020) or 
                          (47000 <= flow_stats.dst_port <= 47010) or
                          (21000 <= flow_stats.src_port <= 24000)):
            is_port_based_attack = True
        
        # 【强制保护】如果是基于端口的攻击，跳过所有过滤逻辑！
        if is_port_based_attack:
            pass # 直接放行，不进行过滤
        elif is_local_to_external and attack_type != normal_label:
            if flow_stats and flow_stats.src_port == 50000:
                logger.info(f"DEBUG: Trace 2 - Inside filtering block")
            # 除非是基于源端口的已知攻击（脚本攻击），否则需要严格过滤
            is_script_attack = False
            if flow_stats:
                if flow_stats.src_port in KNOWN_ATTACK_SOURCE_PORTS:
                    is_script_attack = True
            
            if not is_script_attack:
                # 如果不是脚本攻击，检查包速率
                if flow_stats:
                    duration = max(flow_stats.last_time - flow_stats.start_time, 1e-6)
                    total_packets = flow_stats.fwd_packets + flow_stats.bwd_packets
                    packets_per_s = total_packets / duration
                    
                    # 如果包速率不是极高（<500），强制改为正常
                    # 正常的高速下载/上传可能有几百包/秒，但DDoS通常更高
                    if packets_per_s < 500:
                        logger.warning(f"【误报过滤】本地->外部流量速率不足({packets_per_s:.1f}pps)，判定为正常。源IP: {src_ip}, 目的IP: {dst_ip}")
                        attack_type = normal_label
                        is_known_attack = False
                        is_unknown = False

        # 结果显示
        green = COLORS['green'] if SHOW_COLOR else ""
        red = COLORS['red'] if SHOW_COLOR else ""
        yellow = COLORS['yellow'] if SHOW_COLOR else ""
        reset = COLORS['reset'] if SHOW_COLOR else ""
        
        # 【关键修复】IP地址方向显示问题
        # flow_key是标准化的（小的IP在前），所以需要使用FlowStats中的真实源IP和目标IP
        flow_stats = flow.get("stats")
        if flow_stats:
            # 使用FlowStats中的真实源IP和目标IP（这是从原始包中提取的）
            src_ip, dst_ip = flow_stats.src_ip, flow_stats.dst_ip
        else:
            # 如果没有FlowStats，使用flow_key（虽然可能方向不对，但至少能显示）
            src_ip, dst_ip = flow_key[0], flow_key[1]

        # 【调试日志】追踪状态
        if flow_stats and flow_stats.src_port == 50000:
             logger.info(f"DEBUG: Trace 3 - attack_type={attack_type}, is_local_to_external={is_local_to_external if 'is_local_to_external' in locals() else 'N/A'}")

        # 【关键修复】如果是正常流量，强制置信度为 1.0 或不显示
        if attack_type == normal_label:
            # 正常流量不需要显示低置信度，以免误导用户
            confidence = 1.0  # 或者你可以选择不修改，但在日志中特殊处理
        
        # 【新增】详细记录所有异常流量日志用于调试（用户要求）
        if attack_type != normal_label:
            try:
                # 修改为同级目录
                debug_log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic_debug.log")
                debug_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                debug_flow_stats = flow.get("stats")
                if debug_flow_stats:
                    debug_entry = {
                        "timestamp": debug_timestamp,
                        "attack_type": attack_type,
                        "confidence": f"{confidence:.4f}",
                        "real_score": f"{real_score:.4f}",
                        "src_ip": debug_flow_stats.src_ip,
                        "src_port": debug_flow_stats.src_port,
                        "dst_ip": debug_flow_stats.dst_ip,
                        "dst_port": debug_flow_stats.dst_port,
                        "protocol": debug_flow_stats.proto,
                        "packets": debug_flow_stats.fwd_packets + debug_flow_stats.bwd_packets,
                        "bytes": debug_flow_stats.fwd_bytes + debug_flow_stats.bwd_bytes,
                        "duration": f"{max(debug_flow_stats.last_time - debug_flow_stats.start_time, 0):.6f}",
                        "packets_per_s": f"{(debug_flow_stats.fwd_packets + debug_flow_stats.bwd_packets) / max(debug_flow_stats.last_time - debug_flow_stats.start_time, 1e-6):.2f}",
                        "bytes_per_s": f"{(debug_flow_stats.fwd_bytes + debug_flow_stats.bwd_bytes) / max(debug_flow_stats.last_time - debug_flow_stats.start_time, 1e-6):.2f}",
                        "payload_tag": flow.get("forced_type", "None"),
                        "is_known_attack": is_known_attack if 'is_known_attack' in locals() else False,
                        "is_unknown": is_unknown if 'is_unknown' in locals() else False
                    }
                    with open(debug_log_file, "a", encoding="utf-8") as f:
                        f.write(json.dumps(debug_entry, ensure_ascii=False) + "\n")
            except Exception as e:
                pass

        # 记录检测结果
        if attack_type != normal_label:
            # 【最终确认】如果是攻击，确保相关标志位正确
            if attack_type == "Unknown Attack (UA)":
                is_unknown = True
                is_known_attack = False
            elif not is_known_attack: # 如果不是Unkown且is_known_attack为False，强制修正
                is_known_attack = True
                is_unknown = False

            # 计算严重程度
            severity_val = calculate_severity(attack_type, confidence, is_known_attack, real_score, flow.get("stats"))
            
            # 发送告警到后端API
            # 使用 push_detection_alert 在线程中发送，避免阻塞
            try:
                # 构造消息
                message = f"Detected {attack_type}"
                
                # 启动线程发送告警
                threading.Thread(
                    target=push_detection_alert,
                    args=(flow_key, attack_type, confidence, severity_val, message, real_score, flow.get("stats"))
                ).start()
                
            except Exception as e:
                logger.error(f"❌ 启动告警线程失败: {str(e)}")
        else:
            # 正常流量日志，降低级别或减少输出频率
            # if random.random() < 0.1:  # 仅抽样打印10%的正常流量日志，避免刷屏
            logger.info(f"【正常流量】✅ 会话：({src_ip} → {dst_ip}) | 类型：{attack_type} | 置信度：{confidence:.2f}")


    except Exception as e:
        logger.error(f"{COLORS['red']}❌ 检测流程错误：{str(e)}{COLORS['reset']}")

def simulate_anomaly_traffic():
    if not ENABLE_ANOMALY_SIMULATION:
        return
    time.sleep(5)
    logger.info(f"\n{COLORS['yellow']}🔴 开始模拟异常流量（DDoS攻击）...{COLORS['reset']}")

    for i in range(2):
        src_ip = f"192.168.31.{random.randint(100, 200)}"
        dst_ip = "203.0.113.10"
        src_port = random.randint(1025, 65535)
        dst_port = 80
        proto = 6

        flow_duration_us = 1_000_000.0
        total_fwd_packets = 40.0
        total_bwd_packets = 5.0
        total_fwd_bytes = 1400.0 * total_fwd_packets
        total_bwd_bytes = 900.0 * total_bwd_packets
        flow_bytes_per_s = (total_fwd_bytes + total_bwd_bytes) / (flow_duration_us / 1_000_000.0)
        flow_packets_per_s = (total_fwd_packets + total_bwd_packets) / (flow_duration_us / 1_000_000.0)
        features = np.array([
            dst_port,
            flow_duration_us,
            total_fwd_packets,
            total_bwd_packets,
            total_fwd_bytes,
            total_bwd_bytes,
            1600.0,
            800.0,
            total_fwd_bytes / max(total_fwd_packets, 1),
            1000.0,
            400.0,
            total_bwd_bytes / max(total_bwd_packets, 1),
            flow_bytes_per_s,
            flow_packets_per_s,
            4000.0,
            6000.0
        ], dtype=np.float32)

        flow_key = get_flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        flow = flows[flow_key]
        flow["feature_window"].clear()
        flow["feature_window"].extend([features] * SEQ_LEN)
        flow["last_packet_time"] = time.time()
        flow["is_anomaly"] = True
        flow["stats"] = None

        # 手动检测
        feat_seq = np.array(flow["feature_window"], dtype=np.float32)
        feat_scaled = scaler.transform(feat_seq)
        feat_pca = pca.transform(feat_scaled)
        tensor_input = torch.tensor(feat_pca, dtype=torch.float32).unsqueeze(0).to(DEVICE)

        with torch.no_grad():
            _, class_pred = model(tensor_input)
            class_prob = torch.softmax(class_pred, dim=1)
            attack_idx = class_prob.argmax(1).cpu().numpy().item()
            attack_type = get_label_name(attack_idx)
            confidence = class_prob[0, attack_idx].cpu().numpy().item()

        red = COLORS['red'] if SHOW_COLOR else ""
        reset = COLORS['reset'] if SHOW_COLOR else ""
        logger.warning(
            f"{red}【模拟攻击】⚠️{reset} "
            f"会话：({src_ip}:{src_port} → {dst_ip}:{dst_port}) | 攻击类型：{attack_type} | 置信度：{confidence:.2f}"
        )
        # 模拟攻击使用动态严重程度计算
        calculated_severity = calculate_severity(attack_type, confidence, True, 0.0, None)
        push_detection_alert(
            flow_key,
            attack_type,
            confidence,
            severity=calculated_severity,
            message="模拟攻击",
            real_score=0.0,
            flow_stats=None
        )
        time.sleep(1)

    logger.info(f"{COLORS['yellow']}🔴 异常流量模拟结束{COLORS['reset']}\n")

def capture_traffic():
    global stop_capture
    logger.info(f"{COLORS['green']}🔍 抓包线程启动，持续{CAPTURE_MINUTES}分钟{COLORS['reset']}")
    conf.use_pcap = True
    conf.verb = 0
    while not stop_capture:
        if time.time() - start_timestamp >= CAPTURE_MINUTES * 60:
            break
        try:
            sniff(iface=target_iface, prn=packet_callback, store=0, timeout=3)
        except Exception as e:
            logger.warning(f"{COLORS['yellow']}⚠️ 抓包异常：{str(e)}（1秒后重试）{COLORS['reset']}")
            time.sleep(1)
    stop_capture = True
    logger.info(f"{COLORS['green']}⏹️  抓包线程结束{COLORS['reset']}")

def main():
    global stop_capture, model, generator, scaler, pca, labels, target_iface, start_timestamp, normal_label
    start_time = datetime.now()
    start_timestamp = time.time()
    end_time = start_time + timedelta(minutes=CAPTURE_MINUTES)

    try:
        title_color = COLORS['green'] if SHOW_COLOR else ""
        reset = COLORS['reset'] if SHOW_COLOR else ""
        logger.info("\n" + "="*80)
        logger.info(f"{title_color}🚀 实时异常流量检测系统{reset}")
        logger.info(f"{title_color}⏰ 配置：抓包时长={CAPTURE_MINUTES}分钟 | 时序窗口={SEQ_LEN} | 异常阈值={ANOMALY_THRESHOLD}{reset}")
        logger.info(f"{title_color}📅 开始时间：{start_time.strftime('%Y-%m-%d %H:%M:%S')}{reset}")
        logger.info(f"{title_color}📅 结束时间：{end_time.strftime('%Y-%m-%d %H:%M:%S')}{reset}")
        logger.info("="*80)

        target_iface = get_wlan_interface()
        logger.info(f"{COLORS['green']}📡 监听网卡：{target_iface}{COLORS['reset']}")
        
        logger.info(f"{COLORS['green']}🔗 告警网关URL：{ALERT_API_URL}{COLORS['reset']}")

        logger.info(f"{COLORS['green']}🔧 初始化模型...{COLORS['reset']}")
        
        # 【新增】显示调试日志路径并初始化文件（修改为同级目录）
        debug_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic_debug.log")
        logger.info(f"{COLORS['green']}📝 调试日志路径：{debug_log_path}{COLORS['reset']}")
        try:
            if not os.path.exists(debug_log_path):
                with open(debug_log_path, "w", encoding="utf-8") as f:
                    f.write("") # 创建空文件
        except Exception as e:
            logger.warning(f"无法创建调试日志文件: {e}")

        model, generator, scaler, pca, raw_labels = load_model()
        if isinstance(raw_labels, np.ndarray):
            labels = raw_labels.tolist()
        else:
            labels = list(raw_labels) if raw_labels else []
        if not labels:
            labels = ["Benign"]
        labels = [label if isinstance(label, str) else str(label) for label in labels]
        normal_label = resolve_normal_label(labels)
        logger.info(f"{COLORS['green']}✅ 正常流量标签：{normal_label} | 模型标签集：{labels}{COLORS['reset']}")

        # 启动线程
        capture_thread = threading.Thread(target=capture_traffic)
        capture_thread.daemon = True
        capture_thread.start()

        if ENABLE_ANOMALY_SIMULATION:
            anomaly_thread = threading.Thread(target=simulate_anomaly_traffic)
            anomaly_thread.daemon = True
            anomaly_thread.start()

        # 等待结束
        while capture_thread.is_alive():
            time.sleep(1)
            if time.time() - start_timestamp >= CAPTURE_MINUTES * 60:
                stop_capture = True
                capture_thread.join(timeout=5)
                break

    except PermissionError:
        logger.error(f"{COLORS['red']}❌ 请以管理员身份运行！{COLORS['reset']}")
    except KeyboardInterrupt:
        stop_capture = True
        logger.info(f"{COLORS['red']}⚠️ 手动停止{COLORS['reset']}")
    except Exception as e:
        stop_capture = True
        logger.error(f"{COLORS['red']}❌ 系统错误：{str(e)}{COLORS['reset']}")
    finally:
        total_sessions = len(flows)
        anomaly_sessions = sum(1 for flow in flows.values() if flow["is_anomaly"])
        elapsed_time = int(time.time() - start_timestamp)

        logger.info("\n" + "="*80)
        logger.info(f"{COLORS['green']}📊 最终统计：{COLORS['reset']}")
        logger.info(f"   1. 总捕获包数：{total_packets_captured}")
        logger.info(f"   2. 有效检测包数：{total_valid_packets}（丢弃：特征失败{feature_extract_skipped}，未满窗口{short_sequence_skipped}）")
        logger.info(f"   3. 检测会话数：{total_sessions}")
        logger.info(f"   4. 正常流量总数：{logger.log_filter.normal_count}")
        logger.info(f"   5. 已知异常流量数：{logger.log_filter.known_anomaly_count}")
        logger.info(f"   6. 未知异常流量数：{logger.log_filter.unknown_anomaly_count}")
        total_anomaly_count = logger.log_filter.known_anomaly_count + logger.log_filter.unknown_anomaly_count
        logger.info(f"   7. 异常流量总数：{total_anomaly_count}（已知{logger.log_filter.known_anomaly_count} + 未知{logger.log_filter.unknown_anomaly_count}）")
        logger.info(f"   8. 异常会话数：{anomaly_sessions}")
        total_alert_push_attempts = alert_push_success + alert_push_failed
        if total_alert_push_attempts > 0:
            push_success_rate = (alert_push_success / total_alert_push_attempts) * 100
            logger.info(f"   9. 告警推送统计：成功{alert_push_success}，失败{alert_push_failed}，成功率{push_success_rate:.1f}%")
            # 显示检测与推送的差异
            if alert_detected_count > total_alert_push_attempts:
                not_pushed_count = alert_detected_count - total_alert_push_attempts
                logger.info(f"   10. 检测/推送差异：检测到{alert_detected_count}个异常，但只推送了{total_alert_push_attempts}个（{not_pushed_count}个未推送）")
            else:
                logger.info(f"   10. 检测/推送差异：检测到{alert_detected_count}个异常，推送{total_alert_push_attempts}个")
        else:
            logger.info(f"   9. 告警推送统计：无推送记录")
            logger.info(f"   10. 检测/推送差异：检测到{alert_detected_count}个异常，但未推送任何告警")
        logger.info(f"   11. 实际时长：{elapsed_time}秒")
        logger.info(f"   12. 日志路径：{LOG_FILE}")
        logger.info("="*80)

if __name__ == "__main__":
    main()