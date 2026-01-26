#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PIDS - 生产级 Linux NIDS (Network Intrusion Detection System)
核心特性：
1. DPI 规则引擎 (Deep Packet Inspection) - 基于 Payload 特征精确检测
2. AI 模型兜底 (TransEC-GAN) - 检测未知威胁
3. 自动网卡识别 (Linux 环境)
4. 实时告警推送到 Java 后端
"""

import logging
import os
import sys
import time
import re
import requests
import torch
import numpy as np
import joblib
from collections import defaultdict, deque
from dataclasses import dataclass
from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.interfaces import get_if_list

# ========== 全局配置 ==========
SEQ_LEN = 32
PCA_DIM = 12
FEATURE_DIM = 16
FLOW_TIMEOUT = 60
ANOMALY_THRESHOLD = 0.7
NUM_CLASSES = 6
LATENT_DIM = 128

# 路径配置
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(_BASE_DIR, "transec_gan_model")
PREPROCESS_DIR = os.path.join(_BASE_DIR, "preprocessed_data")
MODEL_PATH = os.path.join(MODEL_DIR, "best_model_4x5880_max.pth")
SCALER_PATH = os.path.join(PREPROCESS_DIR, "scaler.pkl")
PCA_PATH = os.path.join(PREPROCESS_DIR, "pca.pkl")
LOG_FILE = os.path.join(_BASE_DIR, "ids_linux.log")

# Java 后端告警 API (修正为实际端口 8985)
ALERT_API_URL = "http://127.0.0.1:8985/api/analysis/alert"

# 硬件适配
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# ========== ANSI 颜色代码 (Linux 终端支持) ==========
class Colors:
    RED = '\033[91m'      # 高危攻击
    YELLOW = '\033[93m'   # 未知攻击
    GREEN = '\033[92m'    # 正常流量
    BLUE = '\033[94m'     # 信息
    MAGENTA = '\033[95m'  # DPI 规则命中
    CYAN = '\033[96m'     # AI 检测
    BOLD = '\033[1m'
    RESET = '\033[0m'

# ========== 日志配置 ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ========== DPI 规则库 (核心!) ==========
ATTACK_SIGNATURES = {
    "SQL Injection": [
        b"UNION SELECT", b"union select",
        b"OR '1'='1", b"or 1=1",
        b"sleep(", b"SLEEP(",
        b"information_schema", b"INFORMATION_SCHEMA",
        b"' OR ", b"\" OR ",
        b"'; DROP TABLE", b"; DROP TABLE"
    ],
    "XSS Attack": [
        b"<script>", b"<SCRIPT>",
        b"javascript:", b"JAVASCRIPT:",
        b"onerror=", b"onload=",
        b"alert(", b"prompt(",
        b"document.cookie"
    ],
    "Webshell/RCE": [
        b"eval(", b"EVAL(",
        b"system(", b"exec(",
        b"cmd.exe", b"CMD.EXE",
        b"/bin/sh", b"/bin/bash",
        b"whoami", b"WHOAMI",
        b"base64_decode", b"shell_exec",
        b"<?php", b"passthru("
    ],
    "Path Traversal": [
        b"../", b"..\\",
        b"/etc/passwd", b"/etc/shadow",
        b"C:\\Windows\\System32",
        b"../../../../"
    ],
    "Port Scanning": [
        b"Nmap", b"nmap",
        b"masscan", b"MASSCAN",
        b"hydra", b"HYDRA",
        b"nikto", b"sqlmap"
    ]
}

def detect_by_payload(packet):
    """
    第一层检测：基于 Payload 的 DPI 规则引擎
    返回: (attack_type, confidence) 或 None
    """
    if not packet.haslayer(Raw):
        return None
    
    try:
        payload = bytes(packet[Raw].load)
        # 忽略过短的包 (避免误报)
        if len(payload) < 10:
            return None
        
        # 遍历规则库
        for attack_type, signatures in ATTACK_SIGNATURES.items():
            for sig in signatures:
                if sig in payload:
                    # 规则命中，置信度设为 1.0 (实锤)
                    logger.info(f"{Colors.MAGENTA}{Colors.BOLD}🎯 [DPI 规则命中] {attack_type} - 特征: {sig.decode('utf-8', errors='ignore')[:50]}{Colors.RESET}")
                    return (attack_type, 1.0)
        
        return None
    except Exception as e:
        logger.debug(f"Payload 解析异常: {e}")
        return None

# ========== 流量统计数据结构 ==========
@dataclass
class FlowStats:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: int
    start_time: float
    last_time: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: float = 0.0
    bwd_bytes: float = 0.0
    fwd_len_max: float = 0.0
    fwd_len_min: float = float("inf")
    fwd_len_sum: float = 0.0
    bwd_len_max: float = 0.0
    bwd_len_min: float = float("inf")
    bwd_len_sum: float = 0.0
    fwd_prev_time: float = None
    bwd_prev_time: float = None
    fwd_iat_sum: float = 0.0
    bwd_iat_sum: float = 0.0

    def update(self, src_ip, src_port, dst_ip, dst_port, pkt_len, timestamp):
        direction_forward = (src_ip == self.src_ip and src_port == self.src_port)
        if self.start_time is None:
            self.start_time = timestamp
        self.last_time = timestamp

        if direction_forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt_len
            self.fwd_len_max = max(self.fwd_len_max, pkt_len)
            self.fwd_len_min = min(self.fwd_len_min, pkt_len)
            self.fwd_len_sum += pkt_len
            if self.fwd_prev_time is not None:
                self.fwd_iat_sum += timestamp - self.fwd_prev_time
            self.fwd_prev_time = timestamp
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt_len
            self.bwd_len_max = max(self.bwd_len_max, pkt_len)
            self.bwd_len_min = min(self.bwd_len_min, pkt_len)
            self.bwd_len_sum += pkt_len
            if self.bwd_prev_time is not None:
                self.bwd_iat_sum += timestamp - self.bwd_prev_time
            self.bwd_prev_time = timestamp

        return self.to_feature_vector()

    def to_feature_vector(self):
        duration = max((self.last_time - self.start_time) if self.start_time else 0.0, 1e-6)
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes

        def safe_mean(sum_val, count):
            return float(sum_val) / count if count > 0 else 0.0
        def safe_min(val):
            return 0.0 if val == float("inf") else val

        fwd_iat_mean = safe_mean(self.fwd_iat_sum, max(self.fwd_packets - 1, 1)) if self.fwd_packets > 1 else 0.0
        bwd_iat_mean = safe_mean(self.bwd_iat_sum, max(self.bwd_packets - 1, 1)) if self.bwd_packets > 1 else 0.0

        return np.array([
            self.dst_port,
            duration * 1e6,
            float(self.fwd_packets),
            float(self.bwd_packets),
            float(self.fwd_bytes),
            float(self.bwd_bytes),
            self.fwd_len_max,
            safe_min(self.fwd_len_min),
            safe_mean(self.fwd_len_sum, self.fwd_packets if self.fwd_packets else 1),
            self.bwd_len_max,
            safe_min(self.bwd_len_min),
            safe_mean(self.bwd_len_sum, self.bwd_packets if self.bwd_packets else 1),
            float(total_bytes) / duration,
            float(total_packets) / duration,
            fwd_iat_mean * 1e6,
            bwd_iat_mean * 1e6
        ], dtype=np.float32)

# 全局流量存储
def get_flow_key(src_ip, dst_ip, src_port, dst_port, proto):
    if (src_ip, src_port) > (dst_ip, dst_port):
        return (dst_ip, src_ip, dst_port, src_port, proto)
    return (src_ip, dst_ip, src_port, dst_port, proto)

flows = defaultdict(lambda: {
    "feature_window": deque(maxlen=SEQ_LEN),
    "last_packet_time": time.time(),
    "stats": None
})

# ========== AI 模型定义 (TransEC-GAN) ==========
import torch.nn as nn

class TransformerEncoder(nn.Module):
    def __init__(self, input_dim, d_model=128, nhead=8, num_layers=4):
        super().__init__()
        self.linear = nn.Linear(input_dim, d_model)
        self.pos_encoder = nn.Embedding(SEQ_LEN, d_model)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=256,
            activation="gelu", batch_first=True, norm_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

    def forward(self, x):
        batch_size, seq_len = x.shape[0], x.shape[1]
        x = self.linear(x)
        pos = torch.arange(seq_len, device=x.device).repeat(batch_size, 1)
        x = x + self.pos_encoder(pos)
        return self.transformer(x).mean(dim=1)

class Discriminator(nn.Module):
    def __init__(self):
        super().__init__()
        self.transformer = TransformerEncoder(input_dim=PCA_DIM, d_model=128)
        self.real_fc = nn.Linear(128, 1)
        self.class_fc = nn.Linear(128, NUM_CLASSES)

    def forward(self, x):
        x = self.transformer(x)
        real_pred = self.real_fc(x)
        class_pred = self.class_fc(x)
        return real_pred, class_pred

# ========== 模型加载 ==========
def load_model():
    try:
        checkpoint = torch.load(MODEL_PATH, map_location=DEVICE, weights_only=False)
        disc_state_dict = checkpoint["discriminator_state_dict"]
        if next(iter(disc_state_dict.keys())).startswith("module."):
            disc_state_dict = {k.replace("module.", ""): v for k, v in disc_state_dict.items()}
        
        discriminator = Discriminator().to(DEVICE)
        discriminator.load_state_dict(disc_state_dict, strict=True)
        discriminator.eval()

        scaler = joblib.load(SCALER_PATH)
        pca = joblib.load(PCA_PATH)
        labels = checkpoint["label_classes"]

        logger.info(f"{Colors.GREEN}✅ TransEC-GAN 模型加载成功 (设备: {DEVICE}){Colors.RESET}")
        return discriminator, scaler, pca, labels
    except Exception as e:
        logger.error(f"{Colors.RED}❌ 模型加载失败: {e}{Colors.RESET}")
        sys.exit(1)

# ========== 网卡自动识别 (Linux) ==========
def get_linux_interface():
    try:
        ifaces = get_if_list()
        # 排除回环接口
        candidates = [i for i in ifaces if i != "lo"]
        
        if not candidates:
            logger.warning(f"{Colors.YELLOW}⚠️ 未找到可用网卡，使用默认 eth0{Colors.RESET}")
            return "eth0"
        
        # 优先选择常见网卡名
        for iface in candidates:
            if any(name in iface for name in ["eth", "ens", "enp", "wlan"]):
                logger.info(f"{Colors.GREEN}✅ 自动选择网卡: {iface}{Colors.RESET}")
                return iface
        
        # 否则返回第一个
        logger.info(f"{Colors.GREEN}✅ 自动选择网卡: {candidates[0]}{Colors.RESET}")
        return candidates[0]
    except Exception as e:
        logger.error(f"{Colors.RED}❌ 网卡识别失败: {e}{Colors.RESET}")
        sys.exit(1)

# ========== 告警推送 ==========
def push_alert(src_ip, dst_ip, attack_type, confidence, severity, method="DPI"):
    """
    推送告警到 Java 后端
    """
    try:
        payload = {
            "sourceIp": src_ip,
            "targetIp": dst_ip,
            "attackType": attack_type,
            "confidence": round(confidence, 2),
            "severity": severity,
            "detectionMethod": method,
            "timestamp": int(time.time() * 1000)
        }
        
        response = requests.post(ALERT_API_URL, json=payload, timeout=2)
        if response.status_code == 200:
            logger.debug(f"✅ 告警已推送: {attack_type} ({src_ip} → {dst_ip})")
        else:
            logger.warning(f"⚠️ 告警推送失败 (HTTP {response.status_code})")
    except requests.exceptions.RequestException as e:
        logger.debug(f"告警推送异常: {e}")

# ========== 核心检测逻辑 ==========
discriminator, scaler, pca, labels = load_model()
packet_count = 0
alert_count = 0

def packet_callback(packet):
    global packet_count, alert_count
    packet_count += 1
    
    try:
        # 只处理 IP 包
        if not packet.haslayer(IP):
            return
        
        ip = packet[IP]
        src_ip, dst_ip = str(ip.src), str(ip.dst)
        proto = int(ip.proto)
        src_port, dst_port = 0, 0
        
        # 提取端口号
        if proto == 6 and packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port = int(tcp.sport) if tcp.sport else 0
            dst_port = int(tcp.dport) if tcp.dport else 0
        elif proto == 17 and packet.haslayer(UDP):
            udp = packet[UDP]
            src_port = int(udp.sport) if udp.sport else 0
            dst_port = int(udp.dport) if udp.dport else 0
        else:
            return  # 忽略其他协议
        
        # ========== 第一层：DPI 规则检测 (优先级最高) ==========
        rule_result = detect_by_payload(packet)
        if rule_result:
            attack_type, confidence = rule_result
            severity = 5  # 规则命中视为高危
            alert_count += 1
            
            logger.warning(
                f"{Colors.RED}{Colors.BOLD}🚨 [高危攻击] {attack_type} | "
                f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                f"置信度: {confidence:.2f} | 方法: DPI 规则{Colors.RESET}"
            )
            
            push_alert(src_ip, dst_ip, attack_type, confidence, severity, method="DPI")
            return  # 规则命中后直接返回，不再走后续检测
        
        # ========== 第二层：流量特征检测 (DDoS/Flood) ==========
        flow_key = get_flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        flow = flows[flow_key]
        flow["last_packet_time"] = time.time()
        
        # 初始化流统计
        if flow["stats"] is None:
            now = time.time()
            flow["stats"] = FlowStats(
                src_ip=src_ip, src_port=src_port,
                dst_ip=dst_ip, dst_port=dst_port,
                proto=proto, start_time=now, last_time=now
            )
        
        # 更新流特征
        pkt_len = len(packet)
        features = flow["stats"].update(src_ip, src_port, dst_ip, dst_port, pkt_len, time.time())
        flow["feature_window"].append(features)
        
        # 计算流量速率
        duration = max(flow["stats"].last_time - flow["stats"].start_time, 1e-6)
        total_packets = flow["stats"].fwd_packets + flow["stats"].bwd_packets
        packets_per_s = total_packets / duration
        
        # 高速率流量判定为 DDoS
        if packets_per_s > 2000:
            attack_type = "DDoS Flood"
            confidence = min(0.95, 0.7 + (packets_per_s / 5000) * 0.25)
            severity = 5
            alert_count += 1
            
            logger.warning(
                f"{Colors.RED}{Colors.BOLD}🚨 [DDoS 攻击] {attack_type} | "
                f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                f"速率: {packets_per_s:.0f} pkt/s | 置信度: {confidence:.2f}{Colors.RESET}"
            )
            
            push_alert(src_ip, dst_ip, attack_type, confidence, severity, method="Flow Analysis")
            return
        
        # ========== 第三层：AI 模型检测 (未知威胁) ==========
        if len(flow["feature_window"]) >= SEQ_LEN:
            try:
                # 准备序列数据
                seq_features = np.array(list(flow["feature_window"]))
                seq_scaled = scaler.transform(seq_features)
                seq_pca = pca.transform(seq_scaled)
                seq_tensor = torch.tensor(seq_pca, dtype=torch.float32).unsqueeze(0).to(DEVICE)
                
                # AI 推理
                with torch.no_grad():
                    real_pred, class_pred = discriminator(seq_tensor)
                    real_score = torch.sigmoid(real_pred).item()
                    class_probs = torch.softmax(class_pred, dim=1).cpu().numpy()[0]
                    predicted_class = int(np.argmax(class_probs))
                    max_prob = float(class_probs[predicted_class])
                
                # 判断是否为异常
                if real_score < ANOMALY_THRESHOLD and predicted_class > 0:
                    attack_type = labels[predicted_class] if predicted_class < len(labels) else "Unknown Attack"
                    confidence = max_prob
                    severity = 4 if "Unknown" in attack_type else 3
                    alert_count += 1
                    
                    logger.warning(
                        f"{Colors.YELLOW}{Colors.BOLD}⚠️ [AI 检测] {attack_type} | "
                        f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                        f"置信度: {confidence:.2f} | OOD分数: {real_score:.2f}{Colors.RESET}"
                    )
                    
                    push_alert(src_ip, dst_ip, attack_type, confidence, severity, method="AI Model")
            
            except Exception as e:
                logger.debug(f"AI 推理异常: {e}")
        
        # 定期清理超时流
        if packet_count % 1000 == 0:
            clean_timeout_flows()
            logger.info(f"{Colors.BLUE}📊 已处理 {packet_count} 个数据包 | 检测到 {alert_count} 个威胁{Colors.RESET}")
    
    except Exception as e:
        logger.error(f"数据包处理异常: {e}")

def clean_timeout_flows():
    now = time.time()
    timeout_count = 0
    for key, flow in list(flows.items()):
        if now - flow["last_packet_time"] > FLOW_TIMEOUT:
            del flows[key]
            timeout_count += 1
    if timeout_count > 0:
        logger.debug(f"清理超时流: {timeout_count} 个")

# ========== 主函数 ==========
def main():
    logger.info(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    logger.info(f"{Colors.BOLD}{Colors.CYAN}🛡️  PIDS - 生产级 Linux NIDS 启动中...{Colors.RESET}")
    logger.info(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    
    # 获取网卡
    interface = get_linux_interface()
    
    logger.info(f"{Colors.GREEN}📡 监听网卡: {interface}{Colors.RESET}")
    logger.info(f"{Colors.GREEN}🎯 告警推送: {ALERT_API_URL}{Colors.RESET}")
    logger.info(f"{Colors.GREEN}🔍 检测策略: DPI 规则 → 流量分析 → AI 模型{Colors.RESET}")
    logger.info(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")
    
    try:
        # 开始抓包
        sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        logger.info(f"\n{Colors.YELLOW}⏹️  检测已停止{Colors.RESET}")
        logger.info(f"{Colors.BLUE}📊 总计处理: {packet_count} 个数据包{Colors.RESET}")
        logger.info(f"{Colors.RED}🚨 检测威胁: {alert_count} 个{Colors.RESET}")
    except Exception as e:
        logger.error(f"{Colors.RED}❌ 运行异常: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
