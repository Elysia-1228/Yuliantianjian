#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PIDS - 生产级 Linux NIDS (融合优化版)
融合了两个版本的优点：
- 异步告警推送 (避免阻塞)
- 完整的 IAT 计算 (提升 AI 精度)
- DDoS 防重复告警
- 详细的调试日志
"""

import os
import sys
import time
import uuid
import torch
import joblib
import logging
import threading
import warnings
import requests
import numpy as np
import torch.nn as nn
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from scapy.all import sniff, conf, IP, TCP, UDP, Raw
from scapy.interfaces import get_if_list

# ========== 全局配置 ==========
SEQ_LEN = 32
PCA_DIM = 12
FLOW_TIMEOUT = 60
ANOMALY_THRESHOLD = 0.7
NUM_CLASSES = 6
LATENT_DIM = 128

# 路径配置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "transec_gan_model")
PREPROCESS_DIR = os.path.join(BASE_DIR, "preprocessed_data")
MODEL_PATH = os.path.join(MODEL_DIR, "best_model_4x5880_max.pth")
SCALER_PATH = os.path.join(PREPROCESS_DIR, "scaler.pkl")
PCA_PATH = os.path.join(PREPROCESS_DIR, "pca.pkl")
LOG_FILE = os.path.join(BASE_DIR, "nids_production.log")

# Java 后端告警 API (修正为实际端口 8985)
ALERT_API_URL = "http://127.0.0.1:8985/api/analysis/alert"

# 硬件适配
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# ========== ANSI 颜色代码 ==========
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
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
warnings.filterwarnings("ignore")

# ========== DPI 规则库 ==========
ATTACK_SIGNATURES = {
    "SQL Injection": [
        b"UNION SELECT", b"union select",
        b"OR '1'='1", b"or 1=1", b"OR 1=1",
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
    DPI 规则引擎 (优先级最高)
    返回: (attack_type, signature) 或 None
    """
    if not packet.haslayer(Raw):
        return None
    
    try:
        payload = bytes(packet[Raw].load)
        # 忽略过短的包 (减少误报)
        if len(payload) < 10:
            return None
        
        for attack_type, signatures in ATTACK_SIGNATURES.items():
            for sig in signatures:
                if sig in payload:
                    sig_str = sig.decode('utf-8', errors='ignore')[:50]
                    logger.info(f"{Colors.MAGENTA}{Colors.BOLD}🎯 [DPI 规则命中] {attack_type} - 特征: {sig_str}{Colors.RESET}")
                    return (attack_type, sig_str)
        
        return None
    except Exception as e:
        logger.debug(f"Payload 解析异常: {e}")
        return None

# ========== 流量统计 (完整版 IAT 计算) ==========
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
    fwd_prev_time: float = None  # 用于计算 IAT
    bwd_prev_time: float = None
    fwd_iat_sum: float = 0.0
    bwd_iat_sum: float = 0.0
    last_alert_time: float = 0.0  # 防重复告警

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
            fwd_iat_mean * 1e6,  # 完整的 IAT 计算
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

# ========== AI 模型定义 ==========
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
        discriminator.load_state_dict(disc_state_dict, strict=False)
        discriminator.eval()

        scaler = joblib.load(SCALER_PATH)
        pca = joblib.load(PCA_PATH)
        labels = checkpoint.get("label_classes", ["Benign", "DoS", "PortScan", "BruteForce", "WebAttack", "Bot"])

        logger.info(f"{Colors.GREEN}✅ AI 模型加载成功 (设备: {DEVICE}, 支持: {labels}){Colors.RESET}")
        return discriminator, scaler, pca, labels
    except Exception as e:
        logger.warning(f"{Colors.YELLOW}⚠️ AI 模型加载失败，将仅以 DPI 规则模式运行: {e}{Colors.RESET}")
        return None, None, None, None

# ========== 网卡自动识别 ==========
def get_linux_interface():
    try:
        ifaces = get_if_list()
        candidates = [i for i in ifaces if i != "lo"]
        
        if not candidates:
            logger.warning(f"{Colors.YELLOW}⚠️ 未找到可用网卡，使用默认 eth0{Colors.RESET}")
            return "eth0"
        
        for iface in candidates:
            if any(name in iface for name in ["eth", "ens", "enp", "wlan"]):
                logger.info(f"{Colors.GREEN}✅ 自动选择网卡: {iface}{Colors.RESET}")
                return iface
        
        logger.info(f"{Colors.GREEN}✅ 自动选择网卡: {candidates[0]}{Colors.RESET}")
        return candidates[0]
    except Exception as e:
        logger.error(f"{Colors.RED}❌ 网卡识别失败: {e}{Colors.RESET}")
        sys.exit(1)

# ========== 异步告警推送 (避免阻塞) ==========
def push_alert(src_ip, dst_ip, attack_type, confidence, severity, method="DPI", payload_info=""):
    """
    异步推送告警到 Java 后端
    """
    def _send():
        try:
            alert_data = {
                "threatId": str(uuid.uuid4()),
                "threatLevel": severity,
                "impactScope": f"{attack_type} | {src_ip} -> {dst_ip}",
                "occurTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "createTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "sourceIp": src_ip,
                "targetIp": dst_ip,
                "attackType": attack_type,
                "confidence": round(confidence, 2),
                "detectionMethod": method,
                "message": f"{method} 检测到攻击特征: {payload_info}" if payload_info else f"{method} 检测"
            }
            
            response = requests.post(ALERT_API_URL, json=alert_data, timeout=2)
            if response.status_code == 200:
                logger.debug(f"✅ 告警已推送: {attack_type} ({src_ip} → {dst_ip})")
            else:
                logger.warning(f"⚠️ 告警推送失败 (HTTP {response.status_code})")
        except requests.exceptions.RequestException as e:
            logger.debug(f"告警推送异常: {e}")
    
    # 异步发送，不阻塞抓包主线程
    threading.Thread(target=_send, daemon=True).start()

# ========== 核心检测逻辑 ==========
discriminator, scaler, pca, labels = load_model()
packet_count = 0
alert_count = 0

def packet_callback(packet):
    global packet_count, alert_count
    packet_count += 1
    
    try:
        if not packet.haslayer(IP):
            return
        
        ip = packet[IP]
        src_ip, dst_ip = str(ip.src), str(ip.dst)
        proto = int(ip.proto)
        src_port, dst_port = 0, 0
        
        if proto == 6 and packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port = int(tcp.sport) if tcp.sport else 0
            dst_port = int(tcp.dport) if tcp.dport else 0
        elif proto == 17 and packet.haslayer(UDP):
            udp = packet[UDP]
            src_port = int(udp.sport) if udp.sport else 0
            dst_port = int(udp.dport) if udp.dport else 0
        else:
            return
        
        # ========== 第一层：DPI 规则检测 ==========
        rule_result = detect_by_payload(packet)
        if rule_result:
            attack_type, sig = rule_result
            severity = 5  # 规则命中视为高危
            alert_count += 1
            
            logger.warning(
                f"{Colors.RED}{Colors.BOLD}🚨 [高危攻击] {attack_type} | "
                f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                f"置信度: 1.00 | 方法: DPI 规则{Colors.RESET}"
            )
            
            push_alert(src_ip, dst_ip, attack_type, 1.0, severity, method="DPI", payload_info=sig)
            return
        
        # ========== 第二层：流量特征检测 ==========
        flow_key = get_flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        flow = flows[flow_key]
        flow["last_packet_time"] = time.time()
        
        if flow["stats"] is None:
            now = time.time()
            flow["stats"] = FlowStats(
                src_ip=src_ip, src_port=src_port,
                dst_ip=dst_ip, dst_port=dst_port,
                proto=proto, start_time=now, last_time=now
            )
        
        pkt_len = len(packet)
        features = flow["stats"].update(src_ip, src_port, dst_ip, dst_port, pkt_len, time.time())
        flow["feature_window"].append(features)
        
        # DDoS 检测 (带防重复告警)
        duration = max(flow["stats"].last_time - flow["stats"].start_time, 1e-6)
        total_packets = flow["stats"].fwd_packets + flow["stats"].bwd_packets
        packets_per_s = total_packets / duration
        
        if packets_per_s > 2000:
            # 防止同一流 10 秒内重复告警
            now = time.time()
            if now - flow["stats"].last_alert_time > 10:
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
                flow["stats"].last_alert_time = now
            return
        
        # ========== 第三层：AI 模型检测 ==========
        if discriminator and len(flow["feature_window"]) >= SEQ_LEN:
            try:
                seq_features = np.array(list(flow["feature_window"]))
                seq_scaled = scaler.transform(seq_features)
                seq_pca = pca.transform(seq_scaled)
                seq_tensor = torch.tensor(seq_pca, dtype=torch.float32).unsqueeze(0).to(DEVICE)
                
                with torch.no_grad():
                    real_pred, class_pred = discriminator(seq_tensor)
                    real_score = torch.sigmoid(real_pred).item()
                    class_probs = torch.softmax(class_pred, dim=1).cpu().numpy()[0]
                    predicted_class = int(np.argmax(class_probs))
                    max_prob = float(class_probs[predicted_class])
                
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
    logger.info(f"{Colors.BOLD}{Colors.CYAN}🛡️  PIDS - 生产级 Linux NIDS (融合优化版){Colors.RESET}")
    logger.info(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
    
    interface = get_linux_interface()
    
    logger.info(f"{Colors.GREEN}📡 监听网卡: {interface}{Colors.RESET}")
    logger.info(f"{Colors.GREEN}🎯 告警推送: {ALERT_API_URL}{Colors.RESET}")
    logger.info(f"{Colors.GREEN}🔍 检测策略: DPI 规则 → 流量分析 → AI 模型{Colors.RESET}")
    logger.info(f"{Colors.GREEN}⚡ 优化特性: 异步告警 + 完整IAT + 防重复{Colors.RESET}")
    logger.info(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")
    
    try:
        conf.verb = 0  # 关闭 Scapy 详细输出
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
