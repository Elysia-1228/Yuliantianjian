import logging
import os
import json
import math
import torch
import torch.nn as nn
import numpy as np
import warnings
import joblib
from scapy.layers.inet import IP, TCP, UDP
from collections import defaultdict, deque
import time
from dataclasses import dataclass, field
from typing import Union

# ========== 全局配置（与 CICIDS2017 训练对齐） ==========
SEQ_LEN = 32        # 时序窗口长度
PCA_DIM = 25         # PCA降维维度（95.6%方差）
FEATURE_DIM = 78     # CICIDS2017 原始特征维度
FLOW_TIMEOUT = 60

ANOMALY_THRESHOLD = 0.65  # OOD检测阈值（训练集real_score均值0.876，std=0.124）
NUM_CLASSES = 8      # 8类：Benign + 7种攻击
LATENT_DIM = 128     # 生成器噪声维度

CLASS_NAMES = ['Benign', 'BruteForce', 'DoS', 'WebAttack', 'Infiltration', 'Bot', 'PortScan', 'DDoS']

# 路径配置（基于当前文件位置）
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(_BASE_DIR, "TransEC-GAN-models")
PREPROCESS_DIR = os.path.join(_BASE_DIR, "preprocessed_data")
MODEL_PATH = os.path.join(MODEL_DIR, "best_model_4x5880_max.pth")
SCALER_PATH = os.path.join(PREPROCESS_DIR, "scaler.pkl")
PCA_PATH = os.path.join(PREPROCESS_DIR, "pca.pkl")
LABEL_PATH = os.path.join(PREPROCESS_DIR, "label_encoder.npy")
LOG_FILE = os.path.join(_BASE_DIR, "ids_detection.log")

# 颜色常量
COLORS = {
    "green": "\033[32m",    # 正常流量
    "red": "\033[31m",      # 已知攻击
    "yellow": "\033[33m",   # 未知攻击
    "reset": "\033[0m",     # 重置颜色
    "default": "\033[0m"
}

# 日志过滤器
class LogFilter:
    def __init__(self):
        self.normal_count = 0
        self.known_anomaly_count = 0
        self.unknown_anomaly_count = 0

    def filter(self, record):
        msg = record.getMessage()
        # 【关键修复】匹配更灵活的格式，支持"【🔴 高危告警 - 已知攻击】"等格式
        # 使用更宽松的匹配，只要包含关键字符串就计数
        if "已知攻击" in msg or "【🔴 高危告警 - 已知攻击】" in msg:
            self.known_anomaly_count += 1
        elif "未知攻击" in msg or "【🔴 高危告警 - 未知攻击】" in msg or "Unknown Attack" in msg:
            self.unknown_anomaly_count += 1
        elif "【正常流量】" in msg or "正常流量" in msg:
            self.normal_count += 1
        elif "【模拟攻击】" in msg or "模拟攻击" in msg:
            self.known_anomaly_count += 1
        elif "📊 最终统计：" in msg:
            record.msg = record.msg.replace("正常流量总数=", f"正常流量总数={self.normal_count}")
            record.msg = record.msg.replace("已知异常流量数=", f"已知异常流量数={self.known_anomaly_count}")
            record.msg = record.msg.replace("未知异常流量数=", f"未知异常流量数={self.unknown_anomaly_count}")
        return True

# 日志初始化
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.handlers.clear()
file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8", mode="a")
file_handler.setLevel(logging.INFO)
log_filter = LogFilter()
file_handler.addFilter(log_filter)
file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(file_formatter)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(console_formatter)
logger.addHandler(file_handler)
logger.addHandler(console_handler)
logger.log_filter = log_filter

warnings.filterwarnings("ignore")

# 硬件适配
DEVICE = "cuda" if (torch.cuda.is_available() and os.environ.get("USE_CUDA", "1") == "1") else "cpu"
logger.info(f"{COLORS['default']}🖥️  运行设备：{DEVICE}{COLORS['reset']}")

# 全局流量存储
def get_flow_key(src_ip, dst_ip, src_port, dst_port, proto):
    if (src_ip, src_port) > (dst_ip, dst_port):
        return (dst_ip, src_ip, dst_port, src_port, proto)
    return (src_ip, dst_ip, src_port, dst_port, proto)

@dataclass
class FlowStats:
    """78维流特征统计（对齐 CICIDS2017 CICFlowMeter 输出）"""
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
    fwd_len_sq_sum: float = 0.0
    bwd_len_max: float = 0.0
    bwd_len_min: float = float("inf")
    bwd_len_sum: float = 0.0
    bwd_len_sq_sum: float = 0.0
    all_len_min: float = float("inf")
    all_len_max: float = 0.0
    all_len_sum: float = 0.0
    all_len_sq_sum: float = 0.0
    fwd_prev_time: float = None
    bwd_prev_time: float = None
    flow_prev_time: float = None
    fwd_iat_list: list = field(default_factory=list)
    bwd_iat_list: list = field(default_factory=list)
    flow_iat_list: list = field(default_factory=list)
    fwd_psh_flags: int = 0
    bwd_psh_flags: int = 0
    fwd_urg_flags: int = 0
    bwd_urg_flags: int = 0
    fwd_header_len: float = 0.0
    bwd_header_len: float = 0.0
    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    cwe_count: int = 0
    ece_count: int = 0
    init_win_fwd: int = -1
    init_win_bwd: int = -1
    act_data_pkt_fwd: int = 0
    min_seg_size_fwd: float = float("inf")
    active_times: list = field(default_factory=list)
    idle_times: list = field(default_factory=list)
    last_active_time: float = None

    def update(self, src_ip, src_port, dst_ip, dst_port, pkt_len, timestamp, packet=None):
        is_fwd = (src_ip == self.src_ip and src_port == self.src_port and
                  dst_ip == self.dst_ip and dst_port == self.dst_port)
        if self.start_time is None:
            self.start_time = timestamp
        self.last_time = timestamp

        if self.flow_prev_time is not None:
            flow_iat = timestamp - self.flow_prev_time
            self.flow_iat_list.append(flow_iat)
            if flow_iat > 1.0:
                if self.last_active_time is not None:
                    self.idle_times.append(flow_iat)
                self.last_active_time = timestamp
            else:
                if self.last_active_time is not None:
                    active_dur = timestamp - self.last_active_time
                    if active_dur > 0:
                        self.active_times.append(active_dur)
                else:
                    self.last_active_time = timestamp
        else:
            self.last_active_time = timestamp
        self.flow_prev_time = timestamp

        self.all_len_min = min(self.all_len_min, pkt_len)
        self.all_len_max = max(self.all_len_max, pkt_len)
        self.all_len_sum += pkt_len
        self.all_len_sq_sum += pkt_len * pkt_len

        if packet is not None:
            self._update_flags(packet, is_fwd)

        if is_fwd:
            self._update_fwd(pkt_len, timestamp, packet)
        else:
            self._update_bwd(pkt_len, timestamp, packet)

        return self.to_feature_vector()

    def _update_flags(self, packet, is_fwd):
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = tcp.flags if hasattr(tcp, 'flags') else 0
            if isinstance(flags, str):
                flags = sum({'F':1,'S':2,'R':4,'P':8,'A':16,'U':32,'E':64,'C':128}.get(c,0) for c in flags)
            if flags & 0x01: self.fin_count += 1
            if flags & 0x02: self.syn_count += 1
            if flags & 0x04: self.rst_count += 1
            if flags & 0x08:
                self.psh_count += 1
                if is_fwd: self.fwd_psh_flags += 1
                else: self.bwd_psh_flags += 1
            if flags & 0x10: self.ack_count += 1
            if flags & 0x20:
                self.urg_count += 1
                if is_fwd: self.fwd_urg_flags += 1
                else: self.bwd_urg_flags += 1
            if flags & 0x40: self.ece_count += 1
            if flags & 0x80: self.cwe_count += 1
            if is_fwd and self.init_win_fwd == -1:
                self.init_win_fwd = int(tcp.window) if hasattr(tcp, 'window') else 0
            elif not is_fwd and self.init_win_bwd == -1:
                self.init_win_bwd = int(tcp.window) if hasattr(tcp, 'window') else 0

    def _update_fwd(self, pkt_len, timestamp, packet=None):
        self.fwd_packets += 1
        self.fwd_bytes += pkt_len
        self.fwd_len_max = max(self.fwd_len_max, pkt_len)
        self.fwd_len_min = min(self.fwd_len_min, pkt_len)
        self.fwd_len_sum += pkt_len
        self.fwd_len_sq_sum += pkt_len * pkt_len
        if self.fwd_prev_time is not None:
            self.fwd_iat_list.append(timestamp - self.fwd_prev_time)
        self.fwd_prev_time = timestamp
        if packet is not None:
            hdr_len = 0
            if packet.haslayer(IP): hdr_len += packet[IP].ihl * 4
            if packet.haslayer(TCP): hdr_len += packet[TCP].dataofs * 4 if packet[TCP].dataofs else 20
            elif packet.haslayer(UDP): hdr_len += 8
            self.fwd_header_len += hdr_len
            self.min_seg_size_fwd = min(self.min_seg_size_fwd, hdr_len) if hdr_len > 0 else self.min_seg_size_fwd
            payload_len = pkt_len - hdr_len
            if payload_len > 0:
                self.act_data_pkt_fwd += 1

    def _update_bwd(self, pkt_len, timestamp, packet=None):
        self.bwd_packets += 1
        self.bwd_bytes += pkt_len
        self.bwd_len_max = max(self.bwd_len_max, pkt_len)
        self.bwd_len_min = min(self.bwd_len_min, pkt_len)
        self.bwd_len_sum += pkt_len
        self.bwd_len_sq_sum += pkt_len * pkt_len
        if self.bwd_prev_time is not None:
            self.bwd_iat_list.append(timestamp - self.bwd_prev_time)
        self.bwd_prev_time = timestamp
        if packet is not None:
            hdr_len = 0
            if packet.haslayer(IP): hdr_len += packet[IP].ihl * 4
            if packet.haslayer(TCP): hdr_len += packet[TCP].dataofs * 4 if packet[TCP].dataofs else 20
            elif packet.haslayer(UDP): hdr_len += 8
            self.bwd_header_len += hdr_len

    def to_feature_vector(self):
        """生成与 CICIDS2017 对齐的 78 维特征向量"""
        duration = max((self.last_time - self.start_time) if self.start_time else 0.0, 1e-6)
        duration_us = duration * 1e6
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes

        def _mean(lst): return float(np.mean(lst)) if lst else 0.0
        def _std(lst): return float(np.std(lst)) if len(lst) > 1 else 0.0
        def _max(lst): return float(max(lst)) if lst else 0.0
        def _min(lst): return float(min(lst)) if lst else 0.0
        def _safe_min(v): return 0.0 if v == float("inf") else float(v)
        def _safe_div(a, b): return float(a) / b if b > 0 else 0.0
        def _var(sq_sum, s, n): return max(sq_sum / n - (s / n) ** 2, 0.0) if n > 0 else 0.0
        def _std_from_var(sq_sum, s, n): return math.sqrt(_var(sq_sum, s, n))

        fwd_iat_us = [x * 1e6 for x in self.fwd_iat_list]
        bwd_iat_us = [x * 1e6 for x in self.bwd_iat_list]
        flow_iat_us = [x * 1e6 for x in self.flow_iat_list]

        fwd_pkt_mean = _safe_div(self.fwd_len_sum, self.fwd_packets)
        fwd_pkt_std = _std_from_var(self.fwd_len_sq_sum, self.fwd_len_sum, self.fwd_packets)
        bwd_pkt_mean = _safe_div(self.bwd_len_sum, self.bwd_packets)
        bwd_pkt_std = _std_from_var(self.bwd_len_sq_sum, self.bwd_len_sum, self.bwd_packets)
        all_pkt_mean = _safe_div(self.all_len_sum, total_packets)
        all_pkt_std = _std_from_var(self.all_len_sq_sum, self.all_len_sum, total_packets)
        all_pkt_var = _var(self.all_len_sq_sum, self.all_len_sum, total_packets)

        down_up = _safe_div(self.bwd_packets, self.fwd_packets) if self.fwd_packets > 0 else 0.0
        avg_pkt_size = _safe_div(total_bytes, total_packets)

        active_us = [x * 1e6 for x in self.active_times]
        idle_us = [x * 1e6 for x in self.idle_times]

        return np.array([
            float(self.dst_port),                                   #  0 Destination Port
            duration_us,                                            #  1 Flow Duration
            float(self.fwd_packets),                                #  2 Total Fwd Packets
            float(self.bwd_packets),                                #  3 Total Backward Packets
            float(self.fwd_bytes),                                  #  4 Total Length of Fwd Packets
            float(self.bwd_bytes),                                  #  5 Total Length of Bwd Packets
            float(self.fwd_len_max),                                #  6 Fwd Packet Length Max
            _safe_min(self.fwd_len_min),                            #  7 Fwd Packet Length Min
            fwd_pkt_mean,                                           #  8 Fwd Packet Length Mean
            fwd_pkt_std,                                            #  9 Fwd Packet Length Std
            float(self.bwd_len_max),                                # 10 Bwd Packet Length Max
            _safe_min(self.bwd_len_min),                            # 11 Bwd Packet Length Min
            bwd_pkt_mean,                                           # 12 Bwd Packet Length Mean
            bwd_pkt_std,                                            # 13 Bwd Packet Length Std
            _safe_div(total_bytes, duration),                       # 14 Flow Bytes/s
            _safe_div(total_packets, duration),                     # 15 Flow Packets/s
            _mean(flow_iat_us),                                     # 16 Flow IAT Mean
            _std(flow_iat_us),                                      # 17 Flow IAT Std
            _max(flow_iat_us),                                      # 18 Flow IAT Max
            _min(flow_iat_us),                                      # 19 Flow IAT Min
            sum(fwd_iat_us),                                        # 20 Fwd IAT Total
            _mean(fwd_iat_us),                                      # 21 Fwd IAT Mean
            _std(fwd_iat_us),                                       # 22 Fwd IAT Std
            _max(fwd_iat_us),                                       # 23 Fwd IAT Max
            _min(fwd_iat_us),                                       # 24 Fwd IAT Min
            sum(bwd_iat_us),                                        # 25 Bwd IAT Total
            _mean(bwd_iat_us),                                      # 26 Bwd IAT Mean
            _std(bwd_iat_us),                                       # 27 Bwd IAT Std
            _max(bwd_iat_us),                                       # 28 Bwd IAT Max
            _min(bwd_iat_us),                                       # 29 Bwd IAT Min
            float(self.fwd_psh_flags),                              # 30 Fwd PSH Flags
            float(self.bwd_psh_flags),                              # 31 Bwd PSH Flags
            float(self.fwd_urg_flags),                              # 32 Fwd URG Flags
            float(self.bwd_urg_flags),                              # 33 Bwd URG Flags
            float(self.fwd_header_len),                             # 34 Fwd Header Length
            float(self.bwd_header_len),                             # 35 Bwd Header Length
            _safe_div(self.fwd_packets, duration),                  # 36 Fwd Packets/s
            _safe_div(self.bwd_packets, duration),                  # 37 Bwd Packets/s
            _safe_min(self.all_len_min),                            # 38 Min Packet Length
            float(self.all_len_max),                                # 39 Max Packet Length
            all_pkt_mean,                                           # 40 Packet Length Mean
            all_pkt_std,                                            # 41 Packet Length Std
            all_pkt_var,                                            # 42 Packet Length Variance
            float(self.fin_count),                                  # 43 FIN Flag Count
            float(self.syn_count),                                  # 44 SYN Flag Count
            float(self.rst_count),                                  # 45 RST Flag Count
            float(self.psh_count),                                  # 46 PSH Flag Count
            float(self.ack_count),                                  # 47 ACK Flag Count
            float(self.urg_count),                                  # 48 URG Flag Count
            float(self.cwe_count),                                  # 49 CWE Flag Count
            float(self.ece_count),                                  # 50 ECE Flag Count
            down_up,                                                # 51 Down/Up Ratio
            avg_pkt_size,                                           # 52 Average Packet Size
            fwd_pkt_mean,                                           # 53 Avg Fwd Segment Size
            bwd_pkt_mean,                                           # 54 Avg Bwd Segment Size
            float(self.fwd_header_len),                             # 55 Fwd Header Length.1
            0.0,                                                    # 56 Fwd Avg Bytes/Bulk
            0.0,                                                    # 57 Fwd Avg Packets/Bulk
            0.0,                                                    # 58 Fwd Avg Bulk Rate
            0.0,                                                    # 59 Bwd Avg Bytes/Bulk
            0.0,                                                    # 60 Bwd Avg Packets/Bulk
            0.0,                                                    # 61 Bwd Avg Bulk Rate
            float(self.fwd_packets),                                # 62 Subflow Fwd Packets
            float(self.fwd_bytes),                                  # 63 Subflow Fwd Bytes
            float(self.bwd_packets),                                # 64 Subflow Bwd Packets
            float(self.bwd_bytes),                                  # 65 Subflow Bwd Bytes
            float(max(self.init_win_fwd, 0)),                       # 66 Init_Win_bytes_forward
            float(max(self.init_win_bwd, 0)),                       # 67 Init_Win_bytes_backward
            float(self.act_data_pkt_fwd),                           # 68 act_data_pkt_fwd
            _safe_min(self.min_seg_size_fwd),                       # 69 min_seg_size_forward
            _mean(active_us),                                       # 70 Active Mean
            _std(active_us),                                        # 71 Active Std
            _max(active_us),                                        # 72 Active Max
            _min(active_us),                                        # 73 Active Min
            _mean(idle_us),                                         # 74 Idle Mean
            _std(idle_us),                                          # 75 Idle Std
            _max(idle_us),                                          # 76 Idle Max
            _min(idle_us),                                          # 77 Idle Min
        ], dtype=np.float32)


flows = defaultdict(lambda: {
    "feature_window": deque(maxlen=SEQ_LEN),
    "last_packet_time": time.time(),
    "is_anomaly": False,
    "stats": None
})

# ========== 模型定义（TransEC-GAN 大容量版，与训练脚本对齐） ==========
class TransformerEncoder(nn.Module):
    def __init__(self, input_dim, d_model=256, nhead=8, num_layers=6, seq_len=32, dropout=0.1):
        super().__init__()
        self.linear = nn.Linear(input_dim, d_model)
        self.pos_encoder = nn.Embedding(seq_len, d_model)
        self.input_norm = nn.LayerNorm(d_model)
        self.input_dropout = nn.Dropout(dropout)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=1024,
            activation="gelu", batch_first=True, norm_first=True,
            dropout=dropout
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.seq_len = seq_len

    def forward(self, x):
        batch_size, seq_len = x.shape[0], x.shape[1]
        x = self.linear(x)
        pos = torch.arange(seq_len, device=x.device).unsqueeze(0).expand(batch_size, -1)
        x = x + self.pos_encoder(pos)
        x = self.input_dropout(self.input_norm(x))
        return self.transformer(x).mean(dim=1)

class Generator(nn.Module):
    def __init__(self, latent_dim=LATENT_DIM, num_classes=NUM_CLASSES, pca_dim=PCA_DIM, seq_len=SEQ_LEN, dropout=0.1):
        super().__init__()
        self.seq_len = seq_len
        self.noise_linear = nn.Sequential(
            nn.Linear(latent_dim + num_classes, 256),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(256, 256)
        )
        self.transformer = TransformerEncoder(input_dim=256, d_model=256, seq_len=seq_len, dropout=dropout)
        self.fc = nn.Sequential(
            nn.Linear(256, 512),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(512, pca_dim)
        )

    def forward(self, z, labels):
        x = torch.cat([z, labels], dim=1)
        x = self.noise_linear(x).unsqueeze(1).expand(-1, self.seq_len, -1)
        x = self.transformer(x)
        x = self.fc(x).unsqueeze(1).expand(-1, self.seq_len, -1)
        return x

class Discriminator(nn.Module):
    def __init__(self, pca_dim=PCA_DIM, num_classes=NUM_CLASSES, seq_len=SEQ_LEN, dropout=0.1):
        super().__init__()
        self.transformer = TransformerEncoder(input_dim=pca_dim, d_model=256, seq_len=seq_len, dropout=dropout)
        self.head = nn.Sequential(
            nn.Linear(256, 512),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        self.real_fc = nn.Linear(512, 1)
        self.class_fc = nn.Linear(512, num_classes)

    def forward(self, x):
        feat = self.transformer(x)
        feat = self.head(feat)
        real_pred = self.real_fc(feat)
        class_pred = self.class_fc(feat)
        return real_pred, class_pred

# ========== 工具函数 ==========
def get_wlan_interface():
    import platform
    try:
        if platform.system() == "Windows":
            from scapy.arch.windows import get_windows_if_list
            scapy_ifaces = get_windows_if_list()
            for iface in scapy_ifaces:
                if iface.get("name", "").lower() == "wlan":
                    logger.info(f"{COLORS['green']}✅ 选中WLAN网卡：{iface['name']}（{iface.get('description', '未知型号')}）{COLORS['reset']}")
                    return iface["name"]
            for iface in scapy_ifaces:
                if iface.get("name", "").lower() in ["以太网", "ethernet"]:
                    logger.info(f"{COLORS['green']}✅ 选中有线网卡：{iface['name']}（{iface.get('description', '未知型号')}）{COLORS['reset']}")
                    return iface["name"]
            logger.warning(f"{COLORS['yellow']}⚠️ 未自动识别网卡，请手动输入（常见：WLAN/以太网）{COLORS['reset']}")
            return input().strip() or "WLAN"
        else:
            # Linux/Unix 环境自动获取网卡
            from scapy.interfaces import get_if_list
            ifaces = get_if_list()
            # 排除回环接口
            candidates = [i for i in ifaces if i != "lo"]
            if candidates:
                # 优先选择 eth0, ens33 等常见网卡
                for iface in candidates:
                    if any(name in iface for name in ["eth", "ens", "enp", "wlan"]):
                        logger.info(f"{COLORS['green']}✅ 选中Linux网卡：{iface}{COLORS['reset']}")
                        return iface
                # 否则返回第一个非lo网卡
                logger.info(f"{COLORS['green']}✅ 选中Linux网卡：{candidates[0]}{COLORS['reset']}")
                return candidates[0]
            elif ifaces:
                 return ifaces[0]
            else:
                 logger.warning(f"{COLORS['yellow']}⚠️ 未找到可用网卡，默认为 eth0{COLORS['reset']}")
                 return "eth0"
                 
    except Exception as e:
        logger.error(f"{COLORS['red']}❌ 网卡识别失败：{str(e)}{COLORS['reset']}")
        raise SystemExit(1)

def load_model():
    try:
        checkpoint = torch.load(MODEL_PATH, map_location=DEVICE, weights_only=False)

        pca_dim = checkpoint.get('pca_dim', PCA_DIM)
        num_classes = checkpoint.get('num_classes', NUM_CLASSES)
        seq_len = checkpoint.get('seq_len', SEQ_LEN)

        disc_state_dict = checkpoint["discriminator_state_dict"]
        if next(iter(disc_state_dict.keys())).startswith("module."):
            disc_state_dict = {k.replace("module.", ""): v for k, v in disc_state_dict.items()}

        discriminator = Discriminator(pca_dim=pca_dim, num_classes=num_classes, seq_len=seq_len).to(DEVICE)
        discriminator.load_state_dict(disc_state_dict, strict=True)

        gen_state_dict = checkpoint["generator_state_dict"]
        if next(iter(gen_state_dict.keys())).startswith("module."):
            gen_state_dict = {k.replace("module.", ""): v for k, v in gen_state_dict.items()}
        generator = Generator(pca_dim=pca_dim, num_classes=num_classes, seq_len=seq_len).to(DEVICE)
        generator.load_state_dict(gen_state_dict, strict=True)

        scaler = joblib.load(SCALER_PATH)
        pca = joblib.load(PCA_PATH)
        labels = checkpoint.get("label_classes", CLASS_NAMES)

        logger.info(f"{COLORS['green']}✅ TransEC-GAN 模型加载成功 "
                    f"(PCA={pca_dim}, Classes={num_classes}, Seq={seq_len}){COLORS['reset']}")
        logger.info(f"{COLORS['green']}   支持检测: {', '.join(labels)}{COLORS['reset']}")
        return discriminator.eval(), generator.eval(), scaler, pca, labels
    except Exception as e:
        logger.error(f"{COLORS['red']}❌ 模型加载失败：{str(e)}{COLORS['reset']}")
        raise SystemExit(1)

def extract_features(packet):
    try:
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        src_ip, dst_ip = str(ip.src), str(ip.dst)
        proto = int(ip.proto)
        src_port = 0
        dst_port = 0

        if proto == 6 and packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port = int(tcp.sport) if tcp.sport else 0
            dst_port = int(tcp.dport) if tcp.dport else 0
        elif proto == 17 and packet.haslayer(UDP):
            udp = packet[UDP]
            src_port = int(udp.sport) if udp.sport else 0
            dst_port = int(udp.dport) if udp.dport else 0
        else:
            return None

        flow_key = get_flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        flow = flows[flow_key]
        flow["last_packet_time"] = time.time()

        if flow["stats"] is None:
            now = time.time()
            flow["stats"] = FlowStats(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
                start_time=now,
                last_time=now
            )

        pkt_len = len(packet)
        features = flow["stats"].update(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            pkt_len=pkt_len,
            timestamp=time.time(),
            packet=packet
        )

        flow["feature_window"].append(features)
        return flow_key, features
    except Exception as e:
        logger.debug(f"特征提取警告：{str(e)}（包摘要：{packet.summary()}）")
        return None

def clean_timeout_flows():
    now = time.time()
    timeout_count = 0
    for key, flow in list(flows.items()):
        if now - flow["last_packet_time"] > FLOW_TIMEOUT:
            del flows[key]
            timeout_count += 1
    if timeout_count > 0:
        logger.debug(f"清理超时会话：{timeout_count} 个")

if __name__ == "__main__":
    logger.info(f"{COLORS['green']}✅ ids_common.py 核心模块加载成功{COLORS['reset']}")