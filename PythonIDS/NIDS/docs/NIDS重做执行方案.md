# NIDS 重做执行方案 v2.0

> 御链天鉴 · 网络入侵检测系统重构
> **保留 TransEC-GAN 架构** · 基于 CICIDS2017 重新训练 · 5880高性能服务器

---

## 一、现状诊断

### 1.1 模型架构（保留）

TransEC-GAN 由老师设计，架构不动：

```
TransEC-GAN = TransformerEncoder + GAN(Generator + Discriminator)

Discriminator（实时检测使用）:
  输入: (batch, SEQ_LEN=32, PCA_DIM=12) → TransformerEncoder(12→128) → mean pooling
  输出: real_score(1) + class_pred(NUM_CLASSES)

Generator（训练时使用）:
  输入: noise(LATENT_DIM=128) + one-hot(NUM_CLASSES)
  输出: (batch, SEQ_LEN, PCA_DIM) 的合成序列
```

### 1.2 现有代码问题（需修复）

| 问题 | 严重程度 | 修复方案 |
|------|---------|---------|
| 无训练脚本 | ⚠️ 高 | 新写完整的 GAN 训练脚本 |
| NUM_CLASSES=6 不匹配 | ⚠️ 高 | 调整为匹配 CICIDS2017 的类别数 |
| 16维特征与CICIDS2017 78列对齐不完整 | ⚠️ 高 | 从 CSV 精确选取对应的 16 列 |
| PCA 预处理(16→12)需重新生成 | ⚠️ 高 | 在新数据上重新 fit PCA |
| 实时检测代码臃肿(1759行) | ⚠️ 中 | 精简重写检测主循环 |
| OOD 判定逻辑混乱 | ⚠️ 中 | 简化为 real_score + class_confidence |
| 窗口填充方式不合理 | ⚠️ 中 | 改为真正的时序窗口 |

### 1.3 保留的部分

- **模型架构**：TransformerEncoder, Generator, Discriminator（ids_common.py）
- **FlowStats 数据类**：流量统计逻辑合理
- **extract_features 函数**：网络包→16维特征向量
- **告警推送逻辑**：send_alert_payload
- **get_flow_key / get_wlan_interface**：工具函数

### 1.4 需要重写的部分

- **训练脚本**：完整的 TransEC-GAN 训练管线
- **数据预处理**：CICIDS2017 → 16维 → PCA 12维 → 序列化
- **preprocessed_data/**：scaler.pkl + pca.pkl + label_encoder.npy 全部重新生成
- **实时检测主循环**：精简 OOD/分类判定逻辑
- **transec_gan_model/best_model_4x5880_max.pth**：用新训练的模型替换

---

## 二、数据集：CICIDS2017

### 2.1 数据概况

| 属性 | 值 |
|-----|-----|
| 来源 | Canadian Institute for Cybersecurity, UNB |
| 格式 | CSV（CICFlowMeter 生成的流特征） |
| 时间跨度 | 2017年7月3日-7日（周一至周五） |
| 特征维度 | 78 维流特征（训练用16维子集） |
| 服务器路径 | `/home/test/ids_project/data/` |
| 总大小 | ~843 MB（8个CSV文件） |

### 2.2 攻击类型分布

| 日期 | 攻击类型 | 标签 |
|------|---------|------|
| Monday | 正常流量 | BENIGN |
| Tuesday | 暴力破解 | FTP-Patator, SSH-Patator |
| Wednesday | DoS/DDoS | DoS slowloris, DoS Slowhttptest, DoS Hulk, DoS GoldenEye, Heartbleed |
| Thursday AM | Web攻击 | Web Attack – Brute Force, Web Attack – XSS, Web Attack – Sql Injection |
| Thursday PM | 渗透 | Infiltration |
| Friday AM | 僵尸网络 | Bot |
| Friday PM | 端口扫描/DDoS | PortScan, DDoS |

### 2.3 标签合并策略（15→6类）

为匹配 TransEC-GAN 的 NUM_CLASSES=6：

```
原始标签                              → 合并标签      → 类别ID
─────────────────────────────────────────────────────────────
BENIGN                               → Benign        → 0
FTP-Patator, SSH-Patator             → BruteForce    → 1
DoS Hulk, DoS GoldenEye,            → DoS           → 2
DoS slowloris, DoS Slowhttptest,
Heartbleed
Web Attack – Brute Force,            → WebAttack     → 3
Web Attack – XSS,
Web Attack – Sql Injection
Infiltration, Bot                    → Infiltration  → 4
PortScan, DDoS                       → DDoS/Scan     → 5
```

> **NUM_CLASSES = 6**（0=正常 + 5种攻击），与现有架构完全兼容

### 2.4 特征列映射（CICIDS2017 78列 → FlowStats 16维）

从 CICIDS2017 CSV 中精确选取与 FlowStats.to_feature_vector() 对应的 16 列：

```
FlowStats 索引  FlowStats 名称         CICIDS2017 CSV 列名
─────────────────────────────────────────────────────────
 0              dst_port               Destination Port
 1              duration_us            Flow Duration
 2              fwd_packets            Total Fwd Packets
 3              bwd_packets            Total Backward Packets
 4              fwd_bytes              Total Length of Fwd Packets
 5              bwd_bytes              Total Length of Bwd Packets
 6              fwd_len_max            Fwd Packet Length Max
 7              fwd_len_min            Fwd Packet Length Min
 8              fwd_len_mean           Fwd Packet Length Mean
 9              bwd_len_max            Bwd Packet Length Max
10              bwd_len_min            Bwd Packet Length Min
11              bwd_len_mean           Bwd Packet Length Mean
12              flow_bytes_per_s       Flow Bytes/s
13              flow_pkts_per_s        Flow Packets/s
14              fwd_iat_mean_us        Fwd IAT Mean
15              bwd_iat_mean_us        Bwd IAT Mean
```

> **关键**：训练时只用这 16 列，确保与实时检测的 FlowStats 输出完全对齐。

---

## 三、训练管线设计

### 3.1 数据流

```
CICIDS2017 CSV (78列)
       │
       ▼  选取16列对齐FlowStats
16维原始特征 (N samples × 16)
       │
       ▼  StandardScaler 标准化
16维标准化特征
       │
       ▼  PCA(n_components=12) 降维
12维PCA特征 (N × 12)
       │
       ▼  滑动窗口/填充为序列
序列数据 (M sequences × 32 × 12)
       │
       ├──────────────────┐
       ▼                  ▼
  Discriminator      Generator
  (真/假 + 分类)    (生成合成序列)
```

### 3.2 GAN 训练策略

```
Epoch loop:
  1. 训练 Discriminator:
     - 真实数据: D(real) → real_score=1, class_pred=label
     - 生成数据: D(G(z, label)) → real_score=0
     - Loss_D = BCE(real) + BCE(fake) + CrossEntropy(class)

  2. 训练 Generator:
     - 生成数据: D(G(z, label)) → real_score=1 (欺骗D)
     - Loss_G = BCE(fool_D)

  3. 验证:
     - 在验证集上计算分类准确率
     - 保存最佳模型 checkpoint

超参数:
  - lr_D = 2e-4, lr_G = 1e-4 (D学习率高于G)
  - beta1 = 0.5, beta2 = 0.999
  - 标签平滑: real=0.9, fake=0.1
  - 类别加权 CrossEntropy (处理不平衡)
  - 早停: patience=20 (基于验证集分类准确率)
```

### 3.3 保存的模型文件

```
best_model_4x5880_max.pth = {
    'discriminator_state_dict': ...,
    'generator_state_dict': ...,
    'label_classes': ['Benign', 'BruteForce', 'DoS', 'WebAttack', 'Infiltration', 'DDoS/Scan'],
    'epoch': ...,
    'val_accuracy': ...,
}
```

---

## 四、执行计划

### Phase 0：数据预处理（服务器执行）
**预计耗时：30分钟**

```bash
# 脚本：nids_data_preprocess.py
# 位置：/home/test/ids_project/
# 运行：python nids_data_preprocess.py
```

**步骤：**
1. 加载 8 个 CSV 文件，合并为统一 DataFrame
2. 清洗：替换 inf→NaN，删除含 NaN 的行，删除重复行
3. 标签合并：15 类 → 6 类
4. **特征选取**：从 78 列中精确选取 FlowStats 对应的 16 列
5. 数据划分：70% 训练 / 15% 验证 / 15% 测试（分层采样）
6. StandardScaler 标准化（仅在训练集上 fit）
7. PCA(n_components=12) 降维（仅在训练集上 fit）
8. 序列化：滑动窗口(stride=16)生成 (N, 32, 12) 的序列
9. 保存：npz + scaler.pkl + pca.pkl + label_encoder.npy

**输出文件：**
```
/home/test/ids_project/preprocessed/
├── train_sequences.npz   # X_train (N, 32, 12), y_train (N,)
├── val_sequences.npz     # X_val, y_val
├── test_sequences.npz    # X_test, y_test
├── scaler.pkl            # StandardScaler(16维)
├── pca.pkl               # PCA(16→12)
├── label_encoder.npy     # ['Benign','BruteForce','DoS','WebAttack','Infiltration','DDoS/Scan']
└── data_stats.json       # 数据集统计
```

### Phase 1：TransEC-GAN 训练（服务器 4×5880 GPU）
**预计耗时：2-4小时**

```bash
# 脚本：nids_train_transec_gan.py
# 运行：python nids_train_transec_gan.py \
#   --data_dir preprocessed \
#   --output_dir transec_gan_model \
#   --epochs 200 \
#   --batch_size 256 \
#   --device cuda \
#   --num_gpus 4
```

**步骤：**
1. 加载预处理好的序列数据
2. 初始化 Generator + Discriminator
3. 多GPU并行训练（DataParallel）
4. 对抗训练循环 200 epochs
5. 每 5 个 epoch 在验证集上评估分类准确率
6. 保存最佳模型 → `best_model_4x5880_max.pth`

### Phase 2：模型评估（服务器执行）
**预计耗时：15分钟**

在测试集上评估 Discriminator 分类性能：
- 6 类分类报告（Precision/Recall/F1 per class）
- 混淆矩阵热力图
- ROC 曲线（macro/micro）
- HTML 评估报告

**验收标准：**
- Overall Accuracy ≥ 97%
- 各攻击类别 F1 ≥ 0.85
- Benign 类 Precision ≥ 0.95（低误报率）

### Phase 3：集成部署
**预计耗时：2小时**

1. **更新 `ids_common.py`**
   - 更新 NUM_CLASSES=6 对应的标签名
   - 确认模型路径指向新的 .pth 文件

2. **重写 `realtime_detection_fixed.py`**
   - 精简检测主循环（目标：500行以内）
   - 简化 OOD 判定：real_score < 阈值 → 未知攻击
   - 简化分类输出：class_pred argmax → 攻击类型
   - 保留告警推送逻辑

3. **模型文件同步**
   - 新的 `best_model_4x5880_max.pth` → `transec_gan_model/`
   - 新的 `scaler.pkl` + `pca.pkl` → `preprocessed_data/`
   - 新的 `label_encoder.npy` → `preprocessed_data/`

### Phase 4：攻击脚本编写
**预计耗时：3小时**

编写全面的攻击测试套件，覆盖市面上所有常见攻击类型：

#### 4.1 暴力破解类
| 攻击 | 方法 | 脚本 |
|------|------|------|
| SSH 暴力破解 | Paramiko 字典爆破 | `attack_ssh_bruteforce.py` |
| FTP 暴力破解 | ftplib 字典爆破 | `attack_ftp_bruteforce.py` |
| HTTP 登录爆破 | requests POST 字典 | `attack_http_bruteforce.py` |
| RDP 暴力破解 | 模拟 RDP 连接尝试 | `attack_rdp_bruteforce.py` |

#### 4.2 DoS/DDoS 类
| 攻击 | 方法 | 脚本 |
|------|------|------|
| SYN Flood | Scapy 伪造 SYN 包 | `attack_syn_flood.py` |
| UDP Flood | Scapy 大量 UDP 包 | `attack_udp_flood.py` |
| HTTP Flood | 高频 HTTP GET/POST | `attack_http_flood.py` |
| Slowloris | 慢速 HTTP 长连接 | `attack_slowloris.py` |
| ICMP Flood (Ping of Death) | 大 ICMP 包 | `attack_icmp_flood.py` |
| CC 攻击 | 模拟大量代理请求 | `attack_cc.py` |

#### 4.3 扫描与侦察类
| 攻击 | 方法 | 脚本 |
|------|------|------|
| TCP SYN 扫描 | Scapy 半开扫描 | `attack_syn_scan.py` |
| TCP 全连接扫描 | socket connect | `attack_tcp_scan.py` |
| UDP 端口扫描 | Scapy UDP 探测 | `attack_udp_scan.py` |
| XMAS/FIN/NULL 扫描 | Scapy 特殊标志位 | `attack_stealth_scan.py` |
| 服务版本探测 | Banner Grabbing | `attack_banner_grab.py` |
| OS 指纹识别 | TTL/Window 分析 | `attack_os_fingerprint.py` |
| DNS 枚举 | 子域名爆破 | `attack_dns_enum.py` |

#### 4.4 Web 攻击类
| 攻击 | 方法 | 脚本 |
|------|------|------|
| SQL 注入 | UNION/盲注/时间盲注 | `attack_sqli.py` |
| XSS | 反射型/存储型 Payload | `attack_xss.py` |
| 命令注入 | OS Command Injection | `attack_cmdi.py` |
| 目录遍历 | ../../../etc/passwd | `attack_path_traversal.py` |
| 文件包含 | LFI/RFI | `attack_file_inclusion.py` |
| CSRF | 伪造跨站请求 | `attack_csrf.py` |
| SSRF | 服务端请求伪造 | `attack_ssrf.py` |
| WebShell 上传 | 恶意文件上传 | `attack_webshell.py` |

#### 4.5 中间人攻击类
| 攻击 | 方法 | 脚本 |
|------|------|------|
| ARP 欺骗 | Scapy ARP Reply | `attack_arp_spoof.py` |
| DNS 欺骗 | 伪造 DNS 响应 | `attack_dns_spoof.py` |
| 会话劫持 | TCP 序列号预测 | `attack_session_hijack.py` |

#### 4.6 恶意软件/后渗透类
| 攻击 | 方法 | 脚本 |
|------|------|------|
| C2 通信模拟 | 周期性 HTTPS 心跳 | `attack_c2_beacon.py` |
| 数据外泄 | DNS 隧道/ICMP 隧道 | `attack_data_exfil.py` |
| 反弹 Shell | TCP 反向连接 | `attack_reverse_shell.py` |
| 横向移动 | SMB/WMI 远程执行 | `attack_lateral_move.py` |
| 提权模拟 | 异常进程/端口 | `attack_privilege_esc.py` |

#### 4.7 协议异常类
| 攻击 | 方法 | 脚本 |
|------|------|------|
| 畸形包 | 异常 TCP 标志组合 | `attack_malformed_pkt.py` |
| 分片攻击 | IP 分片重叠 | `attack_fragmentation.py` |
| 协议滥用 | 非标准端口/协议 | `attack_protocol_abuse.py` |

> **总计：35+ 种攻击脚本**，覆盖 OWASP Top 10、MITRE ATT&CK 网络层面常见手法。
> 对于 CICIDS2017 训练集中未包含的攻击类型，NIDS 通过 Discriminator 的 real_score（OOD 检测）识别为"未知攻击"。

---

## 五、关键参数总结

```python
# 优化后参数（以最佳效果为准）
SEQ_LEN = 32              # 时序窗口长度
PCA_DIM = auto            # PCA 自动选择（保留95%方差，预计32~48维）
FEATURE_DIM = 78          # CICIDS2017 全部流特征
NUM_CLASSES = 8            # 8类分类（Benign + 7种攻击）
LATENT_DIM = 128           # 生成器噪声维度
ANOMALY_THRESHOLD = 0.5    # OOD阈值（基于 Discriminator real_score）
```

---

## 六、依赖清单

### 服务器（训练环境）
```bash
pip install numpy pandas scikit-learn torch torchvision \
    matplotlib seaborn tqdm joblib -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### 本地/生产（检测环境）
```bash
pip install numpy scikit-learn torch scapy requests joblib \
    -i https://pypi.tuna.tsinghua.edu.cn/simple
```

---

## 七、文件结构规划

```
PythonIDS/
├── ids_common.py                  # 更新：标签名映射
├── realtime_detection_fixed.py    # 重写：精简检测循环
├── transec_gan_model/             # 新训练的模型
│   └── best_model_4x5880_max.pth
├── preprocessed_data/             # 重新生成
│   ├── scaler.pkl
│   ├── pca.pkl
│   └── label_encoder.npy
├── nids_training/                 # 新增：训练脚本
│   ├── nids_data_preprocess.py    # 数据预处理
│   ├── nids_train_transec_gan.py  # GAN训练
│   └── nids_evaluate.py           # 评估报告
├── attack_scripts/                # 新增：攻击测试
│   ├── attack_bruteforce.py
│   ├── attack_dos.py
│   ├── attack_web.py
│   └── attack_ddos_scan.py
├── PIDS/                          # 不变
└── docs/
    └── NIDS重做执行方案.md
```

---

## 八、里程碑与验收标准

| 阶段 | 验收标准 |
|------|---------|
| Phase 0 | 数据预处理完成，序列 npz + scaler/pca 生成 |
| Phase 1 | GAN 训练完成，验证集 Acc ≥ 95% |
| Phase 2 | 测试集 Acc ≥ 97%，评估报告 HTML 生成 |
| Phase 3 | 实时检测能正确分类 6 种流量类型 |
| Phase 4 | 攻击脚本触发 NIDS 告警并推送到后端 |
