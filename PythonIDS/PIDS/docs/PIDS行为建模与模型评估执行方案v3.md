# PIDS 行为建模与模型评估执行方案 v3.0

> 御链天鉴开发团队 · 2025年
> 硬件环境：高性能服务器 4×NVIDIA RTX 5880 GPU
> 参考论文：KAIROS (IEEE S&P 2024) — Practical Intrusion Detection and Investigation using Whole-system Provenance

---

## 一、数据方案：DARPA TC 数据集

### 1.1 为什么选择 DARPA TC？

DARPA Transparent Computing (TC) 是目前**因果溯源图入侵检测领域最权威的公开数据集**，被 KAIROS、UNICORN、ThreaTrace 等顶会论文广泛使用。

| 对比维度 | DARPA TC 数据集 | 我们的 PIDS 系统 | 匹配度 |
|----------|----------------|-----------------|--------|
| 数据类型 | 全系统因果溯源图 | 因果溯源图 | 完全一致 |
| 节点类型 | Process / File / Socket | process / file / socket / attacker | 高度匹配 |
| 边类型 | 系统调用事件(read/write/exec/connect) | 攻击行为(攻击/访问/执行/连接) | 可直接映射 |
| 检测任务 | APT异常检测 + 攻击溯源 | 异常检测 + 攻击分类 | 一致 |
| 标签 | 有 Ground Truth 报告 | 需要标签 | 可直接使用 |

### 1.2 数据集构成

DARPA TC 进行了多轮对抗演练（Engagement），我们主要使用：

| 演练 | 子数据集 | 操作系统 | 攻击场景 | 数据规模 |
|------|---------|---------|---------|---------|
| **E3** | THEIA | Linux | APT攻击（后门、数据窃取、提权） | 数百万事件 |
| **E3** | CADETS | FreeBSD | APT攻击（命令执行、横向移动） | 数百万事件 |
| **E3** | ClearScope | Android | 移动端攻击 | 数百万事件 |
| **E3** | FiveDirections | Windows | Windows APT攻击 | 数百万事件 |
| **E5** | THEIA | Linux | 8天持续APT攻击 | 千万级事件 |
| **E5** | CADETS | FreeBSD | 8天持续APT攻击 | 千万级事件 |

**推荐优先使用**：E3-THEIA + E3-CADETS（Linux/FreeBSD，与我们系统最匹配）

### 1.3 数据格式与转换

**原始格式**：CDM (Common Data Model)，Avro 序列化（`.bin.gz`）

**CDM 核心实体**：
- `Subject` → 进程/线程（对应我们的 `process` 节点）
- `FileObject` → 文件（对应我们的 `file` 节点）
- `NetFlowObject` → 网络连接（对应我们的 `socket` 节点）
- `Event` → 系统调用事件（对应我们的边）

**转换管道**：
```
CDM Avro (.bin.gz)
    ↓ fastavro 解析
Subject/FileObject/NetFlowObject/Event
    ↓ CDM适配器 (cdm_adapter.py)
我们的格式: {nodes: [{id, label, type}], edges: [{source, target, label}]}
    ↓ 时间窗口切割 (每5分钟一个子图)
溯源子图集合 (数千~万级)
    ↓ FeatureExtractor.extract()
130维特征向量 + Ground Truth标签
    ↓ 存储
data/train_dataset.npz (features, labels, attack_types)
```

### 1.4 Ground Truth 标注

DARPA 提供了详细的攻击报告（`tc_ground_truth_report_e3.pdf` / `e5`），包含：
- 攻击发生的精确时间窗口
- 涉及的进程、文件、网络连接
- 攻击类型和阶段

**标注策略**：
- 落在攻击时间窗口内且涉及攻击实体的子图 → 标记为 `anomaly (1)` + 具体攻击类型
- 其余子图 → 标记为 `normal (0)`

### 1.5 数据集划分

| 集合 | 来源 | 比例 | 用途 |
|------|------|------|------|
| 训练集 | E3-THEIA 70% | ~70% | 模型训练 |
| 验证集 | E3-THEIA 30% | ~15% | 超参数调优 |
| 测试集 | E3-CADETS | ~15% | 跨系统泛化评估 |

> 用不同 TA1 系统的数据做测试，验证模型的跨平台泛化能力。

### 1.6 数据增强（补充）

在 DARPA TC 真实数据基础上，额外使用合成数据增强：
- **子图采样**：从大图中随机采样不同大小的子图
- **节点/边扰动**：随机添加/删除少量节点和边
- **时间戳抖动**：对时间戳添加随机噪声
- **攻击模板生成**：基于已知攻击模式生成变体

---

## 二、行为建模方案

### 2.1 模型架构（三层递进）

有了 DARPA TC 真实数据的支撑，可以训练更强大的模型：

| 层级 | 模型 | 输入 | 输出 | GPU需求 | 推理时间 |
|------|------|------|------|---------|---------|
| **L1 快速筛选** | IF + LOF + XGBoost 集成 | 130维向量 | 异常得分(0-1) | CPU | ≤5ms |
| **L2 深度检测** | VAE + MLP 分类器 | 130维向量 | 攻击类型(9类) | 1×GPU | ≤20ms |
| **L3 图级推理** | GNN (GraphSAGE) + Attention | 溯源图 | 图级异常得分 | 2-4×GPU | ≤100ms |

### 2.2 L1：集成异常检测器（CPU）

**改进现有 `BehaviorModeler`**：

```python
EnsembleDetector:
  ├── IsolationForest (无监督，异常检测)
  ├── LocalOutlierFactor (无监督，密度异常)
  ├── OneClassSVM (无监督，边界异常)
  └── XGBoost (有监督，攻击分类)
      ↓ 加权投票
  最终预测: normal/anomaly + 攻击类型 + 置信度
```

**特征重要性**：集成 SHAP 值分析，输出每个维度对检测结果的贡献度。

### 2.3 L2：VAE + 攻击分类器（单卡GPU）

**双任务联合训练**：

```
输入(130维) → Encoder(130→64→32) → μ,σ → z(32维) → Decoder(32→64→130) → 重建
                                               ↓
                                       z(32维) → MLP(32→64→9) → 攻击类型

损失 = α × 重建损失(MSE+KL) + β × 分类损失(FocalLoss)
```

- 任务1：重建误差 → 异常得分（正常样本重建误差小，异常样本大）
- 任务2：分类 → 攻击类型识别（SQL注入/XSS/RCE/提权/...）

**训练配置**：
- 框架：PyTorch
- 优化器：AdamW, lr=1e-3, weight_decay=1e-5
- Batch size：256
- Epochs：200（早停 patience=20）
- 混合精度：FP16（AMP）
- GPU：单卡 RTX 5880

### 2.4 L3：GNN 图级推理（多卡GPU，远期目标）

**核心思路**：参考 KAIROS 论文，直接在溯源图上做图神经网络推理。

```
溯源图 → 节点特征编码 → GraphSAGE(3层) → 图级池化 → 异常得分
```

- 框架：PyTorch + PyTorch Geometric
- GNN：GraphSAGE（3层，hidden=128）
- 池化：全局注意力池化
- 训练：4卡 DDP 分布式训练
- 此层为远期目标，Phase 1-3 先不实现

---

## 三、模型评估方案

### 3.1 评估指标体系

| 维度 | 指标 | 目标值 | 说明 |
|------|------|--------|------|
| **检测能力** | Accuracy | ≥ 95% | 整体准确率 |
| | Precision | ≥ 93% | 减少误报 |
| | Recall | ≥ 97% | 宁可误报不可漏报 |
| | F1-Score | ≥ 95% | 综合指标 |
| | AUC-ROC | ≥ 0.98 | 区分能力 |
| **分类能力** | 各攻击类型检测率 | ≥ 90% | 分类别统计 |
| | 宏平均F1 | ≥ 92% | 类别均衡评估 |
| **效率** | L1推理时间 | ≤ 5ms | 实时检测 |
| | L2推理时间 | ≤ 20ms | 深度分析 |
| | 吞吐量 | ≥ 1000/s | 批量处理 |
| **泛化性** | 跨系统检测率 | ≥ 85% | E3-THEIA训练→E3-CADETS测试 |

### 3.2 评估可视化

1. **ROC曲线 & PR曲线** — 不同阈值下的检测性能
2. **混淆矩阵热力图** — TP/TN/FP/FN 分布
3. **分攻击类型检测率柱状图** — 各类攻击的检测效果
4. **特征重要性排名图（SHAP）** — 哪些特征对检测最关键
5. **模型对比雷达图** — L1 vs L2 多维度对比
6. **推理延迟分布图** — 实时性能分析
7. **t-SNE/UMAP 降维可视化** — 正常/异常样本在特征空间的分布

### 3.3 评估报告

自动生成 HTML 格式的评估报告，包含所有图表和指标，可直接用于**答辩/汇报/论文**。

---

## 四、执行计划

### Phase 0：数据准备（1-2天）

| 序号 | 任务 | 产出 |
|------|------|------|
| 0.1 | 下载 DARPA TC E3 数据集（THEIA + CADETS） | 原始 `.bin.gz` 文件 |
| 0.2 | 编写 CDM → 溯源图适配器 | `cdm_adapter.py` |
| 0.3 | 时间窗口切割 + Ground Truth 标注 | 带标签的溯源子图集合 |
| 0.4 | 批量特征提取（FeatureExtractor） | `data/train_dataset.npz` |
| 0.5 | 数据集划分（训练/验证/测试） | `data/{train,val,test}_dataset.npz` |

### Phase 1：L1 集成模型（1天）

| 序号 | 任务 | 产出 |
|------|------|------|
| 1.1 | 修复 BehaviorModeler 特征名称 | 更新 `behavior_modeling.py` |
| 1.2 | 添加 XGBoost 有监督分类器 | 更新 `behavior_modeling.py` |
| 1.3 | 实现 Ensemble 集成检测器 | `ensemble_detector.py` |
| 1.4 | 训练 + 初步评估 | `models/ensemble_v1.0.pkl` |

### Phase 2：L2 VAE 分类器（2天）

| 序号 | 任务 | 产出 |
|------|------|------|
| 2.1 | 实现 VAE + MLP 分类器（PyTorch） | `vae_classifier.py` |
| 2.2 | 编写训练脚本（单卡GPU） | `train_vae.py` |
| 2.3 | 在 5880 服务器上训练 | `models/vae_classifier_v1.0.pt` |
| 2.4 | 集成到推理管道 | 更新 `behavior_modeling.py` |

### Phase 3：评估 + 可视化（1-2天）

| 序号 | 任务 | 产出 |
|------|------|------|
| 3.1 | 完善评估指标 + 可视化图表 | `visualization.py` |
| 3.2 | 性能基准测试 | `benchmark.py` |
| 3.3 | 跨系统泛化测试（THEIA→CADETS） | 泛化性报告 |
| 3.4 | 生成完整 HTML 评估报告 | `reports/eval_report_v1.0.html` |

### Phase 4：系统集成（1天）

| 序号 | 任务 | 产出 |
|------|------|------|
| 4.1 | 推理API集成到 pids_feature_api.py | 更新API端点 |
| 4.2 | 前端展示检测结果 | 更新 ThreatTracing.tsx |
| 4.3 | 在线特征持久化 | 数据积累机制 |

---

## 五、GPU服务器环境配置

```bash
# 基础环境
conda create -n pids python=3.10
conda activate pids

# PyTorch (CUDA 12.x)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121

# 数据处理
pip install fastavro          # CDM Avro格式解析
pip install numpy pandas networkx scipy

# 机器学习
pip install scikit-learn xgboost lightgbm shap

# 可视化
pip install matplotlib seaborn plotly

# API服务
pip install fastapi uvicorn

# 远期（L3 GNN）
# pip install torch-geometric pyg-lib torch-scatter torch-sparse
```

---

## 六、文件结构规划

```
PIDS/
├── feature_extraction/          # ✅ 已完成
│   └── feature_extractor.py     # 130维特征提取
│
├── behavior_modeling/           # 🔨 待实现
│   ├── __init__.py
│   ├── behavior_modeling.py     # L1: 传统ML（改进）
│   ├── ensemble_detector.py     # L1: 集成检测器
│   ├── vae_classifier.py        # L2: VAE+MLP分类器
│   ├── train_vae.py             # L2: 训练脚本
│   ├── cdm_adapter.py           # DARPA TC CDM数据适配器
│   ├── data_generator.py        # 合成数据增强（补充）
│   └── models/                  # 模型权重
│       ├── ensemble_v1.0.pkl
│       └── vae_classifier_v1.0.pt
│
├── evaluation/                  # 🔨 待实现
│   ├── __init__.py
│   ├── evaluation.py            # 评估指标（改进）
│   ├── visualization.py         # 评估可视化
│   ├── benchmark.py             # 性能基准
│   └── reports/                 # 评估报告
│       └── eval_report_v1.0.html
│
├── data/                        # 🔨 新增
│   ├── raw/                     # DARPA TC 原始数据
│   │   ├── ta1-theia-e3-official.bin.gz
│   │   └── ta1-cadets-e3-official.bin.gz
│   ├── processed/               # 处理后的溯源子图
│   ├── train_dataset.npz        # 训练集
│   ├── val_dataset.npz          # 验证集
│   └── test_dataset.npz         # 测试集
│
├── pids_feature_api.py          # FastAPI（集成推理）
└── requirements.txt             # 依赖
```

---

## 七、关键技术决策

| 决策点 | 选择 | 理由 |
|--------|------|------|
| **主力数据集** | DARPA TC E3 (THEIA+CADETS) | 学术界最权威的溯源图数据集，有Ground Truth |
| **数据格式** | CDM Avro → 我们的 {nodes,edges} | 编写适配器一次性转换 |
| **模型层级** | 三层(L1+L2+L3远期) | 真实数据支撑更强模型 |
| **L2框架** | PyTorch | 生态成熟，GPU支持好 |
| **L2架构** | VAE+MLP双任务 | 异常检测+分类一体化 |
| **泛化测试** | THEIA训练→CADETS测试 | 验证跨系统泛化能力 |
| **参考论文** | KAIROS (S&P 2024) | 同领域最新顶会工作 |

---

## 八、与 KAIROS 论文的关系

| 维度 | KAIROS | 我们的 PIDS |
|------|--------|------------|
| 数据集 | DARPA TC E3/E5 | DARPA TC E3（相同） |
| 特征提取 | 图嵌入(node2vec) | 130维结构化特征向量（我们的方案） |
| 检测方法 | 时序图神经网络 | L1集成ML + L2 VAE（更务实） |
| 溯源能力 | 自动生成攻击摘要图 | 因果溯源图可视化（已有前端） |
| 创新点 | 时序异常检测 | 130维多粒度特征 + 三层递进检测 |

> 我们不是复制 KAIROS，而是**借鉴其数据集和评估方法论**，用我们自己的 130 维特征向量 + 集成检测架构实现。

---

*方案版本: v3.0 | 预计总工期: 6-8天 | 核心改动: 采用 DARPA TC 真实数据集替代合成数据*
