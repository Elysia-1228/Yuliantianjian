# 御链天鉴 · YuLianTianJian

> **网络安全智能分析与威胁溯源系统**  
> An AI-powered Intrusion Detection & Threat Tracing System with Blockchain Auditing

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17-orange.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.7-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://python.org/)
[![Hyperledger Fabric](https://img.shields.io/badge/Fabric-2.2.5-2F3134.svg)](https://hyperledger-fabric.readthedocs.io/)

---

## 📖 项目简介

**御链天鉴**是一套面向企业/园区网络的全栈智能入侵检测平台，融合了以下核心技术：

- 🔍 **NIDS（网络层检测）**：基于 TransEC-GAN 深度学习模型 + Snort 风格规则引擎，实时抓包分析，覆盖 35+ 攻击类型
- 🖥️ **PIDS（主机层检测）**：基于 KAIROS 因果溯源图，提取 130 维特征，L1+L2 双层异常检测（AUC=0.987）
- ⛓️ **区块链存证**：威胁告警通过 Hyperledger Fabric 上链，确保审计日志不可篡改
- 🗺️ **可视化溯源**：AntV G6 渲染攻击因果链路图，ECharts 地理态势感知，雷达图特征可视化
- 🤖 **AI 报告**：集成 Google Gemini API，自动生成结构化安全分析报告

---

## ✨ 核心功能

### 🛡️ 双引擎入侵检测

| 功能 | NIDS | PIDS |
|------|------|------|
| 检测层次 | 网络流量层 | 主机进程层 |
| 核心算法 | TransEC-GAN Discriminator | L1集成检测器 + L2 VAE分类器 |
| 特征维度 | 78维（CICIDS2017标准） | 130维（图结构/节点/边/序列/语义） |
| 检测精度 | 8类攻击分类 | AUC=0.987, F1=0.923 |
| 攻击类型 | 35+种（DoS/DDoS/PortScan/BruteForce/WebAttack/Infiltration/Bot） | 异常行为检测 |
| 响应速度 | 实时（逐包分析） | 毫秒级 |

### 📊 威胁可视化

- **实时告警大屏**：WebSocket 推送，毫秒级延迟，按攻击者IP聚合展示
- **地理态势地图**：ECharts + GeoJSON，攻击来源全球分布
- **PIDS 因果溯源图**：AntV G6 渲染进程→文件→网络因果链路，支持增量动态扩展
- **130维特征全景图**：点阵热力图 + 5维雷达图（图结构/节点/边/序列/语义）
- **攻击趋势分析**：24h/7d/30d 多时间维度

### ⛓️ 区块链存证

- NIDS 告警自动上链（`/api/chain/alert`）
- 溯源记录上链（`/api/chain/trace`）
- 支持按类型富查询链上数据
- AES 字段级加密（`impactScope` 等敏感字段）

---

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────┐
│              FrontCode (React 18)            │
│   React + TypeScript + Vite + TailwindCSS   │
│   AntV G6 / ECharts / Recharts / Gemini     │
│              Port: 5173 (dev)                │
└──────────────┬──────────────────────────────┘
               │  REST API + WebSocket (/ids/stream)
               ▼
┌──────────────────────────────────────────────┐
│           BackCode (Spring Boot 3.5.7)        │
│        Java 17 + MyBatis + Druid             │
│              Port: 8985                       │
└──────┬──────────────┬──────────────┬─────────┘
       │              │              │
       ▼              ▼              ▼
┌───────────┐  ┌─────────────┐  ┌──────────────┐
│  MySQL 8  │  │  PythonIDS  │  │   backend    │
│ net_safe  │  │  NIDS:send  │  │ Fabric 2.2.5 │
│   13表    │  │  PIDS:7890  │  │  Port: 8986  │
└───────────┘  └─────────────┘  └──────────────┘
```

---

## 📁 项目结构

```
YuLianTianJian/
├── FrontCode/          # React 前端（11个页面）
├── BackCode/           # Java 主后端（Spring Boot 3.5.7）
├── PythonIDS/
│   ├── NIDS/           # 网络入侵检测（TransEC-GAN + 规则引擎）
│   └── PIDS/           # 主机入侵检测（FastAPI :7890，130维特征）
├── backend/            # 区块链网关（Hyperledger Fabric 2.2.5）
├── RuleBasedIDS/       # 签名规则引擎（Flask UI）
├── scripts/            # 启动脚本 + 主机监控Agent
└── docs/               # 技术文档
```

详细结构请参阅 [docs/PROJECT_DOCUMENTATION.md](docs/PROJECT_DOCUMENTATION.md)

---

## 🚀 快速开始

### 环境要求

| 组件 | 版本 | 必须 |
|------|------|------|
| JDK | 17 | ✅ |
| Maven | 3.6+ | ✅ |
| MySQL | 8.0 | ✅ |
| Python | 3.8+ | ✅ |
| Node.js | 18+ | ✅ |
| WSL2 + Docker | - | 仅区块链功能需要 |

### 1. 克隆项目

```bash
git clone https://github.com/你的用户名/YuLianTianJian.git
cd YuLianTianJian
```

### 2. 初始化数据库

```sql
CREATE DATABASE net_safe CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE net_safe;
SOURCE BackCode/src/main/resources/schema.sql;
```

### 3. 配置后端

编辑 `BackCode/application-dev.yml`，填入你的 MySQL 信息：
```yaml
safe:
  datasource:
    host: localhost
    port: 3306
    database: net_safe
    username: root
    password: 你的MySQL密码
```

### 4. 启动各组件

```bash
# 终端1：启动 Java 主后端（端口8985）
cd BackCode
mvn spring-boot:run

# 终端2：启动 PIDS FastAPI（端口7890）
cd PythonIDS
python -m PIDS.pids_feature_api

# 终端3：启动前端（端口5173）
cd FrontCode
npm install
npm run dev

# 终端4（可选，需要管理员权限）：启动 NIDS 实时检测
cd PythonIDS/NIDS
python realtime_detection.py

# 终端5（可选）：攻击模拟（用于测试）
cd PythonIDS/NIDS/attack_scripts
python quick_attack.py
```

### 5. 访问系统

打开浏览器访问：**http://localhost:5173**

默认账号：查看数据库 `sys_user` 表或使用初始化时设置的账号。

---

## 📡 核心 API 速览

### NIDS 告警推送（Python → Java）
```
POST http://localhost:8985/api/analysis/alert
Body: { threatId, threatLevel, sourceIp, targetIp, attackType, affectedProcess, ... }
```

### 溯源图谱生成（前端 → Java）
```
POST http://localhost:8985/api/tracing/result/generate-graph
Body: { source_ip, target_ip, attack_type }
```

### PIDS 特征提取（前端直调）
```
POST http://localhost:7890/api/pids/features/extract
Body: { graphData: { nodes, edges }, threatId }
```

### WebSocket 实时告警
```
ws://localhost:8985/ids/stream
```

完整接口文档：[docs/PROJECT_DOCUMENTATION.md](docs/PROJECT_DOCUMENTATION.md)

---

## 🔬 技术细节

### NIDS：TransEC-GAN 检测引擎

```
抓包 → FlowStats(78维) → StandardScaler → PCA(25维)
     → TransformerEncoder → Discriminator
     → real_score + 8类概率 → 威胁等级(1~5)
```

- 训练数据集：CICIDS2017（8类：Benign + 7种攻击）
- 模型权重：`best_model_4x5880_max.pth`
- OOD 检测阈值：`attack_prob > 0.92 & confidence > 0.80`

### PIDS：130维因果图特征

| 特征组 | 维度范围 | 维度数 | 说明 |
|--------|---------|--------|------|
| 图结构特征 | 0~14 | 15 | 节点数/边密度/聚类系数等 |
| 节点特征 | 15~54 | 40 | 进程/文件/网络节点统计 |
| 边特征 | 55~79 | 25 | 执行/读写/连接/Fork边计数 |
| 序列特征 | 80~109 | 30 | 时间间隔/爆发模式/操作熵 |
| 语义特征 | 110~129 | 20 | SQL注入/XSS/提权/RCE得分 |

### 区块链：Hyperledger Fabric 2.2.5

- 通道：`mychannel`
- 链码：`evidence`（支持 `submitEvidenceBatch` / `queryEvidenceByType`）
- 加密字段：`orgName`, `impactScope`, `reportUrl`（AES）
- 鉴权：`X-API-KEY` 请求头

---

## 📋 35+ 攻击类型覆盖

| 大类 | 子类型 | 威胁等级 |
|------|--------|---------|
| **DoS** | SYN Flood / UDP Flood / ICMP Flood / Slowloris / R.U.D.Y. / HTTP Flood / HTTPS Flood / TCP RST Flood | 3 |
| **DDoS** | HTTP Flood / DNS Flood / NTP Amplification / SSDP Amplification / UDP Flood / SNMP Amplification | 4 |
| **PortScan** | SYN / FIN / NULL / XMAS / UDP / RST Scan | 2~3 |
| **BruteForce** | SSH / FTP / RDP / MySQL / Telnet / SMTP / PostgreSQL | 3~4 |
| **WebAttack** | SQL Injection / XSS / Path Traversal / Command Injection / CSRF | 3~**5** |
| **Infiltration** | Reverse Shell / Data Exfiltration / Covert Channel / Lateral Movement | 4~**5** |
| **Bot** | C&C Communication / Heartbeat / DNS Tunnel / IRC / Beacon | 4~**5** |

---

## 👥 开发团队

| 角色 | 负责模块 |
|------|---------|
| 开发者 A（本仓库主要提交者） | NIDS / PIDS / Java主后端 / React前端 |
| 开发者 B | 区块链网关（Hyperledger Fabric） |

---

## 📚 文档

| 文档 | 说明 |
|------|------|
| [PROJECT_DOCUMENTATION.md](docs/PROJECT_DOCUMENTATION.md) | 完整技术文档（架构/接口/特征/数据库） |
| [MERGE_GUIDE.md](docs/MERGE_GUIDE.md) | 代码合并集成指南 |
| [BackCode/AI_ENGINE_INTEGRATION.md](BackCode/AI_ENGINE_INTEGRATION.md) | AI引擎集成说明 |
| [backend/README.md](backend/README.md) | 区块链网关部署说明 |

---

## 🔒 安全说明

⚠️ **上传至 GitHub 前请务必处理以下敏感信息**：

- `BackCode/application-dev.yml` 中的 MySQL 密码
- `BackCode/application.yml` 中的 JWT 密钥
- `backend/` 中的 Fabric 证书路径
- AI 服务器地址（`10.138.50.151`）

建议通过环境变量传入敏感配置，具体方法参见 [docs/MERGE_GUIDE.md](docs/MERGE_GUIDE.md)。

---

## 📄 License

MIT License - 详见 [LICENSE](LICENSE) 文件。

---

<div align="center">

**御链天鉴** · 以链为鉴，御威于先

*Built with ❤️ by the YuLianTianJian Team*

</div>
