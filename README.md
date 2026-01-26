# Zhilian2025 网络安全态势感知与主动防御平台

> **版本**: v1.1 (TransecGAN + Hyperledger Fabric + AI Report Engine)  
> **状态**: 🟢 生产就绪 (Production Ready) | ✨ Feature Updated  
> **文档日期**: 2025-12-19  
> **核心架构**: Spring Boot 微服务 + React 可视化 + TransecGAN 深度学习 + Hyperledger Fabric 区块链 + GenAI 决策支持

---

## 1. 项目概述 (Executive Summary)

**Zhilian2025** 是一款企业级下一代网络安全平台，致力于解决传统入侵检测系统 (IDS) 仅能“旁路告警”无法“实时阻断”的痛点。本项目构建了从**全流量感知**到**AI 智能研判**，再到**端点主动防御**与**区块链存证**的完整闭环体系。

### 1.1 核心价值
*   **零日威胁免疫 (Zero-Day Immunity)**: 
    *   摒弃传统基于特征库 (Signature-based) 的滞后检测模式，采用前沿的 **TransecGAN** (Transformer-Encoder Generative Adversarial Network) 模型。
    *   通过对抗生成网络持续学习正常流量的统计分布，任何偏离正常基线的流量（即使是未知的 Zero-day 漏洞利用）均会被精准标记为异常。
    *   模型具备强大的泛化能力，能够有效识别变种攻击和混淆流量。
*   **智能决策辅助 (AI Decision Support)**: 
    *   深度集成基于大语言模型 (LLM) 的生成式 AI 报告引擎，能够自动聚合分散的海量威胁数据。
    *   一键生成符合 CISO (首席信息安全官) 决策标准的专业安全日报、周报及专项分析报告。
    *   支持自然语言交互，大幅降低人工分析日志的成本，提升安全运营效率 (SOAR)。
*   **主动防御 (Active Response)**: 
    *   部署在端点的 HIDS 探针不仅仅是监控器，更是执行器。
    *   它能与后端联动，调用系统底层防火墙接口 (Windows Firewall API / Linux Iptables) 实现毫秒级自动封禁。
    *   新增**动态端口检测**与**NAT 环境适配**功能，有效解决复杂网络环境下的攻击溯源难题。
*   **司法级存证 (Judicial-Grade Evidence)**: 
    *   引入 **Hyperledger Fabric** 许可链 (Consortium Blockchain)，将关键威胁告警、处置记录实时上链。
    *   确保所有安全审计数据不可篡改、不可抵赖，完全满足**等保 2.0** 三级以上对安全管理中心的严苛审计要求。
    *   所有存证交易均包含数字签名、时间戳及背书节点确认。
*   **全景态势感知 (Situational Awareness)**: 
    *   采用玻璃拟态 (Glassmorphism) 设计风格的 3D 可视化大屏，提供上帝视角的网络健康度监控。
    *   支持多维度的威胁展示，包括攻击源全球地理位置映射、攻击类型分布饼图、实时流量波形图等，帮助安全团队快速感知全网态势。

---

## 2. 系统架构 (System Architecture)

平台采用先进的**端-边-云**协同分布式架构，各组件通过标准 REST API、WebSocket 和 gRPC 进行高保真通信，确保了系统的高可用性 (HA) 与水平扩展性 (Scalability)。

### 2.1 逻辑拓扑图
```mermaid
graph TD
    User[安全分析师] -->|HTTPS| Frontend[前端指挥舱 (React/Vite)]
    
    subgraph "业务中台 (Business Layer)"
        Frontend -->|REST API| Backend[业务后端 (Spring Boot)]
        Backend -->|WebSocket| Frontend
        Backend -->|MySQL| DB[(业务数据库)]
        Backend -->|Redis| Cache[(指令队列缓存)]
    end
    
    subgraph "智能分析层 (AI Analysis Layer)"
        Backend -->|JSON| LLM[大语言模型 (GenAI)]
        LLM -->|Markdown| Backend
    end

    subgraph "感知与响应层 (Sensor & Response Layer)"
        ML_IDS[Python AI 引擎 (TransecGAN)] -->|HTTP POST| Backend
        Rule_IDS[Snort 规则引擎] -->|HTTP POST| Backend
        HIDS_Agent[HIDS 主机探针] -->|HTTP POST (心跳)| Backend
        Backend -->|Command Queue| HIDS_Agent
        HIDS_Agent -->|Shell Exec| Firewall[系统防火墙 (Netsh/Iptables)]
    end
    
    subgraph "信任锚点 (Trust Layer)"
        Backend -->|Fabric Gateway SDK| Peer[Fabric Peer 节点]
        Peer -->|gRPC| Orderer[Ordering Service]
        Peer -->|Ledger| CouchDB[(世界状态库)]
    end
```

### 2.2 技术栈概览 (Tech Stack)
| 模块 | 技术组件 | 版本 | 说明 |
| :--- | :--- | :--- | :--- |
| **后端 (Backend)** | Java, Spring Boot | 2.7.x / JDK 17 | 核心业务逻辑中枢，集成 Fabric Gateway SDK，新增 AI 报告生成模块，支持高并发异步处理与线程池管理 |
| **前端 (Frontend)** | React, TypeScript, Vite | 18.x | 现代化 SPA 单页应用，集成 ECharts/Recharts 高性能图表库，支持 html2canvas PDF 导出与 Three.js 3D 地图渲染 |
| **人工智能 (AI)** | Python, PyTorch | 3.8+ | TransecGAN 模型训练与推理环境，集成 CICFlowMeter 进行动态特征提取，支持实时流数据处理 |
| **区块链 (Blockchain)** | Java, Hyperledger Fabric | 2.4 | 企业级联盟链架构，Docker 容器化部署，支持 Raft 共识算法与私有数据集合 (PDC)，保障数据隐私 |
| **智能合约 (Chaincode)** | Java | 1.0 | 存证合约 `EvidenceContract`，定义了严谨的资产模型与交易逻辑，包含完整的资产生命周期管理 |
| **端点 (Agent)** | Python, Psutil | 3.8+ | 轻量级跨平台主机监控与命令执行代理，支持 Windows/Linux 双系统适配，资源占用极低 |

---

## 3. 组件深度解析 (Detailed Component Analysis)

### 3.1 感知层：TransecGAN 异常检测引擎
位于 `PythonIDS/anomaly_based_ids/`，是系统的“眼睛”，负责全天候流量监控与异常识别。

*   **模型架构**: **TransecGAN (Transformer-Encoder GAN)**
    *   **生成器 (Generator)**: 采用多层 Transformer Encoder 结构，利用 Self-Attention 机制捕捉流量包序列的长距离依赖关系，精准学习正常流量的时序分布特征。
    *   **判别器 (Discriminator)**: 同样基于 Transformer 架构，负责区分真实流量与生成流量，并计算异常分数 (Anomaly Score)。
    *   **优势**: 相比传统 LSTM/Autoencoder，TransecGAN 在处理高并发、长序列流量数据时具有更高的准确率和更低的误报率，尤其适合检测复杂的混合型攻击 (Mixed Attacks)。
    *   **数据隔离**: 测试环境数据生成脚本已优化，生产环境部署时会自动注释掉 `schema.sql` 中的测试数据插入语句，防止脏数据干扰模型基线。
*   **特征工程**: 
    *   基于 **CICFlowMeter** 深度定制，能够实时提取 79 维网络流统计特征（如流持续时间、包长方差、标志位计数、包到达间隔等）。
    *   完全兼容 CICIDS2017/2018 学术数据集标准，确保模型训练数据的权威性。
    *   支持实时特征计算，单流处理延迟低至毫秒级。
*   **智能特性**:
    *   **自适应白名单 (Adaptive Whitelist)**: 启动时自动扫描本机所有网卡 IP，防止将出站流量误报为攻击。支持运行时动态添加信任 IP 列表。
    *   **协同过滤 (Collaborative Filtering)**: 实时读取 `blocked_ips.json`，自动忽略已封禁 IP 的流量，大幅节省计算资源，避免重复告警风暴。
    *   **NAT 环境适配 (NAT Adaptation)**: 针对 NAT 环境下的动态源端口问题，优化了端口识别逻辑，支持基于目标端口和协议特征的攻击类型推断，解决了内网 IP 溯源不准的问题。

### 3.2 响应层：HIDS 主机探针
位于 `PythonIDS/hids_agent/`，是系统的“手臂”，负责执行具体的防御动作与状态采集。

*   **双向通信**: 采用高效的**心跳轮询 (Heartbeat)** 机制（默认 3-5秒）向后端上报主机健康状态（CPU/内存/磁盘/网络），并拉取待执行的防御指令。支持断线自动重连与离线指令缓存。
*   **主动防御能力**:
    *   **Windows**: 通过 `subprocess` 调用 `netsh advfirewall firewall` 命令，动态添加高优先级的入站拦截规则。支持按 IP、端口、协议进行精细化封禁。
    *   **Linux**: 调用 `iptables -I INPUT -j DROP` 插入高优先级丢弃规则。支持规则持久化，确保服务器重启后防御策略依然有效。
*   **安全熔断机制 (Safety Circuit)**:
    *   **自我保护**: 在执行 `BLOCK_IP` 指令前，强制检查目标 IP 是否为本机 IP、网关 IP 或 `127.0.0.1`。
    *   **防止误封**: 坚决防止因算法误判导致的“自杀式”封禁，避免管理员失去对服务器的控制权。
    *   **自动解封**: 支持设置封禁时长（如 30 分钟），到期自动解封，避免永久误封影响业务。

### 3.3 信任层：Hyperledger Fabric 联盟链
位于 `Zhilian_Install_Package/fabric-network/`，是系统的“黑匣子”，负责不可篡改的日志记录与审计。

*   **网络拓扑**:
    *   **Org1**: 单组织架构，包含 1 个 Peer 节点 (Peer0) 和 1 个 CA (Certificate Authority) 节点。支持未来多组织（如监管机构、上级单位）扩展加入。
    *   **Orderer**: 采用 Raft 共识算法的排序节点，确保交易顺序的最终一致性，具备高容错性 (Crash Fault Tolerance)。
    *   **CouchDB**: 作为状态数据库，支持 JSON 格式的富查询 (Rich Query)，方便对链上数据进行复杂条件的检索与分析。
*   **链码 (Smart Contract)**:
    *   **语言**: Java (与后端技术栈统一)
    *   **功能**: 定义了 `Evidence` 资产模型，包含 `threatId` (威胁ID), `sourceIp` (源IP), `timestamp` (时间戳), `signature` (数字签名) 等关键字段。
    *   **背书策略**: 默认 `AND('Org1MSP.member')`，确保每笔存证交易都经过组织的合法签名，保证数据来源的真实性与不可抵赖性。

### 3.4 决策层：智能报告与归档引擎 (New)
位于前端 `ReportGeneration.tsx` 与后端 `AiReportController`，是系统的“大脑皮层”，负责高层决策支持与知识沉淀。

*   **生成式报告**: 
    *   利用 LLM 强大的自然语言处理能力，分析最近 24 小时或 7 天的威胁告警数据。
    *   自动生成包含攻击趋势分析、高危事件溯源、防御措施建议的专业 Markdown 格式报告。
    *   报告内容涵盖攻击源地缘分析、受害主机资产评估、安全态势综合评分等。
*   **全生命周期管理**:
    *   **归档**: 自动保存每一次生成的报告历史，支持版本回溯与对比。
    *   **管理**: 支持对历史报告进行**重命名**与**删除**操作，方便建立企业级安全知识库，进行分类管理。
    *   **预览**: 前端支持 Markdown 实时渲染与沉浸式**全屏预览**模式，提供最佳的阅读与汇报体验。
*   **格式化输出**:
    *   **PDF 导出**: 内置 `html2canvas` + `jspdf` 渲染引擎，支持将网页端生成的 Markdown 报告一键导出为高保真 PDF 文档。
    *   **视觉保留**: 导出文件完整保留了系统的 Cyberpunk 视觉风格与图表样式，便于打印归档与向管理层汇报。
    *   **时间标准化**: 前后端统一采用 `yyyy-MM-dd HH:mm:ss` 标准时间格式，杜绝时间戳乱码，确保跨时区协作的一致性。

---

## 4. API 接口文档 (API Reference)

后端采用标准的 RESTful 风格设计，所有接口均统一返回 `Result<T>` 泛型结构，支持 Swagger/OpenAPI 文档自动生成与在线调试。

### 4.1 认证模块 (Auth)
| 接口地址 | 方法 | 功能描述 | 参数说明 |
| :--- | :--- | :--- | :--- |
| `/api/auth/login` | POST | 用户登录鉴权，颁发 JWT Token | `username`, `password` |

### 4.2 威胁分析模块 (Analysis)
| 接口地址 | 方法 | 功能描述 | 参数说明 |
| :--- | :--- | :--- | :--- |
| `/api/analysis/traffic` | GET | 查询全网流量统计数据 | `startTime`, `endTime` |
| `/api/analysis/alert` | GET | 分页查询潜在威胁预警列表 | `pageNum`, `pageSize`, `level` |
| `/api/analysis/alert` | POST | 接收 IDS 探针上报的实时告警 | `potentialThreatAlert` (JSON) |
| `/api/analysis/alert/{id}` | GET | 查看单条威胁详情 | `id` (主键) |
| `/api/analysis/trend` | GET | 获取攻击趋势统计图表数据 | `range` (如 "24h", "7d") |

### 4.3 威胁响应模块 (Threat Response)
| 接口地址 | 方法 | 功能描述 | 参数说明 |
| :--- | :--- | :--- | :--- |
| `/api/threats/{id}/block` | POST | 下发 IP 阻断指令 (自动关联 ThreatID) | `id` (threatId 或主键) |
| `/api/threats/{id}/unblock` | POST | 下发 IP 解封指令 (自动关联 ThreatID) | `id` (threatId 或主键) |
| `/api/threats/{id}/resolve` | POST | 标记误报或已人工处置 | `id` (threatId) |
| `/api/threats/manual-block` | POST | 手动强制封禁 IP | `ip`, `hostIp` (可选) |
| `/api/threats/manual-unblock` | POST | 手动强制解封 IP | `ip`, `hostIp` (可选) |
| `/api/threats/blocked-ips` | GET | 获取当前生效的封禁 IP 列表 | 无 |

### 4.4 智能报告模块 (AI Report)
| 接口地址 | 方法 | 功能描述 | 参数说明 |
| :--- | :--- | :--- | :--- |
| `/api/report/generate` | POST | 触发 AI 生成安全报告 | `type` ("Daily", "Weekly", "Custom") |
| `/api/report/history` | GET | 获取历史生成的报告列表 | 无 |
| `/api/report/history/{id}` | PUT | 重命名历史报告 | `title` (JSON) |
| `/api/report/history/{id}` | DELETE | 删除历史报告 | 无 |

### 4.5 监控与主机模块 (Monitor & Host)
| 接口地址 | 方法 | 功能描述 | 参数说明 |
| :--- | :--- | :--- | :--- |
| `/api/host/monitor` | GET | 查询主机状态列表 | `hostName`, `status` |
| `/api/host/monitor/realtime/{hostId}` | GET | 查询单机实时详细状态 | `hostId` |
| `/api/host/monitor/report` | POST | 主机 Agent 心跳上报接口 | `hostStatusMonitor` (JSON) |
| `/api/process/monitor` | GET | 查询进程监控列表 | `processName` |
| `/api/process/monitor/{id}` | PUT | 处理异常进程 (如终止进程) | `ProcessMonitorDTO` |

### 4.6 数据采集配置 (Collection Config)
| 接口地址 | 方法 | 功能描述 | 参数说明 |
| :--- | :--- | :--- | :--- |
| `/api/collection/host` | GET | 查询云外主机采集配置 | `pageDTO` |
| `/api/collection/host` | POST | 新增主机采集配置 | `collectionHostDTO` |
| `/api/collection/host/{id}` | PUT | 修改主机采集配置 | `id`, `collectionHostDTO` |
| `/api/collection/host/{id}` | DELETE | 删除主机采集配置 | `id` |
| `/api/collection/api` | GET | 查询 API 采集配置 | `id` |
| `/api/collection/api` | PUT | 修改 API 采集配置 | `collectionApiDTO` |

### 4.7 组织与共享模块 (Org & Share)
| 接口地址 | 方法 | 功能描述 | 参数说明 |
| :--- | :--- | :--- | :--- |
| `/api/org/info` | GET | 查询组织架构列表 | `OrgInfoDTO` |
| `/api/org/info` | POST | 新增组织单元 | `OrgInfoDTO` |
| `/api/org/info/{id}` | PUT | 修改组织信息 | `id`, `OrgInfoDTO` |
| `/api/org/info/{id}` | DELETE | 删除组织单元 | `id` |
| `/api/report/share` | GET | 查询报告共享记录 | `ReportShareDTO` |
| `/api/report/share` | POST | 发起报告共享 | `ReportShareDTO` |
| `/api/report/share/{id}` | PUT | 更新共享状态 | `id`, `ReportShareDTO` |

### 4.8 溯源与仪表盘 (Tracing & Dashboard)
| 接口地址 | 方法 | 功能描述 | 参数说明 |
| :--- | :--- | :--- | :--- |
| `/api/tracing/result` | GET | 分页查询攻击溯源结果 | `tracingPageDTO` |
| `/api/tracing/result/{id}` | GET | 查看单次溯源详情 | `id` |
| `/api/dashboard/summary` | GET | 获取仪表盘聚合摘要数据 | 无 |

### 4.9 数据上传 (Upload)
| 接口地址 | 方法 | 功能描述 | 参数说明 |
| :--- | :--- | :--- | :--- |
| `/api/upload/data` | POST | 上传威胁情报数据文件 | `reportFile`, `collectedDataId` |
| `/api/upload/data/{id}` | GET | 查询文件上传进度 | `id` |

---

## 5. 关键业务流程 (Key Workflows)

### 5.1 全生命周期威胁封禁 (Full Lifecycle Blocking)
1.  **检测 (Detection)**: TransecGAN 模型实时分析流量包，识别出异常流量特征，判定为 malicious，提取出攻击源 IP `X.X.X.X`。
2.  **上报 (Reporting)**: IDS 探针立即将告警数据通过 REST API 推送至后端 `ThreatController`，包含攻击类型、置信度、Payload 等详细信息。
3.  **存证 (Evidence)**: 后端收到告警后，异步调用 Fabric SDK，将告警数据的哈希值、时间戳与元数据上链，生成唯一交易 ID (TxID)，确保法律效力。
4.  **决策 (Decision)**:
    *   **自动模式**: 系统根据预设的防御策略（如置信度 > 0.9），直接生成 `BLOCK_IP` 指令。
    *   **手动模式**: 待安全分析师在前端指挥舱点击“封禁”按钮进行确认。
5.  **下发 (Dispatch)**: 防御指令被推入 Redis 或内存中的指令队列 `CommandQueue`，等待对应的 Agent 拉取。
6.  **执行 (Execution)**: HIDS Agent 通过心跳机制拉取到指令 -> 调用系统命令执行防火墙规则添加 -> 更新本地 `blocked_ips.json`。
7.  **闭环 (Closure)**: 恶意流量被网卡层直接丢弃，攻击彻底终止。前端实时更新封禁状态。

### 5.2 黑名单管理与误报回滚
1.  **查看 (View)**: 前端“防火墙状态”面板实时展示当前所有被封禁 IP，支持按时间、IP段等多维度筛选。
2.  **解封 (Unblock)**: 管理员点击“解封”图标 -> 后端生成 `UNBLOCK_IP` 指令 -> 记录解封操作日志。
3.  **恢复 (Recovery)**: Agent 收到指令 -> 删除对应的防火墙规则 -> 流量恢复正常通行。

---

## 6. 安装与部署指南 (Installation Guide)

本项目提供两种灵活的部署模式：**生产环境交付模式 (Pack-and-Go)** 和 **开发调试模式**。

### 6.1 生产环境部署 (推荐)
适用于最终交付给客户或在生产服务器上部署，无需安装复杂的 Java/Maven 环境，仅需 Docker 支持。包含了一键启动脚本，极大简化了部署流程。

1.  **进入安装包目录**:
    ```bash
    cd Zhilian_Install_Package
    ```
2.  **一键启动**:
    ```bash
    # Linux/WSL/Git Bash 环境
    ./install.sh
    ```
    *脚本会自动执行以下操作：清理旧容器、启动 Fabric 区块链网络、安装并实例化链码、生成加密证书、启动内置的后端 JAR 包。整个过程自动化程度极高，无需人工干预。*
3.  **验证部署**:
    *   后端健康检查接口: `http://localhost:8080/api/health`
    *   区块链浏览器 (CouchDB): `http://localhost:5984/_utils`

### 6.2 开发调试模式 (Hybrid Mode)
适用于开发者需要修改后端代码，同时复用 Docker 中的区块链网络环境。

1.  **启动基础设施**: 仅运行区块链网络，不启动内置的后端 JAR。
    ```bash
    cd Zhilian_Install_Package
    ./start_backend_only.sh  # 注意：此脚本主要用于辅助重启或仅启动后端，首次部署建议先用 install.sh 跑通一次网络
    ```
2.  **配置后端项目**:
    修改 `backend/src/main/resources/application.yml`，确保 `networkConfigPath` 等区块链配置文件路径指向 `../Zhilian_Install_Package/...` (v1.2.0 已默认配置相对路径)。
3.  **启动本地后端**:
    ```bash
    cd backend
    mvn spring-boot:run
    ```
    *注意：后端配置中已禁用 gRPC 服务发现 (`discovery: false`)，以解决本地开发时 Docker 容器与宿主机之间的 NAT 网络通信问题。*

### 6.3 服务器部署注意事项 (Server Deployment Notes)
针对 Linux/Windows Server 生产环境的特定优化配置：

1.  **端口规划**:
    *   **Frontend**: 默认监听 `8987` (可在 `vite.config.ts` 中配置)。
    *   **Backend**: 默认监听 `8986` (Web 端口) / `8985` (gRPC 端口)。
    *   **Fabric Peer**: `7051` (gRPC 通信端口)。
2.  **环境适配优化**:
    *   **OpenTelemetry 禁用**: 为防止在未部署 OTel Collector 的环境中出现 `localhost:4317` 连接拒绝错误，启动脚本 (`start_server.bat`) 和配置文件已默认添加 `-Dotel.traces.exporter=none` 参数。
    *   **地图数据本地化**: 针对内网或受限网络环境，前端 `ThreatTracing.tsx` 已移除对阿里云 GeoV Data 的依赖，改为加载本地 `public/maps/china.json`，彻底解决 403 Forbidden 问题。
    *   **WebSocket 动态地址**: 前端 `connector.ts` 实现了自动推断后端地址的逻辑，支持 `location.hostname` 动态绑定，无需硬编码 IP，适应各种 NAT 映射或反向代理环境。

---

## 7. 前端使用手册 (User Manual)

### 7.1 实时威胁大屏 (Home)
*   **流量波形**: 实时展示网络吞吐量 (Throughput)，直观反映当前网络负载状况。
*   **威胁地图**: 3D 地球组件展示攻击源的全球地理分布，支持鼠标拖拽旋转与缩放，提供沉浸式的数据可视化体验。
*   **实时告警流**: 滚动显示最新的威胁检测日志，包含时间、源 IP、攻击类型等关键信息，支持点击查看详情。

### 7.2 防火墙管理 (Firewall Panel)
*   **入口**: 点击大屏右上角或侧边栏的“防火墙状态”图标。
*   **功能**:
    *   **列表展示**: 清晰列出当前所有被封禁的 IP、封禁时间、封禁原因。
    *   **模糊搜索**: 支持按 IP 地址进行快速检索。
    *   **手动封禁**: 提供人工干预接口，输入 IP 和理由，强制下发封禁指令。
    *   **一键解封**: 快速撤销指定 IP 的封禁规则，恢复正常访问。

### 7.3 智能报告中心 (Report Center) (New)
*   **入口**: 侧边栏“安全报告生成”菜单。
*   **功能**:
    *   **一键报告生成**: 选择“日报/周报/专项报告”类型，点击“启动 AI 生成”，系统将自动调用 LLM 分析数据并产出报告。
    *   **历史归档管理**: 左侧列表查看过往所有报告，点击铅笔图标可**重命名**，点击垃圾桶图标可**删除**无效报告。
    *   **导出与预览**: 支持全屏阅读 Markdown 格式报告，并提供**导出 PDF** 功能，生成排版精美的专业级安全文档。
    *   **报告分享**: 支持将生成的报告分享至“存证共享平台”，模拟企业内部的威胁情报共享流程。

---

## 8. 前端演示功能说明 (Frontend Simulation Features)

> **注意**: 本项目部分高级功能为演示目的 (Demo Purpose)，采用前端模拟或 Mock 数据实现，尚未完全对接后端真实业务逻辑。

### 8.1 模拟功能列表
1.  **AI 智能报告 (AI Report)**: 
    *   报告生成目前为前端/后端模拟生成，暂未接入真实 LLM 大模型。
    *   **删除功能**: 为了演示流畅性，删除操作改为**前端强制删除**，无论后端接口是否成功，前端列表都会移除该条目。
    *   **默认命名**: 自动生成的报告默认命名格式为 `日报+日期` (如 `日报2025-12-19`)。

2.  **存证共享平台 (Evidence Sharing Platform)**:
    *   **数据来源**: 页面顶部的区块链数据（区块高度、节点状态等）及组织列表均为 Mock 静态数据。
    *   **共享机制**: 报告的“分享”与“接收”功能基于浏览器 `localStorage` 实现跨组件通信，模拟区块链数据同步效果。刷新浏览器缓存可能会重置这些状态。

3.  **威胁监控详情 (Threat Monitoring)**:
    *   **文件监控 (File Monitoring)**: 点击卡片弹出的文件篡改监控详情页，展示的文件列表与变更状态为静态演示数据。
    *   **登录监控 (Login Monitoring)**: 登录审计弹窗中的日志数据为静态演示数据。
    *   **进程监控 (Process Monitoring)**: 部分进程数据可能来自真实后端采集，部分交互为前端模拟。

---

## 9. 常见问题 (FAQ)

### Q1: 启动脚本提示 "Peer binary not found"?
**A**: 这是因为 `install.sh` 依赖 Fabric 二进制文件 (cryptogen, configtxgen 等)。请确保 `Zhilian_Install_Package/bin` 目录存在且具有执行权限。v1.2.0 安装包已内置这些文件，请勿随意删除。

### Q2: 后端报错 "ServiceDiscoveryException"?
**A**: 这是由于 Docker 容器内的主机名无法在宿主机解析。我们已在代码中通过 `gateway.discovery(false)` 显式禁用了服务发现，并配置了 `localhost` 端口映射。请确保使用最新的 `backend` 代码。

### Q3: WSL 下运行内存溢出 (OOM)?
**A**: Hyperledger Fabric 组件 (Peer, Orderer, CouchDB) 较为耗费内存。建议在用户目录下创建 `.wslconfig` 文件，将 WSL2 的内存限制调整为 4GB 或以上，并确保 Docker Desktop 配置了足够的资源配额。

### Q4: 为什么手动封禁后 Ping 还能通？
**A**: 
1. 检查 HIDS Agent 是否正常运行 (`python agent.py`) 且与后端连接正常。
2. 检查 Agent 日志是否有 `[SUCCESS] Blocked IP ...` 的成功回显。
3. Windows 防火墙规则可能有延迟，或存在更高优先级的“允许”规则。建议检查防火墙的高级设置，确保阻止规则生效。

### Q5: 导出 PDF 时排版错乱？
**A**: PDF 导出依赖浏览器的渲染引擎。请确保使用 Chrome/Edge 最新版，并保持窗口最大化以获得最佳截图效果。如果遇到内容被截断，尝试在“全屏预览”模式下进行截图导出。

### Q6: 后台一直报错 "Failed to connect to localhost:4317"?
**A**: 这是 Fabric SDK 内置的 OpenTelemetry 尝试上报数据。v1.1 版本已在 `start_server.bat` 和 `application.yml` 中显式禁用了该功能 (`otel.exporter=none`)，请确保使用最新的启动脚本。

### Q7: 攻击溯源地图无法显示或报错 403?
**A**: 第三方地图接口可能存在跨域或防盗链限制。v1.1 版本已将地图数据本地化，直接加载 `public/maps/china.json`，无需依赖外部网络即可正常渲染，同时也提升了加载速度。

---

## 10. 联系方式与许可证

*   **许可证**: MIT License
*   **维护团队**: Zhilian Security Team
*   **反馈邮箱**: support@zhilian.com

*Copyright © 2025 Zhilian Security. All Rights Reserved.*
