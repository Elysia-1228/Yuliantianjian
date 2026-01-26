# 区块链业务综合控制台（Backend）

## 简介
- Spring Boot 后端，集成 Hyperledger Fabric Gateway 完成上链与查询
- 异步批量处理（队列聚合 + 熔断重试），并通过 WebSocket 实时推送结果
- 前端单页控制台 `src/main/resources/static/index.html`，支持数据模拟与监控
- 基础安全与运维：API Key 鉴权、AOP 审计、Actuator 健康检查、选择性字段加密

## 强制前置条件（WSL + Fabric Docker 网络）
- 未在 WSL2 内部署并运行 Hyperledger Fabric 的 Docker Compose 网络时，后端无法连接到区块链网络，项目不可运行。
- `application.yml` 中的网关配置指向 WSL 中 `fabric-samples/test-network` 生成的本地文件与证书，需在 WSL 环境内存在：
  - `connection-org1.yaml`、用户证书与私钥目录
  - 通道名称为 `mychannel`，合约名称为 `evidence`
- 请在 WSL 中启动后端（而非 Windows 主机），推荐命令：`mvn spring-boot:run`

### 在 WSL 中部署 Fabric 网络
- 安装与准备
  - 开启 WSL2 并安装 Linux 发行版（如 Ubuntu 22.04）
  - 在 WSL 中安装 Docker 或启用 Docker Desktop 的 WSL 集成
- 获取并启动 test-network
  - `git clone https://github.com/hyperledger/fabric-samples ~/hyperledger/fabric-samples`
  - `cd ~/hyperledger/fabric-samples/test-network`
  - `./network.sh up createChannel -c mychannel -ca`
- 部署链码（按你的链码路径调整）
  - `./network.sh deployCC -c mychannel -ccn evidence -ccl java -ccp <你的链码路径>`
- 验证
  - `docker ps` 查看 `peer`、`orderer`、`ca` 等容器运行中
  - 确认 `~/hyperledger/fabric-samples/test-network/organizations/...` 下生成 `connection-org1.yaml`、证书与私钥

### 在 WSL 中启动后端
- 构建：`mvn -q -DskipTests package`
- 运行：`mvn spring-boot:run`
- 访问：`http://localhost:8080/index.html`

## 主要特性
- 异步批量上链：聚合入队数据为批次提交到链码 `submitEvidenceBatch`
- 富查询：按类型查询（`/api/chain/list/{type}`），需链码实现 `queryEvidenceByType`
- WebSocket 推送：订阅 `/topic/alerts` 获得批量成功/失败消息
- 安全与合规：
  - API Key 鉴权（请求头 `X-API-KEY`）
  - 选择性字段加密（AES）：`ORG.orgName`、`ALERT.impactScope`、`REPORT.reportUrl`
  - AOP 审计日志、CORS 收束、Actuator 健康检查

## 目录结构
- 后端入口：`src/main/java/com/example/blockchain/Application.java`
- 控制器与业务接口：`src/main/java/com/example/blockchain/BlockchainController.java`
  - 查询按类型：`c:\Users\35742\Desktop\backend\src\main\java\com\example\blockchain\BlockchainController.java:145-165`
- 异步批处理与推送：`src/main/java/com/example/blockchain/service/AsyncService.java`
  - 批量处理核心：`c:\Users\35742\Desktop\backend\src\main\java\com\example\blockchain\service\AsyncService.java:69-104`
- WebSocket 配置：`src/main/java/com/example/blockchain/config/WebSocketConfig.java`
- 安全与审计：
  - API Key 拦截器：`src/main/java/com/example/blockchain/interceptor/AuthInterceptor.java`
  - 审计切面：`src/main/java/com/example/blockchain/aspect/AuditLogAspect.java`
  - AES 工具：`src/main/java/com/example/blockchain/util/AESUtil.java`
- 前端单页：`src/main/resources/static/index.html`

## 快速开始
- 依赖：JDK 8+/11+，Maven 3.6+
- 构建：
  - `mvn -q -DskipTests package`
- 运行（任选其一）：
  - 在 WSL 中运行：`mvn spring-boot:run`
  - 如需 Jar 方式：在 WSL 中执行 `java -jar target/backend-0.0.1-SNAPSHOT.jar`
- 访问：
  - 控制台页面：`http://localhost:8080/index.html`
  - Actuator：`http://localhost:8080/actuator/health`

## 配置
- 修改 `src/main/resources/application.yml` 的 Fabric 网关配置与通道/组织参数（根据你的网络环境）
- API Key：请求头带 `X-API-KEY: secret-api-key`（可在拦截器中更改）

## 接口速览
- 基础接口
  - `POST /api/evidence` 入队上链（同步入队，异步上链）
  - `GET /api/evidence/{id}` 查询单条
  - `POST /api/verify` 校验哈希匹配
- 业务接口（按类型）
  - `POST /api/chain/org`（OrgInfoDTO）
  - `POST /api/chain/alert`（ThreatAlertDTO）
  - `POST /api/chain/traffic`（TrafficStatDTO）
  - `POST /api/chain/report`（ReportConfigDTO）
  - `POST /api/chain/trace`（SourceTracingDTO）
- 富查询（链码需支持 `queryEvidenceByType`）
  - `GET /api/chain/list/{type}`，`type` ∈ `ORG | ALERT | TRAFFIC | REPORT | TRACE`

### 示例请求
```bash
# 组织信息上链（注意带 API Key）
curl -X POST http://localhost:8080/api/chain/org \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: secret-api-key" \
  -d '{
    "id": 1234,
    "orgId": "ORG_43",
    "orgName": "安全部",
    "memberCount": 18,
    "adminPermission": 1,
    "createTime": "2025-11-27 14:21:24",
    "updateTime": "2025-11-27 14:21:24"
  }'

# 按类型查询（需要链码方法 queryEvidenceByType）
curl -X GET http://localhost:8080/api/chain/list/ORG \
  -H "X-API-KEY: secret-api-key"
```

## WebSocket 与实时推送
- 连接端点：`/ws`（SockJS + STOMP）
- 订阅主题：`/topic/alerts`
- 消息类型：
  - `BATCH_SUCCESS`：
    - 字段：`txId`、`count`、`durationMs`、`queueSizeAfter`、`sampleEventIds[]`、`timestamp`
  - `BATCH_FAILED`：
    - 字段：`error`、`requeued`、`dropped`、`timestamp`

## 前端控制台（index.html）
- 视图：
  - 数据模拟（支持随机生成与手动编辑）与提交
  - 实时监控（日志流、展开详情、WS 状态显示）
- 连发 10 条（展示异步聚合性能）
  - 按钮：`⚡ 连发10条`（自动为不同类型生成唯一关键字段以避免冲突）
- 查询结果显示的是链上原始 `metadata`（若存储为密文不会自动解密，默认保持原样）

## 安全与审计
- 选择性字段加密（写入链上前）：
  - `ORG.orgName`、`ALERT.impactScope`、`REPORT.reportUrl`
- API Key 鉴权（请求头 `X-API-KEY`）
- AOP 审计：记录接口访问的关键上下文
- Actuator：健康检查与优雅停机（根据 `application.yml` 配置启用）

## 链码要求
- 批量提交方法：`submitEvidenceBatch`（异步批处理端调用）
- 类型富查询方法：`queryEvidenceByType`（控制器调用）  
  你的控制器实现参考：`c:\Users\35742\Desktop\backend\src\main\java\com\example\blockchain\BlockchainController.java:145-165`

## 常见问题（FAQ）
- 查询返回“乱码/密文”：这是写入时的选择性加密结果，默认不在查询时解密；如需按需解密，可在接口侧增加开关参数（例如 `?decrypt=true`）。
- 富查询报“缺少方法”：确保链码已升级并包含 `queryEvidenceByType`；未升级时控制器会返回明确错误消息。
- 推送消息不显示：
  - 检查浏览器是否连上 `/ws`，订阅 `/topic/alerts`
  - 检查后端批处理线程是否启动（`AsyncService#startWorker`）
- 仓库过大：
  - 不要提交 `target/`、`logs/`、`wallet/`、`keystore/`、`organizations/`、`crypto-config/`、`channel-artifacts/`、`node_modules/`、`dist/` 等生成物
  - 已配置 `.gitignore`；如历史中已有大文件，使用 `git filter-repo` 或 BFG 清理历史后强推

## 版本管理
- 远程仓库：`origin https://github.com/IzumiKona-ta/blockchain.git`
- 拉取：
  - `git fetch origin --tags`
  - `git fetch origin`
  - `git pull --rebase origin main`（或 `master`，取决于远端默认分支）
- 推送：
  - 首次：`git push -u origin <branch>`

## 许可证
- 可按需填写（例如 MIT License）
