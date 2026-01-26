# AI引擎集成文档

## 概述

本项目已集成远程AI引擎用于生成PIDS溯源图谱。AI引擎运行在远程Linux服务器上，通过RESTful API提供服务。

## 架构设计

```
┌─────────────────┐      HTTP POST       ┌──────────────────────┐
│   前端 React    │ ──────────────────> │  后端 Spring Boot    │
│  (localhost)    │                      │   (localhost:8985)   │
└─────────────────┘                      └──────────────────────┘
                                                    │
                                                    │ HTTP POST
                                                    │ (3秒超时)
                                                    ▼
                                         ┌──────────────────────┐
                                         │   AI引擎 (Python)    │
                                         │ 10.138.50.151:5000   │
                                         └──────────────────────┘
```

## 配置说明

### 1. application.yml 配置

```yaml
external:
  ai-engine:
    url: ${AI_ENGINE_URL:http://10.138.50.151:5000/predict}
```

- **默认值**: `http://10.138.50.151:5000/predict`
- **环境变量**: 可通过 `AI_ENGINE_URL` 环境变量覆盖
- **用途**: 指向远程AI引擎的预测接口

### 2. 超时配置

- **连接超时**: 3秒
- **读取超时**: 3秒
- **目的**: 防止AI引擎不可用时阻塞前端请求

## API接口

### POST /api/tracing/result/generate-graph

生成PIDS溯源图谱（自动调用AI引擎或降级到本地规则）

**请求示例**:
```json
POST http://localhost:8985/api/tracing/result/generate-graph
Content-Type: application/json

{
  "source_ip": "45.227.253.98",
  "target_ip": "192.168.1.10",
  "attack_type": "SQL Injection"
}
```

**响应示例（AI引擎在线）**:
```json
{
  "code": 200,
  "msg": "操作成功",
  "data": {
    "nodes": [...],
    "edges": [...],
    "metadata": {
      "source": "ai_engine",
      "confidence": 0.95
    }
  }
}
```

**响应示例（降级模式）**:
```json
{
  "code": 200,
  "msg": "操作成功",
  "data": {
    "mode": "fallback",
    "source_ip": "45.227.253.98",
    "target_ip": "192.168.1.10",
    "attack_type": "SQL Injection",
    "nodes": [
      {
        "id": "attacker",
        "label": "Attacker\n45.227.253.98",
        "type": "diamond",
        "state": "malicious",
        "style": {
          "fill": "#162438",
          "stroke": "#ff4d4f",
          "lineWidth": 2
        }
      },
      {
        "id": "nginx",
        "label": "nginx\n(PID: 17274)",
        "type": "rect",
        "state": "compromised",
        "style": {
          "fill": "#162438",
          "stroke": "#ff4d4f",
          "lineWidth": 2
        }
      },
      {
        "id": "mysqld",
        "label": "mysqld\n(PID: 3847)",
        "type": "rect",
        "state": "critical",
        "style": {
          "fill": "#162438",
          "stroke": "#ff4d4f",
          "lineWidth": 2
        }
      }
    ],
    "edges": [
      {
        "source": "attacker",
        "target": "firewall",
        "label": "TCP/SYN",
        "style": {
          "stroke": "#ff4d4f",
          "lineWidth": 2
        }
      }
    ]
  }
}
```

## 核心实现

### TracingServiceImpl.java

#### 1. callRemoteAiEngine() - 调用远程AI引擎

```java
private JsonNode callRemoteAiEngine(String sourceIp, String targetIp, String attackType) {
    // 配置3秒超时的RestTemplate
    RestTemplate timeoutRestTemplate = new RestTemplateBuilder()
            .setConnectTimeout(Duration.ofSeconds(3))
            .setReadTimeout(Duration.ofSeconds(3))
            .build();

    // 构建请求参数
    Map<String, String> params = new HashMap<>();
    params.put("source_ip", sourceIp);
    params.put("target_ip", targetIp);
    params.put("attack_type", attackType);

    // 发送POST请求
    ResponseEntity<String> response = timeoutRestTemplate.postForEntity(
            aiEngineUrl,
            request,
            String.class
    );

    return objectMapper.readTree(response.getBody());
}
```

**异常处理**:
- `ConnectException`: 连接失败
- `ResourceAccessException`: 超时或网络错误
- 所有异常都会被捕获并抛出，由上层降级处理

#### 2. generateTraceGraph() - 生成图谱（带降级）

```java
public JsonNode generateTraceGraph(String sourceIp, String targetIp, String attackType) {
    try {
        // 尝试调用远程AI引擎
        return callRemoteAiEngine(sourceIp, targetIp, attackType);
    } catch (Exception e) {
        // 降级处理：AI引擎离线时使用本地规则生成
        log.warn("AI Engine Offline, using fallback mode: {}", e.getMessage());
        return generateFallbackGraph(sourceIp, targetIp, attackType);
    }
}
```

#### 3. generateFallbackGraph() - 降级方案

基于攻击类型的规则映射：

**SQL注入场景**:
```
Attacker → Firewall → nginx(PID:17274) → mysqld(PID:3847) → users.ibd
```

**SSH暴力破解场景**:
```
Attacker → Firewall → sshd(PID:18598) → auth.log
                                      → bash(root)(PID:1126)
```

**默认场景**:
```
Attacker → Firewall → Service(PID:12345) → /var/log/system.log
```

## 日志输出

### 正常调用AI引擎
```
INFO  - Calling AI Engine: http://10.138.50.151:5000/predict with params: {source_ip=45.227.253.98, target_ip=192.168.1.10, attack_type=SQL Injection}
INFO  - AI Engine response received successfully
```

### 降级模式
```
ERROR - AI Engine connection failed (ConnectException): Connection refused
WARN  - AI Engine Offline, using fallback mode: AI Engine connection failed
INFO  - Fallback graph generated with 5 nodes and 4 edges
```

## 测试方法

### 1. 使用Postman测试

```bash
POST http://localhost:8985/api/tracing/result/generate-graph
Content-Type: application/json

{
  "source_ip": "45.227.253.98",
  "target_ip": "192.168.1.10",
  "attack_type": "SQL Injection"
}
```

### 2. 使用curl测试

```bash
curl -X POST http://localhost:8985/api/tracing/result/generate-graph \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "45.227.253.98",
    "target_ip": "192.168.1.10",
    "attack_type": "SQL Injection"
  }'
```

### 3. 测试降级模式

**方法1**: 停止AI引擎服务
```bash
# 在AI引擎服务器上
sudo systemctl stop ai-engine
```

**方法2**: 修改配置指向错误地址
```yaml
external:
  ai-engine:
    url: http://localhost:9999/predict  # 不存在的端口
```

## 故障排查

### 问题1: AI引擎连接超时

**症状**:
```
ERROR - AI Engine timeout or network error: I/O error on POST request
```

**解决方案**:
1. 检查AI引擎服务是否运行: `curl http://10.138.50.151:5000/health`
2. 检查网络连通性: `ping 10.138.50.151`
3. 检查防火墙规则: `telnet 10.138.50.151 5000`

### 问题2: AI引擎返回错误

**症状**:
```
WARN - AI Engine returned non-success status: 500 INTERNAL_SERVER_ERROR
```

**解决方案**:
1. 查看AI引擎日志
2. 验证请求参数格式是否正确
3. 检查AI引擎的依赖服务（如模型文件是否存在）

### 问题3: 降级模式未生效

**症状**: AI引擎离线但前端报错

**解决方案**:
1. 检查日志是否有 "AI Engine Offline, using fallback mode"
2. 确认 `generateFallbackGraph()` 方法没有抛出异常
3. 检查返回的JSON格式是否正确

## 性能优化建议

### 1. 连接池配置

当前每次调用都创建新的RestTemplate，建议配置连接池：

```java
@Configuration
public class RestTemplateConfig {
    @Bean
    public RestTemplate aiEngineRestTemplate() {
        HttpComponentsClientHttpRequestFactory factory = 
            new HttpComponentsClientHttpRequestFactory();
        factory.setConnectTimeout(3000);
        factory.setReadTimeout(3000);
        
        // 配置连接池
        PoolingHttpClientConnectionManager connectionManager = 
            new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(100);
        connectionManager.setDefaultMaxPerRoute(20);
        
        CloseableHttpClient httpClient = HttpClients.custom()
            .setConnectionManager(connectionManager)
            .build();
        factory.setHttpClient(httpClient);
        
        return new RestTemplate(factory);
    }
}
```

### 2. 缓存机制

对于相同的攻击类型，可以缓存AI引擎的响应：

```java
@Cacheable(value = "traceGraphs", key = "#sourceIp + '_' + #attackType")
public JsonNode generateTraceGraph(String sourceIp, String targetIp, String attackType) {
    // ...
}
```

### 3. 异步调用

对于非实时场景，可以使用异步调用：

```java
@Async
public CompletableFuture<JsonNode> generateTraceGraphAsync(
    String sourceIp, String targetIp, String attackType) {
    return CompletableFuture.completedFuture(
        generateTraceGraph(sourceIp, targetIp, attackType)
    );
}
```

## 安全建议

1. **API认证**: 为AI引擎接口添加Token认证
2. **参数验证**: 严格验证IP地址和攻击类型格式
3. **速率限制**: 防止恶意调用耗尽AI引擎资源
4. **HTTPS**: 生产环境使用HTTPS加密通信

## 部署清单

### 后端部署
- [x] 配置 `application.yml` 中的 `external.ai-engine.url`
- [x] 确保网络可达 `10.138.50.151:5000`
- [x] 启动Spring Boot应用: `mvn spring-boot:run`

### AI引擎部署（远程服务器）
- [ ] 安装Python依赖
- [ ] 启动Flask服务: `python app.py`
- [ ] 配置防火墙开放5000端口
- [ ] 配置systemd自动启动

### 前端集成
- [ ] 调用 `/api/tracing/result/generate-graph` 接口
- [ ] 解析返回的nodes和edges数据
- [ ] 渲染G6图谱

## 联系方式

如有问题，请联系：
- 后端开发: backend-team@example.com
- AI引擎: ai-team@example.com
