package com.yukasl.backcode.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.yukasl.backcode.mapper.TracingMapper;
import com.yukasl.backcode.pojo.DTO.tracingPageDTO;
import com.yukasl.backcode.pojo.entity.threatSourceTracing;
import com.yukasl.backcode.result.PageResult;
import com.yukasl.backcode.service.TracingService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.*;

@Service
@Slf4j
public class TracingServiceImpl implements TracingService {

    @Autowired
    private TracingMapper tracingMapper;
    @Autowired
    private com.yukasl.backcode.mapper.AnalysisMapper analysisMapper;
    @Autowired
    private RestTemplate restTemplate;

    @Value("${external.blockchain-gateway.url}")
    private String blockchainUrl;

    @Value("${external.ai-engine.url:http://10.138.50.151:5000/predict}")
    private String aiEngineUrl;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 查询威胁溯源结果列表
     * @param tracingPageDTO
     * @return
     */
    @Override
    public PageResult page(tracingPageDTO tracingPageDTO) {
        if (tracingPageDTO == null){
            throw new RuntimeException("查询威胁溯源结果列表,请求参数为空");
        }
        PageHelper.startPage(tracingPageDTO.getPageNum(),tracingPageDTO.getPageSize());

        List<threatSourceTracing> list =  tracingMapper.query(tracingPageDTO);

        Page<threatSourceTracing> p = (Page<threatSourceTracing>) list;
        return new PageResult(p.getTotal(),p.getResult());
    }

    @Override
    public threatSourceTracing queryTracingById(Integer id) {
        if (id == null) {
            throw new RuntimeException("查看威胁溯源详情的Id为空");
        }
        threatSourceTracing sourceTracing =  tracingMapper.queryById(id);
        return sourceTracing;
    }

    public void saveTracing(threatSourceTracing sourceTracing) {
        tracingMapper.insert(sourceTracing);
        // Configured in application.yml
        restTemplate.postForObject(blockchainUrl, sourceTracing, String.class);
    }

    /**
     * 调用 PIDS AI 引擎 (统一连接 Linux 服务器，由 Python 端自动识别目标系统)
     * @param sourceIp 攻击源IP
     * @param targetIp 目标IP
     * @param attackType 攻击类型
     * @return AI引擎返回的JSON图谱数据
     */
    private JsonNode callRemoteAiEngine(String sourceIp, String targetIp, String attackType) {
        // 统一连接 Linux 服务器上的 PIDS Agent
        String aiUrl = "http://10.138.50.151:5000/predict";
        
        log.info("� [PIDS] 调用 Linux PIDS Agent: {}", aiUrl);
        log.info("📡 [PIDS] 目标IP: {} (Python端将自动识别目标系统类型)", targetIp);

        try {
            // === 1. 配置超时的RestTemplate (3秒连不上就放弃) ===
            RestTemplate timeoutRestTemplate = new RestTemplateBuilder()
                    .setConnectTimeout(Duration.ofSeconds(3))
                    .setReadTimeout(Duration.ofSeconds(5))
                    .build();

            // === 2. 构建请求参数 ===
            Map<String, String> params = new HashMap<>();
            params.put("source_ip", sourceIp);
            params.put("target_ip", targetIp);
            params.put("attack_type", attackType);

            // 设置请求头
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<Map<String, String>> request = new HttpEntity<>(params, headers);

            log.info(">>> Calling Python PIDS Server: {} <<<", aiUrl);
            log.info(">>> Request Params: {} <<<", params);

            // === 3. 发送POST请求 ===
            ResponseEntity<String> response = timeoutRestTemplate.postForEntity(
                    aiUrl,
                    request,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                log.info(">>> Python PIDS Server Response Status: {} <<<", response.getStatusCode());
                log.info(">>> Response Body: {} <<<", response.getBody());
                
                JsonNode fullResponse = objectMapper.readTree(response.getBody());
                
                // Python服务器返回格式: {"code": 200, "data": {"nodes": [...], "edges": [...]}}
                // 提取data字段返回给前端
                if (fullResponse.has("code") && fullResponse.get("code").asInt() == 200) {
                    JsonNode data = fullResponse.get("data");
                    log.info("✅ [成功] 成功从 {} 获取图谱数据", aiUrl);
                    log.info(">>> Nodes: {}, Edges: {} <<<", 
                        data.has("nodes") ? data.get("nodes").size() : 0,
                        data.has("edges") ? data.get("edges").size() : 0);
                    
                    // 打印节点详情
                    if (data.has("nodes")) {
                        log.info(">>> Node details: {} <<<", data.get("nodes").toString());
                    }
                    
                    return data;
                } else {
                    log.warn("AI Engine returned error code: {}", fullResponse.get("code"));
                    throw new RuntimeException("AI Engine returned error");
                }
            } else {
                log.warn("AI Engine returned non-success status: {}", response.getStatusCode());
                throw new RuntimeException("AI Engine returned error status");
            }

        } catch (ResourceAccessException e) {
            // === 4. 容错降级 (关键！) ===
            // 如果 Linux Agent 连接失败，不要报错，返回一个空图谱数据，保证前端不白屏
            log.warn("⚠️ [容错降级] PIDS Agent 连接失败: {}。原因: {}", aiUrl, e.getMessage());
            log.warn("⚠️ [容错降级] 返回空图谱数据，避免前端报错");
            
            // 返回一个空的但格式正确的图谱数据
            ObjectNode emptyData = objectMapper.createObjectNode();
            emptyData.set("nodes", objectMapper.createArrayNode());
            emptyData.set("edges", objectMapper.createArrayNode());
            
            return emptyData;
            
        } catch (Exception e) {
            // 其他异常也进行容错降级
            log.error("⚠️ [容错降级] AI Engine 调用失败: {}", e.getMessage(), e);
            log.warn("⚠️ [容错降级] 返回空图谱数据，避免前端报错");
            
            ObjectNode emptyData = objectMapper.createObjectNode();
            emptyData.set("nodes", objectMapper.createArrayNode());
            emptyData.set("edges", objectMapper.createArrayNode());
            
            return emptyData;
        }
    }

    /**
     * 生成威胁溯源图谱（支持全景统一视图）
     * @param sourceIp 攻击源IP
     * @param targetIp 目标IP
     * @param attackType 攻击类型
     * @return 图谱JSON数据
     */
    public JsonNode generateTraceGraph(String sourceIp, String targetIp, String attackType) {
        log.info("=== PIDS Graph Generation Started ===");
        log.info("Source IP: {}, Target IP: {}, Attack Type: {}", sourceIp, targetIp, attackType);
        
        // 1. 查询数据库中所有相关的告警记录
        List<com.yukasl.backcode.pojo.entity.potentialThreatAlert> recentAlerts = null;
        
        try {
            // 🔥 关键修改：查询所有相关记录（最多 100 条），而不是只查 1 条
            recentAlerts = analysisMapper.queryRecentAlerts(sourceIp, targetIp, 100);
            
            if (recentAlerts != null && !recentAlerts.isEmpty()) {
                log.info("📋 从数据库获取到 {} 条告警记录", recentAlerts.size());
                
                // 统计有多少条记录包含主机层数据
                long hostDataCount = recentAlerts.stream()
                    .filter(alert -> alert.getAffectedProcess() != null && !alert.getAffectedProcess().isEmpty())
                    .count();
                log.info("📊 其中 {} 条记录包含主机层数据", hostDataCount);
            }
        } catch (Exception e) {
            log.warn("⚠️ 查询数据库告警记录失败，将使用基础网络视图: {}", e.getMessage());
        }
        
        // 2. 根据是否有主机层数据，决定构建哪种图谱
        JsonNode result;
        
        if (recentAlerts != null && !recentAlerts.isEmpty() && 
            recentAlerts.stream().anyMatch(alert -> alert.getAffectedProcess() != null && !alert.getAffectedProcess().isEmpty())) {
            // === 情况 B：全景溯源视图 (Unified View) ===
            log.info("🔍 [全景模式] 检测到主机层数据，构建完整攻击链路图谱");
            result = buildUnifiedGraph(sourceIp, targetIp, attackType, recentAlerts);
        } else {
            // === 情况 A：基础网络视图 (Simple View) ===
            log.info("🔍 [网络模式] 未检测到主机层数据，构建基础网络图谱");
            result = buildSimpleGraph(sourceIp, targetIp, attackType);
        }
        
        log.info("=== PIDS Graph Generation Completed ===");
        log.info("Nodes: {}, Edges: {}", 
            result.has("nodes") ? result.get("nodes").size() : 0,
            result.has("edges") ? result.get("edges").size() : 0);
        
        return result;
    }
    
    /**
     * 构建基础网络视图 (Simple View)
     * 节点：攻击者 -> 防火墙 -> 目标IP
     */
    private JsonNode buildSimpleGraph(String sourceIp, String targetIp, String attackType) {
        ObjectNode graphData = objectMapper.createObjectNode();
        
        // 构建节点
        var nodes = objectMapper.createArrayNode();
        
        // 攻击者节点
        ObjectNode attackerNode = objectMapper.createObjectNode();
        attackerNode.put("id", "attacker_" + sourceIp.replace(".", "_"));
        attackerNode.put("label", sourceIp);
        attackerNode.put("type", "attacker");
        attackerNode.put("description", "攻击源");
        nodes.add(attackerNode);
        
        // 防火墙节点
        ObjectNode firewallNode = objectMapper.createObjectNode();
        firewallNode.put("id", "firewall");
        firewallNode.put("label", "Firewall");
        firewallNode.put("type", "firewall");
        firewallNode.put("description", "防火墙");
        nodes.add(firewallNode);
        
        // 目标服务器节点
        ObjectNode targetNode = objectMapper.createObjectNode();
        targetNode.put("id", "target_" + targetIp.replace(".", "_"));
        targetNode.put("label", targetIp);
        targetNode.put("type", "server");
        targetNode.put("description", "目标服务器");
        nodes.add(targetNode);
        
        // 构建边
        var edges = objectMapper.createArrayNode();
        
        // 攻击者 -> 防火墙
        ObjectNode edge1 = objectMapper.createObjectNode();
        edge1.put("source", "attacker_" + sourceIp.replace(".", "_"));
        edge1.put("target", "firewall");
        edge1.put("label", attackType);
        edges.add(edge1);
        
        // 防火墙 -> 目标服务器
        ObjectNode edge2 = objectMapper.createObjectNode();
        edge2.put("source", "firewall");
        edge2.put("target", "target_" + targetIp.replace(".", "_"));
        edge2.put("label", "forward");
        edges.add(edge2);
        
        graphData.set("nodes", nodes);
        graphData.set("edges", edges);
        
        return graphData;
    }
    
    /**
     * 构建全景溯源视图 (Unified View)
     * 节点：攻击者 -> 防火墙 -> 目标IP -> 受影响进程 -> 受影响文件
     * 🔥 关键修改：为每条告警记录创建独立的进程和文件节点
     */
    private JsonNode buildUnifiedGraph(String sourceIp, String targetIp, String attackType, 
                                       List<com.yukasl.backcode.pojo.entity.potentialThreatAlert> alerts) {
        ObjectNode graphData = objectMapper.createObjectNode();
        
        // 构建节点
        var nodes = objectMapper.createArrayNode();
        
        // 1. 攻击者节点
        ObjectNode attackerNode = objectMapper.createObjectNode();
        attackerNode.put("id", "attacker_" + sourceIp.replace(".", "_"));
        attackerNode.put("label", sourceIp);
        attackerNode.put("type", "attacker");
        attackerNode.put("description", "攻击源");
        nodes.add(attackerNode);
        
        // 2. 防火墙节点
        ObjectNode firewallNode = objectMapper.createObjectNode();
        firewallNode.put("id", "firewall");
        firewallNode.put("label", "Firewall");
        firewallNode.put("type", "firewall");
        firewallNode.put("description", "防火墙");
        nodes.add(firewallNode);
        
        // 3. 目标服务器节点
        ObjectNode targetNode = objectMapper.createObjectNode();
        targetNode.put("id", "target_" + targetIp.replace(".", "_"));
        targetNode.put("label", targetIp);
        targetNode.put("type", "server");
        targetNode.put("description", "目标服务器");
        nodes.add(targetNode);
        
        // 构建边
        var edges = objectMapper.createArrayNode();
        
        // 攻击者 -> 防火墙
        ObjectNode edge1 = objectMapper.createObjectNode();
        edge1.put("source", "attacker_" + sourceIp.replace(".", "_"));
        edge1.put("target", "firewall");
        edge1.put("label", attackType);
        edges.add(edge1);
        
        // 防火墙 -> 目标服务器
        ObjectNode edge2 = objectMapper.createObjectNode();
        edge2.put("source", "firewall");
        edge2.put("target", "target_" + targetIp.replace(".", "_"));
        edge2.put("label", "forward");
        edges.add(edge2);
        
        // 🔥 关键修改：只处理当前 sourceIp 的告警记录，并为每个进程/文件创建独立节点
        // 使用 Map 来存储进程名称到节点ID的映射，确保相同进程只创建一个节点
        java.util.Map<String, String> processIdMap = new java.util.HashMap<>();
        java.util.Map<String, String> fileIdMap = new java.util.HashMap<>();
        
        // 过滤出属于当前 sourceIp 的告警记录
        List<com.yukasl.backcode.pojo.entity.potentialThreatAlert> filteredAlerts = alerts.stream()
            .filter(alert -> alert.getSourceIp() != null && alert.getSourceIp().equals(sourceIp))
            .collect(java.util.stream.Collectors.toList());
        
        log.info("[FILTER] 过滤后属于 {} 的告警记录: {} 条", sourceIp, filteredAlerts.size());
        
        // 用于存储进程之间的父子关系
        java.util.Map<String, String> processParentMap = new java.util.HashMap<>();
        String lastProcessId = "target_" + targetIp.replace(".", "_");
        
        for (com.yukasl.backcode.pojo.entity.potentialThreatAlert alert : filteredAlerts) {
            String affectedProcessStr = alert.getAffectedProcess();
            String affectedFile = alert.getAffectedFile();
            
            // 跳过没有主机层数据的记录
            if (affectedProcessStr == null || affectedProcessStr.isEmpty()) {
                continue;
            }
            
            // 🔥 关键修复：解析 JSON 数组字符串（如 ["nginx", "php-fpm", "mysql"]）
            try {
                // 清理字符串：移除外层引号和转义字符
                String cleanedStr = affectedProcessStr.trim();
                if (cleanedStr.startsWith("\"") && cleanedStr.endsWith("\"")) {
                    cleanedStr = cleanedStr.substring(1, cleanedStr.length() - 1);
                }
                cleanedStr = cleanedStr.replace("\\\"", "\"");
                
                log.info("🔍 [DEBUG] 原始进程链: {}", affectedProcessStr);
                log.info("🔍 [DEBUG] 清理后进程链: {}", cleanedStr);
                
                // 解析进程链数组
                com.fasterxml.jackson.databind.JsonNode processArray = objectMapper.readTree(cleanedStr);
                
                if (processArray.isArray() && processArray.size() > 0) {
                    log.info("✅ [DEBUG] 成功解析为数组，长度: {}", processArray.size());
                    // 🔥 重要：不要每次都重置为目标服务器，而是从上一个进程继续
                    // 如果是第一条记录，从目标服务器开始；否则从上一个进程继续
                    String currentParent = lastProcessId;
                    
                    // 遍历进程链中的每个进程
                    for (int i = 0; i < processArray.size(); i++) {
                        String processName = processArray.get(i).asText();
                        
                        // 为每个进程创建独立节点（使用进程名称作为ID的一部分，确保去重）
                        String processId = "proc_" + processName.replace("/", "_").replace(" ", "_").replace("-", "_");
                        
                        if (!processIdMap.containsKey(processName)) {
                            ObjectNode processNode = objectMapper.createObjectNode();
                            processNode.put("id", processId);
                            processNode.put("label", processName);
                            processNode.put("type", "process");
                            processNode.put("description", "进程: " + processName);
                            nodes.add(processNode);
                            processIdMap.put(processName, processId);
                            
                            // 连接到父节点
                            ObjectNode edge3 = objectMapper.createObjectNode();
                            edge3.put("source", currentParent);
                            edge3.put("target", processId);
                            edge3.put("label", "execute");
                            edges.add(edge3);
                            
                            // 更新父节点为当前进程
                            currentParent = processId;
                        } else {
                            // 如果进程已存在，更新 currentParent 为已存在的进程ID
                            currentParent = processIdMap.get(processName);
                        }
                    }
                    
                    // 记录最后一个进程ID，用于连接文件和下一条告警记录
                    lastProcessId = currentParent;
                }
            } catch (Exception e) {
                log.warn("⚠️ 解析进程链失败: {}, 原始数据: {}", e.getMessage(), affectedProcessStr);
                // 如果解析失败，尝试作为单个进程处理
                String processId = "proc_" + affectedProcessStr.replace("/", "_").replace(" ", "_").replace("[", "").replace("]", "").replace("\"", "").replace(",", "_");
                
                if (!processIdMap.containsKey(affectedProcessStr)) {
                    ObjectNode processNode = objectMapper.createObjectNode();
                    processNode.put("id", processId);
                    processNode.put("label", affectedProcessStr);
                    processNode.put("type", "process");
                    processNode.put("description", "进程: " + affectedProcessStr);
                    nodes.add(processNode);
                    processIdMap.put(affectedProcessStr, processId);
                    
                    ObjectNode edge3 = objectMapper.createObjectNode();
                    edge3.put("source", lastProcessId);
                    edge3.put("target", processId);
                    edge3.put("label", "execute");
                    edges.add(edge3);
                    
                    lastProcessId = processId;
                }
            }
            
            // 5. 为每个文件创建独立节点（使用文件名称作为ID的一部分，确保去重）
            if (affectedFile != null && !affectedFile.isEmpty()) {
                String fileId = "file_" + affectedFile.replace("/", "_").replace(" ", "_").replace(".", "_");
                
                if (!fileIdMap.containsKey(affectedFile)) {
                    ObjectNode fileNode = objectMapper.createObjectNode();
                    fileNode.put("id", fileId);
                    fileNode.put("label", affectedFile);
                    fileNode.put("type", "file");
                    fileNode.put("description", "文件: " + affectedFile);
                    nodes.add(fileNode);
                    fileIdMap.put(affectedFile, fileId);
                    
                    // 进程 -> 文件
                    ObjectNode edge4 = objectMapper.createObjectNode();
                    edge4.put("source", lastProcessId);
                    edge4.put("target", fileId);
                    edge4.put("label", "access");
                    edges.add(edge4);
                }
            }
        }
        
        log.info("✅ 构建完成: {} 个节点, {} 条边", nodes.size(), edges.size());
        log.info("   - 进程节点: {}", processIdMap.size());
        log.info("   - 文件节点: {}", fileIdMap.size());
        
        graphData.set("nodes", nodes);
        graphData.set("edges", edges);
        
        return graphData;
    }

    /**
     * 🔥 增量溯源 - 根据目标IP生成包含所有攻击源的完整图谱
     * 这个方法会查询针对目标IP的所有攻击，并为每个攻击源创建独立的节点链
     * @param targetIp 目标IP
     * @param lastAlertCount 上次的告警数量（用于优化，可选）
     * @return 完整的图谱数据
     */
    public JsonNode generateIncrementalGraph(String targetIp, Integer lastAlertCount) {
        log.info("=== 🔥 增量溯源开始 ===");
        log.info("目标IP: {}, 上次告警数: {}", targetIp, lastAlertCount);
        
        ObjectNode graphData = objectMapper.createObjectNode();
        var nodes = objectMapper.createArrayNode();
        var edges = objectMapper.createArrayNode();
        
        try {
            // 1. 查询针对目标IP的所有告警记录（最多200条）
            List<com.yukasl.backcode.pojo.entity.potentialThreatAlert> allAlerts = 
                analysisMapper.queryAlertsByTargetIp(targetIp, 200);
            
            if (allAlerts == null || allAlerts.isEmpty()) {
                log.warn("未找到针对目标IP {} 的告警记录", targetIp);
                graphData.set("nodes", nodes);
                graphData.set("edges", edges);
                return graphData;
            }
            
            log.info("📋 查询到 {} 条针对 {} 的告警记录", allAlerts.size(), targetIp);
            
            // 2. 添加中心节点：目标服务器
            ObjectNode targetNode = objectMapper.createObjectNode();
            targetNode.put("id", "target_" + targetIp.replace(".", "_"));
            targetNode.put("label", targetIp);
            targetNode.put("type", "server");
            targetNode.put("description", "目标服务器");
            nodes.add(targetNode);
            
            // 3. 按攻击源IP分组
            Map<String, List<com.yukasl.backcode.pojo.entity.potentialThreatAlert>> alertsBySource = 
                allAlerts.stream()
                    .filter(alert -> alert.getSourceIp() != null)
                    .collect(java.util.stream.Collectors.groupingBy(
                        com.yukasl.backcode.pojo.entity.potentialThreatAlert::getSourceIp
                    ));
            
            log.info("📊 发现 {} 个不同的攻击源", alertsBySource.size());
            
            // 4. 为每个攻击源创建节点链
            int totalProcessNodes = 0;
            int totalFileNodes = 0;
            
            for (Map.Entry<String, List<com.yukasl.backcode.pojo.entity.potentialThreatAlert>> entry : 
                 alertsBySource.entrySet()) {
                String sourceIp = entry.getKey();
                List<com.yukasl.backcode.pojo.entity.potentialThreatAlert> sourceAlerts = entry.getValue();
                
                log.info("  处理攻击源: {} ({} 条告警)", sourceIp, sourceAlerts.size());
                
                // 4.1 创建攻击者节点
                ObjectNode attackerNode = objectMapper.createObjectNode();
                String attackerId = "attacker_" + sourceIp.replace(".", "_");
                attackerNode.put("id", attackerId);
                attackerNode.put("label", sourceIp);
                attackerNode.put("type", "attacker");
                attackerNode.put("description", "攻击源 (" + sourceAlerts.size() + " 次攻击)");
                nodes.add(attackerNode);
                
                // 4.2 创建攻击者到目标的连接
                ObjectNode attackEdge = objectMapper.createObjectNode();
                attackEdge.put("source", attackerId);
                attackEdge.put("target", "target_" + targetIp.replace(".", "_"));
                
                // 获取主要攻击类型
                String mainAttackType = sourceAlerts.get(0).getAttackType();
                attackEdge.put("label", mainAttackType != null ? mainAttackType : "Attack");
                edges.add(attackEdge);
                
                // 4.3 为该攻击源的主机层数据创建进程和文件节点
                Set<String> addedProcesses = new HashSet<>();
                Set<String> addedFiles = new HashSet<>();
                
                for (com.yukasl.backcode.pojo.entity.potentialThreatAlert alert : sourceAlerts) {
                    String affectedProcess = alert.getAffectedProcess();
                    String affectedFile = alert.getAffectedFile();
                    
                    // 跳过没有主机层数据的记录
                    if (affectedProcess == null || affectedProcess.isEmpty()) {
                        continue;
                    }
                    
                    // 创建进程节点（去重）
                    String processKey = sourceIp + "_" + affectedProcess;
                    if (!addedProcesses.contains(processKey)) {
                        String processId = "proc_" + sourceIp.replace(".", "_") + "_" + totalProcessNodes;
                        ObjectNode processNode = objectMapper.createObjectNode();
                        processNode.put("id", processId);
                        processNode.put("label", affectedProcess);
                        processNode.put("type", "process");
                        processNode.put("description", "受影响进程: " + affectedProcess);
                        nodes.add(processNode);
                        addedProcesses.add(processKey);
                        
                        // 目标服务器 -> 进程
                        ObjectNode procEdge = objectMapper.createObjectNode();
                        procEdge.put("source", "target_" + targetIp.replace(".", "_"));
                        procEdge.put("target", processId);
                        procEdge.put("label", "execute");
                        edges.add(procEdge);
                        
                        totalProcessNodes++;
                        
                        // 创建文件节点（如果有）
                        if (affectedFile != null && !affectedFile.isEmpty()) {
                            String fileKey = sourceIp + "_" + affectedFile;
                            if (!addedFiles.contains(fileKey)) {
                                String fileId = "file_" + sourceIp.replace(".", "_") + "_" + totalFileNodes;
                                ObjectNode fileNode = objectMapper.createObjectNode();
                                fileNode.put("id", fileId);
                                fileNode.put("label", affectedFile);
                                fileNode.put("type", "file");
                                fileNode.put("description", "受影响文件: " + affectedFile);
                                nodes.add(fileNode);
                                addedFiles.add(fileKey);
                                
                                // 进程 -> 文件
                                ObjectNode fileEdge = objectMapper.createObjectNode();
                                fileEdge.put("source", processId);
                                fileEdge.put("target", fileId);
                                fileEdge.put("label", "access");
                                edges.add(fileEdge);
                                
                                totalFileNodes++;
                            }
                        }
                    }
                }
            }
            
            log.info("✅ 增量溯源完成:");
            log.info("   - 攻击源数: {}", alertsBySource.size());
            log.info("   - 总节点数: {}", nodes.size());
            log.info("   - 总边数: {}", edges.size());
            log.info("   - 进程节点: {}", totalProcessNodes);
            log.info("   - 文件节点: {}", totalFileNodes);
            
        } catch (Exception e) {
            log.error("增量溯源失败: {}", e.getMessage(), e);
            // 返回空图谱而不是抛出异常
        }
        
        graphData.set("nodes", nodes);
        graphData.set("edges", edges);
        
        log.info("=== 🔥 增量溯源结束 ===");
        return graphData;
    }

}
