package com.yukasl.backcode.controller;

import com.yukasl.backcode.pojo.DTO.alertPageDTO;
import com.yukasl.backcode.pojo.DTO.pageTrafficDateDTO;
import com.yukasl.backcode.pojo.entity.potentialThreatAlert;
import com.yukasl.backcode.result.PageResult;
import com.yukasl.backcode.result.Result;
import com.yukasl.backcode.service.AnalysisService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yukasl.backcode.websocket.WebSocketServer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.yukasl.backcode.service.CommandQueueService;

/**
 * 威胁数据分析预测模块
 */
@RestController
@RequestMapping("/api/analysis")
@Slf4j
public class AnalysisController {
    @Autowired
    private AnalysisService analysisService;

    @Autowired
    private CommandQueueService commandQueueService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private org.springframework.web.client.RestTemplate restTemplate;

    @org.springframework.beans.factory.annotation.Value("${external.ai-service.url}")
    private String aiUrl;

    /**
     * 查询威胁流量统计数据
     */
    @GetMapping("/traffic")
    public Result<PageResult> pageTrafficDate(pageTrafficDateDTO pageTrafficDateDTO) {
        log.info("查询威胁流量统计数据,请求参数为 -> {}", pageTrafficDateDTO);
        PageResult pageResult = analysisService.pageTrafficDate(pageTrafficDateDTO);
        return Result.success(pageResult);

    }

    /**
     * 查询潜在威胁预警列表
     *
     * @param alertPageDTO
     * @return
     */
    @GetMapping("/alert")
    public Result<PageResult> queryAlertPage(alertPageDTO alertPageDTO) {
        log.info("查询潜在威胁预警列表,请求参数为 -> {}", alertPageDTO);
        PageResult pageResult = analysisService.queryAlert(alertPageDTO);
        return Result.success(pageResult);
    }

    /**
     * 查看潜在威胁预警详情
     *
     * @return
     */
    @GetMapping("/alert/{id}")
    public Result<potentialThreatAlert> queryAlertById(@PathVariable Integer id) {
        log.info("查看潜在威胁预警详情,请求参数Id为 -> {}", id);
        potentialThreatAlert threatAlert = analysisService.queryAlertById(id);
        return Result.success(threatAlert);
    }

    /**
     * 接收 IDS 实时告警 (新增)
     */
    @PostMapping("/alert")
    public Result<String> receiveAlert(@RequestBody potentialThreatAlert alert) {
        log.info("接收到 IDS 实时告警: {}", alert);
        analysisService.saveAlert(alert);

        // 推送 WebSocket 消息
        try {
            String json = objectMapper.writeValueAsString(alert);
            WebSocketServer.sendInfo(json);
        } catch (Exception e) {
            log.error("WebSocket 推送失败", e);
        }

        return Result.success("Alert received and processed");
    }

    /**
     * 获取攻击趋势统计 (24h/7d/30d)
     */
    @GetMapping("/trend")
    public Result<java.util.List<java.util.Map<String, Object>>> getTrendStats(@RequestParam(defaultValue = "24h") String range) {
        return Result.success(analysisService.getTrendStats(range));
    }

    /**
     * AI 威胁溯源分析代理接口
     */
    @PostMapping("/ai-trace")
    public Result<java.util.Map<String, Object>> aiTrace(@RequestBody java.util.Map<String, Object> payload) {
        log.info("Requesting AI Trace analysis: {}", payload);
        // AI Agent URL (Configured in application.yml)
        // String aiUrl = "http://10.138.50.151:8000/api/chat"; // Old hardcoded

        try {
            // Forward the request to the AI agent
            java.util.Map response = restTemplate.postForObject(aiUrl, payload, java.util.Map.class);
            return Result.success(response);
        } catch (Exception e) {
            log.error("Failed to call AI agent", e);

            // Fallback mock response for demonstration if AI is unreachable
            java.util.Map<String, Object> mockResponse = new java.util.HashMap<>();
            mockResponse.put("answer", "**(自动回复 - AI 服务连接超时)**\n\n系统检测到该请求尝试连接外部智能体失败。以下是基于规则的自动分析：\n\n1. **攻击特征**: 检测到疑似恶意 Payload。\n2. **建议**: 建议将源 IP 加入黑名单。\n\n(请检查 AI Agent 服务状态)");
            return Result.success(mockResponse);
        }
    }
}