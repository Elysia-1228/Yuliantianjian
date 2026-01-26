package com.yukasl.backcode.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.yukasl.backcode.pojo.DTO.tracingPageDTO;
import com.yukasl.backcode.pojo.entity.threatSourceTracing;
import com.yukasl.backcode.result.PageResult;
import com.yukasl.backcode.result.Result;
import com.yukasl.backcode.service.TracingService;
import com.yukasl.backcode.service.impl.TracingServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/tracing/result")
@Slf4j
public class TracingController {
    @Autowired
    private TracingService tracingService;
    
    @Autowired
    private TracingServiceImpl tracingServiceImpl;

    /**
     * 查询威胁溯源结果列表
     */
    @GetMapping
    public Result<PageResult> tracingPage(tracingPageDTO tracingPageDTO) {
        log.info("查询威胁溯源结果列表,请求参数为 -> {}", tracingPageDTO);
        PageResult pageResult = tracingService.page(tracingPageDTO);
        return Result.success(pageResult);
    }

    /**
     * 查看威胁溯源详情（含流程图）
     */
    @GetMapping("/{id}")
    public Result<threatSourceTracing> queryTracingById(@PathVariable Integer id) {
        log.info("查看威胁溯源详细,Id为 -> {}", id);
        threatSourceTracing sourceTracing = tracingService.queryTracingById(id);
        return Result.success(sourceTracing);
    }

    /**
     * 生成PIDS溯源图谱（调用AI引擎或降级到本地规则）
     * @param params 包含 source_ip, target_ip, attack_type
     * @return 图谱JSON数据
     */
    @PostMapping("/generate-graph")
    public Result<JsonNode> generateGraph(@RequestBody Map<String, String> params) {
        String sourceIp = params.get("source_ip");
        String targetIp = params.get("target_ip");
        String attackType = params.get("attack_type");
        
        log.info("生成PIDS溯源图谱: sourceIp={}, targetIp={}, attackType={}", sourceIp, targetIp, attackType);
        
        if (sourceIp == null || targetIp == null || attackType == null) {
            return Result.error("缺少必要参数: source_ip, target_ip, attack_type");
        }
        
        try {
            JsonNode graphData = tracingServiceImpl.generateTraceGraph(sourceIp, targetIp, attackType);
            return Result.success(graphData);
        } catch (Exception e) {
            log.error("生成图谱失败: {}", e.getMessage(), e);
            return Result.error("生成图谱失败: " + e.getMessage());
        }
    }

    /**
     * 🔥 增量溯源API - 实时动态增加节点
     * 根据目标IP获取所有攻击源的完整溯源图谱，支持实时动态更新
     * @param params 包含 target_ip, last_alert_count (可选)
     * @return 完整的图谱JSON数据（包含所有攻击源的节点）
     */
    @PostMapping("/incremental-graph")
    public Result<JsonNode> getIncrementalGraph(@RequestBody Map<String, Object> params) {
        String targetIp = (String) params.get("target_ip");
        Integer lastAlertCount = params.get("last_alert_count") != null 
            ? Integer.parseInt(params.get("last_alert_count").toString()) 
            : 0;
        
        log.info("🔥 [增量溯源] 目标IP: {}, 上次告警数: {}", targetIp, lastAlertCount);
        
        if (targetIp == null) {
            return Result.error("缺少必要参数: target_ip");
        }
        
        try {
            JsonNode graphData = tracingServiceImpl.generateIncrementalGraph(targetIp, lastAlertCount);
            return Result.success(graphData);
        } catch (Exception e) {
            log.error("增量溯源失败: {}", e.getMessage(), e);
            return Result.error("增量溯源失败: " + e.getMessage());
        }
    }
}