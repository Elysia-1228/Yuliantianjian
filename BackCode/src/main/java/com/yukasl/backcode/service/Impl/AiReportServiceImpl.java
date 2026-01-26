package com.yukasl.backcode.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.pagehelper.PageHelper;
import com.yukasl.backcode.mapper.AnalysisMapper;
import com.yukasl.backcode.mapper.ThreatReportHistoryMapper;
import com.yukasl.backcode.pojo.DTO.alertPageDTO;
import com.yukasl.backcode.pojo.entity.ThreatReportHistory;
import com.yukasl.backcode.pojo.entity.potentialThreatAlert;
import com.yukasl.backcode.service.AiReportService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class AiReportServiceImpl implements AiReportService {

    @Autowired
    private AnalysisMapper analysisMapper;

    @Autowired
    private ThreatReportHistoryMapper historyMapper;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    // AI 接口地址 (Configured in application.yml)
    @org.springframework.beans.factory.annotation.Value("${external.ai-service.url}")
    private String aiApiUrl;

    @Override
    public String generateReport(String type) {
        log.info("开始生成威胁分析报告，类型: {}", type);

        // 1. 获取真实威胁数据 (最近 20 条)
        PageHelper.startPage(1, 20);
        List<potentialThreatAlert> alerts = analysisMapper.queryAlertPage(new alertPageDTO());
        log.info("检索到 {} 条威胁数据用于分析", alerts.size());

        // 2. 构建 Prompt
        String reportName = "Daily".equals(type) ? "安全日报" : "Weekly".equals(type) ? "态势周报" : "专项分析";
        String prompt = buildPrompt(alerts, reportName);

        // 3. 调用 AI 接口
        String aiResponse = callAiApi(prompt);

        // 4. 保存记录
        ThreatReportHistory history = ThreatReportHistory.builder()
                .title(LocalDateTime.now().toLocalDate() + " " + reportName)
                .reportType(type)
                .content(aiResponse)
                .createTime(LocalDateTime.now())
                .build();
        historyMapper.insert(history);
        log.info("报告已保存，ID: {}", history.getId());

        return aiResponse;
    }

    @Override
    public List<ThreatReportHistory> getHistory() {
        return historyMapper.selectAll();
    }

    @Override
    public void renameReport(Integer id, String newTitle) {
        historyMapper.updateTitle(id, newTitle);
    }

    @Override
    public void deleteReport(Integer id) {
        historyMapper.deleteById(id);
    }

    private String buildPrompt(List<potentialThreatAlert> alerts, String reportName) {
        StringBuilder sb = new StringBuilder();
        sb.append("你是一个资深网络安全专家。请根据以下威胁情报数据，撰写一份专业的").append(reportName).append("。\n");
        sb.append("数据如下(JSON格式)：\n");
        try {
            // 只保留关键字段以减少 token 消耗
            List<Map<String, Object>> simplifiedAlerts = alerts.stream().map(a -> {
                Map<String, Object> map = new HashMap<>();
                map.put("time", a.getOccurTime());
                map.put("level", a.getThreatLevel());
                map.put("scope", a.getImpactScope());
                map.put("type", "Unknown"); // 这里的 type 需要从 impactScope 解析，或者后端增加字段
                return map;
            }).toList();
            sb.append(objectMapper.writeValueAsString(simplifiedAlerts));
        } catch (Exception e) {
            sb.append("数据序列化失败");
        }
        sb.append("\n\n要求：\n");
        sb.append("1. 使用 Markdown 格式。\n");
        sb.append("2. 包含核心结论、威胁分布分析、高危事件溯源、防御建议。\n");
        sb.append("3. 语气专业、客观、紧迫感适中。");
        return sb.toString();
    }

    private String callAiApi(String prompt) {
        try {
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("question", prompt);
            requestBody.put("top_k", 1);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
            
            log.info("正在调用 AI 接口: {}", aiApiUrl);
            // 假设返回结构 {"code": 200, "answer": "...", ...}
            Map response = restTemplate.postForObject(aiApiUrl, entity, Map.class);
            
            if (response != null && response.containsKey("answer")) {
                return (String) response.get("answer");
            } else {
                log.warn("AI 接口返回异常: {}", response);
                return "AI 服务返回异常或格式错误。";
            }
        } catch (Exception e) {
            log.error("调用 AI 接口失败", e);
            return "生成报告失败：无法连接 AI 引擎 (" + e.getMessage() + ")";
        }
    }
}
