package com.yukasl.backcode.controller;

import com.yukasl.backcode.pojo.entity.ThreatReportHistory;
import com.yukasl.backcode.result.Result;
import com.yukasl.backcode.service.AiReportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/report")
public class AiReportController {

    @Autowired
    private AiReportService aiReportService;

    @PostMapping("/generate")
    public Result<String> generateReport(@RequestBody Map<String, String> params) {
        String type = params.getOrDefault("type", "Daily");
        String content = aiReportService.generateReport(type);
        return Result.success(content);
    }

    @GetMapping("/history")
    public Result<List<ThreatReportHistory>> getHistory() {
        return Result.success(aiReportService.getHistory());
    }

    @PutMapping("/history/{id}")
    public Result<String> renameReport(@PathVariable Integer id, @RequestBody Map<String, String> params) {
        String newTitle = params.get("title");
        if (newTitle == null || newTitle.trim().isEmpty()) {
            return Result.error("Title cannot be empty");
        }
        aiReportService.renameReport(id, newTitle);
        return Result.success();
    }

    @DeleteMapping("/history/{id}")
    public Result<String> deleteReport(@PathVariable Integer id) {
        aiReportService.deleteReport(id);
        return Result.success();
    }
}
