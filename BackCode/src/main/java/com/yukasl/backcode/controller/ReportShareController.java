package com.yukasl.backcode.controller;

import com.yukasl.backcode.pojo.DTO.ReportShareDTO;
import com.yukasl.backcode.pojo.entity.reportShare;
import com.yukasl.backcode.result.PageResult;
import com.yukasl.backcode.result.Result;
import com.yukasl.backcode.service.ReportShareService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@Slf4j
public class ReportShareController {
    @Autowired
    private ReportShareService reportShareService;

    @GetMapping("/api/report/share")
    public Result<PageResult> queryReportShare(ReportShareDTO reportShareDTO) {
        log.info("查询组织信息列表，请求参数为 -> {}", reportShareDTO);
        return Result.success(reportShareService.queryReportShare(reportShareDTO));
    }

    @PostMapping("/api/report/share")
    public Result<Object> insertReportShare(@RequestBody ReportShareDTO reportShareDTO) {
        log.info("发起报告共享，请求参数为 -> {}", reportShareDTO);
        if (reportShareDTO.getSharedOrgId() == null || reportShareDTO.getSharedOrgId().isEmpty())
            return Result.error("sharedOrgId is empty");
        reportShareService.insertReportShare(reportShareDTO);
        //返回数据
        reportShare latestReportShare = reportShareService.queryLatestReportShare();
        Map<String, Object> result = new HashMap<>();
        result.put("id", latestReportShare.getId());
        return Result.success(result);
    }

    @PutMapping("/api/report/share/{id}")
    public Result<Object> updateReportShare(@PathVariable String id, @RequestBody ReportShareDTO reportShareDTO) {
        log.info("更新共享状态，请求id -> {}，请求参数为 -> {}", id, reportShareDTO);
        reportShareService.updateReportShare(id, reportShareDTO);
        return Result.success();
    }
}