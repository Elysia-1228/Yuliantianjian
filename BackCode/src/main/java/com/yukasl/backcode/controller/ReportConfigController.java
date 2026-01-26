package com.yukasl.backcode.controller;

import com.yukasl.backcode.pojo.DTO.reportConfigDTO;
import com.yukasl.backcode.pojo.VO.ReportStatusVO;
import com.yukasl.backcode.result.PageResult;
import com.yukasl.backcode.result.Result;
import com.yukasl.backcode.service.ReportConfigServcie;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/report/config")
@Slf4j
public class ReportConfigController {
    @Autowired
    private ReportConfigServcie reportConfigServcie;

    /**
     * 查询报告生成配置列表
     */
    @GetMapping
    public Result<PageResult> queryReportConfig(reportConfigDTO reportConfigDTO) {
        log.info("查询报告生成配置列表,请求参数为 -> {}", reportConfigDTO);
        PageResult pageResult = reportConfigServcie.queryReportConfig(reportConfigDTO);
        return Result.success(pageResult);
    }

    /**
     * 新增报告生成配置
     */
    @PostMapping
    public Result addReportConfig(@RequestBody reportConfigDTO reportConfigDTO) {
        log.info("新增报告生成配置的请求参数为 -> {}", reportConfigDTO);
        Integer id = reportConfigServcie.addReportConfig(reportConfigDTO);
        return Result.success(id);
    }

    /**
     * 查询报告生成进度
     */
    @GetMapping("/{id}")
    public Result<ReportStatusVO> getReportStatus(@PathVariable Integer id) {
        log.info("要查询报告进度的Id为 -> {}", id);
        ReportStatusVO reportStatusVO = reportConfigServcie.getReportStatus(id);
        return Result.success(reportStatusVO);
    }
}