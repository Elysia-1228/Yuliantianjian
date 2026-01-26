package com.yukasl.backcode.service.impl;

import com.github.pagehelper.PageHelper;
import com.yukasl.backcode.mapper.ReportShareMapper;
import com.yukasl.backcode.pojo.DTO.ReportShareDTO;
import com.yukasl.backcode.pojo.entity.reportShare;
import com.yukasl.backcode.result.PageResult;
import com.yukasl.backcode.service.ReportShareService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class ReportShareServiceImpl implements ReportShareService {
    @Autowired
    private ReportShareMapper reportShareMapper;

    @Override
    public PageResult queryReportShare(ReportShareDTO reportShareDTO) {
        PageHelper.startPage(reportShareDTO.getPageNum(), reportShareDTO.getPageSize());
        List<reportShare> hostStatusMonitors = reportShareMapper.queryReportShare(reportShareDTO);
        return new PageResult(hostStatusMonitors.size(), hostStatusMonitors);
    }

    public void insertReportShare(ReportShareDTO reportShareDTO) {
        if (reportShareDTO.getShareStatus() == 1)
            reportShareDTO.setShareTime(LocalDateTime.now());
        reportShareMapper.insertReportShare(reportShareDTO);
    }

    public void updateReportShare(String id, ReportShareDTO reportShareDTO) {
        if (reportShareDTO.getShareStatus() == 1)
            reportShareDTO.setShareTime(LocalDateTime.now());
        reportShareMapper.updateReportShare(id, reportShareDTO);
    }

    @Override
    public reportShare queryLatestReportShare() {
        return reportShareMapper.queryLatestReportShare();
    }
}