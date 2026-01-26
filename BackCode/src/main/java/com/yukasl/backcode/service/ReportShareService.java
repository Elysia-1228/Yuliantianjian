package com.yukasl.backcode.service;

import com.yukasl.backcode.pojo.DTO.ReportShareDTO;
import com.yukasl.backcode.pojo.entity.reportShare;
import com.yukasl.backcode.result.PageResult;

public interface ReportShareService {
    PageResult queryReportShare(ReportShareDTO reportShareDTO);

    void insertReportShare(ReportShareDTO reportShareDTO);

    void updateReportShare(String id, ReportShareDTO reportShareDTO);

    reportShare queryLatestReportShare();
}