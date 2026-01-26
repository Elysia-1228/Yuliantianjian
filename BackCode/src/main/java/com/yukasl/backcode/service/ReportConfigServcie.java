package com.yukasl.backcode.service;

import com.yukasl.backcode.pojo.DTO.reportConfigDTO;
import com.yukasl.backcode.pojo.VO.ReportStatusVO;
import com.yukasl.backcode.result.PageResult;

public interface ReportConfigServcie {
    /**
     * 查询报告生成配置列表
     *
     * @param reportConfigDTO
     * @return
     */
    PageResult queryReportConfig(reportConfigDTO reportConfigDTO);

    /**
     * 新增报告生成配置
     *
     * @param reportConfigDTO
     * @return
     */
    Integer addReportConfig(reportConfigDTO reportConfigDTO);

    /**
     * 查询报告生成进度
     *
     * @param id
     * @return
     */
    ReportStatusVO getReportStatus(Integer id);
}