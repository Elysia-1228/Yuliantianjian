package com.yukasl.backcode.mapper;

import com.github.pagehelper.Page;
import com.yukasl.backcode.pojo.DTO.reportConfigDTO;
import com.yukasl.backcode.pojo.VO.ReportStatusVO;
import com.yukasl.backcode.pojo.entity.threatReportConfig;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface ReportConfigMapper {
    /**
     * 通过DTO条件查询报告配置
     *
     * @param reportConfigDTO
     * @return
     */
    Page<threatReportConfig> getByDTO(reportConfigDTO reportConfigDTO);

    /**
     * 新增报告生成配置
     *
     * @param threatReportConfig
     */
    void add(threatReportConfig threatReportConfig);

    /**
     * 根据Id查询
     *
     * @return
     */
    ReportStatusVO getById(Integer id);
}