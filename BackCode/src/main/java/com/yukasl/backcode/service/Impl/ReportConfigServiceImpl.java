package com.yukasl.backcode.service.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.yukasl.backcode.mapper.ReportConfigMapper;
import com.yukasl.backcode.pojo.DTO.reportConfigDTO;
import com.yukasl.backcode.pojo.VO.ReportStatusVO;
import com.yukasl.backcode.pojo.entity.threatReportConfig;
import com.yukasl.backcode.result.PageResult;
import com.yukasl.backcode.service.ReportConfigServcie;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;

@Service
public class ReportConfigServiceImpl implements ReportConfigServcie {
    @Autowired
    private ReportConfigMapper reportConfigMapper;
    @Autowired
    private RestTemplate restTemplate;

    /**
     * 查询报告生成配置列表
     *
     * @param reportConfigDTO
     * @return
     */
    @Override
    public PageResult queryReportConfig(reportConfigDTO reportConfigDTO) {
        if (reportConfigDTO == null) {
            throw new RuntimeException("查询报告生成配置列表,请求参数为空");
        }
        PageHelper.startPage(reportConfigDTO.getPageNum(), reportConfigDTO.getPageSize());
        Page<threatReportConfig> p = reportConfigMapper.getByDTO(reportConfigDTO);
        return new PageResult(p.getTotal(), p.getResult());
    }

    /**
     * 新增报告生成配置
     *
     * @param reportConfigDTO
     * @return
     */
    @Override
    public Integer addReportConfig(reportConfigDTO reportConfigDTO) {
        if (reportConfigDTO == null) {
            throw new RuntimeException("新增报告生成配置请求参数为空");
        }
        if (reportConfigDTO.getReportType() == null) {
            throw new RuntimeException("新增报告生成配置请求参数报告类型为为空");
        }
        if (reportConfigDTO.getStartTime() == null) {
            throw new RuntimeException("新增报告生成配置请求参数开始时间为为空");
        }
        if (reportConfigDTO.getEndTime() == null) {
            throw new RuntimeException("新增报告生成配置请求参数结束时间为为空");
        }
        if (reportConfigDTO.getStartTime().isAfter(reportConfigDTO.getEndTime())) {
            throw new RuntimeException("新增报告生成配置请求参数开始时间不能晚于结束时间");
        }
        threatReportConfig threatReportConfig = new threatReportConfig();
        BeanUtils.copyProperties(reportConfigDTO, threatReportConfig);
        threatReportConfig.setCreateTime(LocalDateTime.now());
        threatReportConfig.setUpdateTime(LocalDateTime.now());
        threatReportConfig.setReportStatus(2);
        reportConfigMapper.add(threatReportConfig);
        restTemplate.postForObject("http://localhost:8080/api/chain/report", threatReportConfig, String.class);
        return threatReportConfig.getId();
    }

    @Override
    public ReportStatusVO getReportStatus(Integer id) {
        if (id == null) {
            throw new RuntimeException("查询报告生成进度的Id为空");
        }
        ReportStatusVO reportStatusVO = reportConfigMapper.getById(id);
        return reportStatusVO;
    }
}