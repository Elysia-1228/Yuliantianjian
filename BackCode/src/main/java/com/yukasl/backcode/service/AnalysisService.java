package com.yukasl.backcode.service;


import com.yukasl.backcode.pojo.DTO.alertPageDTO;
import com.yukasl.backcode.pojo.DTO.pageTrafficDateDTO;
import com.yukasl.backcode.pojo.entity.potentialThreatAlert;
import com.yukasl.backcode.result.PageResult;

public interface AnalysisService {
    /**
     * 查询威胁流量统计数据
     *
     * @param pageTrafficDateDTO
     * @return
     */
    PageResult pageTrafficDate(pageTrafficDateDTO pageTrafficDateDTO);

    /**
     * 查询潜在威胁预警列表
     *
     * @param alertPageDTO
     * @return
     */
    PageResult queryAlert(alertPageDTO alertPageDTO);

    /**
     * 查看潜在威胁预警详情
     *
     * @param id
     * @return
     */
    potentialThreatAlert queryAlertById(Integer id);

    /**
     * 根据 UUID 查询详情
     */
    potentialThreatAlert queryAlertByThreatId(String threatId);

    /**
     * 保存并上链告警
     */
    void saveAlert(potentialThreatAlert alert);

    /**
     * 获取攻击趋势统计数据
     */
    java.util.List<java.util.Map<String, Object>> getTrendStats(String timeRange);
}