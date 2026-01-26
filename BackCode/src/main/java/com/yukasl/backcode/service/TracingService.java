package com.yukasl.backcode.service;


import com.yukasl.backcode.pojo.DTO.tracingPageDTO;
import com.yukasl.backcode.pojo.entity.threatSourceTracing;
import com.yukasl.backcode.result.PageResult;

public interface TracingService {
    /**
     * 查询威胁溯源结果列表
     * @param tracingPageDTO
     * @return
     */
    PageResult page(tracingPageDTO tracingPageDTO);

    /**
     * 查看威胁溯源详情（含流程图）
     * @param id
     * @return
     */
    threatSourceTracing queryTracingById(Integer id);

    void saveTracing(threatSourceTracing sourceTracing);
}
