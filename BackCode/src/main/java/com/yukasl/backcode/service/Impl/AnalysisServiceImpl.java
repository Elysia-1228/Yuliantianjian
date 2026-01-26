package com.yukasl.backcode.service.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.autoconfigure.PageHelperProperties;
import com.yukasl.backcode.mapper.AnalysisMapper;
import com.yukasl.backcode.pojo.DTO.alertPageDTO;
import com.yukasl.backcode.pojo.DTO.pageTrafficDateDTO;
import com.yukasl.backcode.pojo.entity.potentialThreatAlert;
import com.yukasl.backcode.pojo.entity.threatTrafficStat;
import com.yukasl.backcode.result.PageResult;
import com.yukasl.backcode.service.AnalysisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class AnalysisServiceImpl implements AnalysisService {
    @Autowired
    private AnalysisMapper analysisMapper;
    @Autowired
    private PageHelperProperties Page;
    @Autowired
    private RestTemplate restTemplate;

    @org.springframework.beans.factory.annotation.Value("${external.blockchain-gateway.url}")
    private String blockchainUrl;

    /**
     * 查询威胁流量统计数据
     *
     * @param pageTrafficDateDTO
     * @return
     */
    @Override
    public PageResult pageTrafficDate(pageTrafficDateDTO pageTrafficDateDTO) {
        if (pageTrafficDateDTO == null) {
            throw new RuntimeException("查询威胁流量统计数据所需请求参数为空");
        }
        PageHelper.startPage(pageTrafficDateDTO.getPageNum(), pageTrafficDateDTO.getPageSize());
        List<threatTrafficStat> list = analysisMapper.page(pageTrafficDateDTO);
        Page<threatTrafficStat> p = (Page<threatTrafficStat>) list;
        return new PageResult(p.getTotal(), p.getResult());
    }

    /**
     * 查询潜在威胁预警列表
     *
     * @param alertPageDTO
     * @return
     */
    @Override
    public PageResult queryAlert(alertPageDTO alertPageDTO) {
        PageHelper.startPage(alertPageDTO.getPageNum(), alertPageDTO.getPageSize());
        List<potentialThreatAlert> list = analysisMapper.queryAlertPage(alertPageDTO);
        Page<potentialThreatAlert> p = (Page<potentialThreatAlert>) list;
        return new PageResult(p.getTotal(), p.getResult());
    }

    /**
     * 查看潜在威胁预警详情
     */
    @Override
    public potentialThreatAlert queryAlertById(Integer id) {
        if (id == null) {
            throw new RuntimeException("查看潜在威胁预警详情请求参数Id为空");
        }
        potentialThreatAlert threatAlert = analysisMapper.queryAlertById(id);
        return threatAlert;
    }

    @Override
    public potentialThreatAlert queryAlertByThreatId(String threatId) {
        if (threatId == null) {
            return null;
        }
        return analysisMapper.queryAlertByThreatId(threatId);
    }

    /**
     * 保存并上链告警
     */
    @Override
    public void saveAlert(potentialThreatAlert alert) {
        if (alert.getCreateTime() == null) {
            alert.setCreateTime(LocalDateTime.now());
        }
        if (alert.getOccurTime() == null) {
            alert.setOccurTime(LocalDateTime.now());
        }
        // 1. 保存到本地数据库 (供前端快速查询)
        analysisMapper.insert(alert);

        // 2. 推送到区块链网关 (存证)
        try {
            // Configured in application.yml
            // String url = "http://[::1]:8080/api/chain/alert";
            // 异步发送，避免阻塞
            restTemplate.postForObject(blockchainUrl, alert, String.class);
        } catch (Exception e) {
            // 上链失败不应影响本地存储，记录日志即可
            e.printStackTrace();
        }
    }

    @Override
    public List<java.util.Map<String, Object>> getTrendStats(String timeRange) {
        LocalDateTime endTime = LocalDateTime.now();
        LocalDateTime startTime;

        if ("7d".equals(timeRange)) {
            startTime = endTime.minusDays(7);
            return analysisMapper.countAlertsByDay(startTime, endTime);
        } else if ("30d".equals(timeRange)) {
            startTime = endTime.minusDays(30);
            return analysisMapper.countAlertsByDay(startTime, endTime);
        } else {
            // Default 24h
            startTime = endTime.minusHours(24);
            return analysisMapper.countAlertsByHour(startTime, endTime);
        }
    }
}