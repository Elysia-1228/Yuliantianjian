package com.yukasl.backcode.service.impl;

import com.github.pagehelper.PageHelper;
import com.yukasl.backcode.mapper.MonitorMapper;
import com.yukasl.backcode.pojo.DTO.HostMonitorDTO;
import com.yukasl.backcode.pojo.DTO.ProcessMonitorDTO;
import com.yukasl.backcode.pojo.entity.hostStatusMonitor;
import com.yukasl.backcode.pojo.entity.processMonitor;
import com.yukasl.backcode.result.PageResult;
import com.yukasl.backcode.service.MonitorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.time.LocalDateTime;

@Service
public class MonitorServiceImpl implements MonitorService {
    @Autowired
    private MonitorMapper monitorMapper;

    @Override
    public PageResult queryHostMonitor(HostMonitorDTO hostMonitorDTO) {
        PageHelper.startPage(hostMonitorDTO.getPageNum(), hostMonitorDTO.getPageSize());
        List<hostStatusMonitor> hostStatusMonitors = monitorMapper.queryHostMonitor(hostMonitorDTO);
        return new PageResult(hostStatusMonitors.size(), hostStatusMonitors);
    }

    @Override
    public hostStatusMonitor queryHostMonitorByHostId(String hostId) {
        return monitorMapper.queryHostMonitorByHostId(hostId);
    }

    @Override
    public PageResult queryProcessMonitor(ProcessMonitorDTO processMonitorDTO) {
        PageHelper.startPage(processMonitorDTO.getPageNum(), processMonitorDTO.getPageSize());
        List<processMonitor> processMonitors = monitorMapper.queryProcessMonitor(processMonitorDTO);
        return new PageResult(processMonitors.size(), processMonitors);
    }

    @Override
    public void updateProcessMonitor(String id, ProcessMonitorDTO processMonitorDTO) {
        monitorMapper.updateProcessMonitor(id, processMonitorDTO);
    }

    @Override
    public void saveHostStatus(hostStatusMonitor status) {
        if (status.getCreateTime() == null) {
            status.setCreateTime(LocalDateTime.now());
        }
        if (status.getMonitorTime() == null) {
            status.setMonitorTime(LocalDateTime.now());
        }
        monitorMapper.insertHostStatus(status);
    }

    @Override
    public void deleteHostMonitor(String hostId) {
        monitorMapper.deleteByHostId(hostId);
    }
}