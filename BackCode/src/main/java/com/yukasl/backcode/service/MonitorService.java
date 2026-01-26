package com.yukasl.backcode.service;

import com.yukasl.backcode.pojo.DTO.HostMonitorDTO;
import com.yukasl.backcode.pojo.DTO.ProcessMonitorDTO;
import com.yukasl.backcode.pojo.entity.hostStatusMonitor;
import com.yukasl.backcode.result.PageResult;

public interface MonitorService {
    PageResult queryHostMonitor(HostMonitorDTO hostMonitorDTO);

    hostStatusMonitor queryHostMonitorByHostId(String hostId);

    PageResult queryProcessMonitor(ProcessMonitorDTO processMonitorDTO);

    void updateProcessMonitor(String id, ProcessMonitorDTO processMonitorDTO);

    void saveHostStatus(hostStatusMonitor status);

    void deleteHostMonitor(String hostId);
}