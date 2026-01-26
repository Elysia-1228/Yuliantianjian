package com.yukasl.backcode.controller;

import com.yukasl.backcode.pojo.DTO.HostMonitorDTO;
import com.yukasl.backcode.pojo.DTO.ProcessMonitorDTO;
import com.yukasl.backcode.pojo.entity.hostStatusMonitor;
import com.yukasl.backcode.result.PageResult;
import com.yukasl.backcode.result.Result;
import com.yukasl.backcode.service.MonitorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import com.yukasl.backcode.service.CommandQueueService;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;

@RestController
@Slf4j
public class MonitorController {
    @Autowired
    private MonitorService monitorService;

    @Autowired
    private CommandQueueService commandQueueService;

    @GetMapping("/api/host/monitor")
    public Result<PageResult> queryHostMonitor(HostMonitorDTO hostMonitorDTO) {
        log.info("查询主机状态监控列表，请求参数为 -> {}", hostMonitorDTO);
        if (hostMonitorDTO.getMonitorTimeStart() != null && hostMonitorDTO.getMonitorTimeEnd() != null && hostMonitorDTO.getMonitorTimeStart().isAfter(hostMonitorDTO.getMonitorTimeEnd()))
            return Result.error("monitorTimeStart晚于monitorTimeEnd");
        return Result.success(monitorService.queryHostMonitor(hostMonitorDTO));
    }

    @GetMapping("/api/host/monitor/realtime/{hostId}")
    public Result<hostStatusMonitor> queryHostMonitorByHostId(@PathVariable String hostId) {
        log.info("查询主机实时状态，请求参数为 -> {}", hostId);
        hostStatusMonitor hostStatusMonitor = monitorService.queryHostMonitorByHostId(hostId);
        if (hostStatusMonitor == null)
            return Result.error("hostId not found");
        return Result.success(hostStatusMonitor);
    }

    @DeleteMapping("/api/host/monitor/{hostId}")
    public Result deleteHostMonitor(@PathVariable String hostId) {
        log.info("删除主机监控历史数据，请求参数为 -> {}", hostId);
        monitorService.deleteHostMonitor(hostId);
        return Result.success();
    }

    @GetMapping("/api/process/monitor")
    public Result<PageResult> queryProcessMonitor(ProcessMonitorDTO processMonitorDTO) {
        log.info("查询系统进程监控列表，请求参数为 -> {}", processMonitorDTO);
        return Result.success(monitorService.queryProcessMonitor(processMonitorDTO));
    }

    @PutMapping("/api/process/monitor/{id}")
    public Result<Object> updateProcessMonitor(@PathVariable String id, @RequestBody ProcessMonitorDTO processMonitorDTO) {
        log.info("处理异常进程，请求id -> {}，请求参数为 -> {}", id, processMonitorDTO);
        monitorService.updateProcessMonitor(id, processMonitorDTO);
        return Result.success();
    }

    @PostMapping("/api/host/monitor/report")
    public Result<Map<String, Object>> reportHostStatus(@RequestBody hostStatusMonitor status) {
        // 1. 保存状态
        monitorService.saveHostStatus(status);
        
        // 2. 检查是否有待执行指令
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("status", "received");
        
        String command = commandQueueService.pollCommand(status.getHostId());
        
        // 如果特定主机的队列为空，且主机ID不是 127.0.0.1，尝试检查 127.0.0.1 的队列 (作为默认通道)
        if (command == null && !"127.0.0.1".equals(status.getHostId())) {
             command = commandQueueService.pollCommand("127.0.0.1");
             if (command != null) {
                 log.info("从默认通道(127.0.0.1)向主机 {} 下发指令: {}", status.getHostId(), command);
             }
        }

        if (command != null) {
            log.info("向主机 {} 下发指令: {}", status.getHostId(), command);
            List<String> commands = new ArrayList<>();
            commands.add(command);
            responseData.put("commands", commands);
        }
        
        return Result.success(responseData);
    }
}