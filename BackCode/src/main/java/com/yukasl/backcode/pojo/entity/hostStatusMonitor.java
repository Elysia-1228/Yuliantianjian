package com.yukasl.backcode.pojo.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class hostStatusMonitor {
    private Integer id;
    private String hostId;
    private Double cpuUsage;
    private Double memoryUsage;
    private Integer networkConn;
    private Double diskUsage;    // 磁盘使用率
    private String diskInfo;     // 磁盘详细信息 (e.g., "100GB/500GB")
    private String fileStatus;   // 核心文件状态 (JSON)
    
    // New fields from upgraded Agent
    private String cpuModel;
    private Integer cpuCores;
    private Double cpuFreq;
    private String memoryInfo;
    private Double memoryTotalGb;
    private Double memoryUsedGb;
    private Double diskTotalGb;
    private Double diskUsedGb;
    private Double diskFreeGb;
    private String diskPartitions; // JSON string

    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime monitorTime;
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createTime;
}