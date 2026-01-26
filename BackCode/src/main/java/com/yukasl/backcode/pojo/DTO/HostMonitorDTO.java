package com.yukasl.backcode.pojo.DTO;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class HostMonitorDTO {
    private String hostId;
    private LocalDateTime monitorTimeStart;
    private LocalDateTime monitorTimeEnd;
    private Integer pageNum = 1;
    private Integer pageSize = 10;
}