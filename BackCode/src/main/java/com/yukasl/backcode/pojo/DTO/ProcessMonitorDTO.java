package com.yukasl.backcode.pojo.DTO;

import lombok.Data;

@Data
public class ProcessMonitorDTO {
    private String processId;
    private String processName;
    private String processStatus;
    private String abnormalReason;
    private Integer pageNum = 1;
    private Integer pageSize = 10;
}