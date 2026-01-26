package com.yukasl.backcode.pojo.DTO;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class ReportShareDTO {
    private Integer id;
    private Integer reportId;
    private String sharedOrgId;
    private LocalDateTime shareTime;
    private Integer shareStatus;
    private Integer pageNum = 1;
    private Integer pageSize = 10;
}