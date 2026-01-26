package com.yukasl.backcode.pojo.VO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ReportStatusVO {
    private Integer id;
    private Integer reportStatus;
    private String reportUrl;
}