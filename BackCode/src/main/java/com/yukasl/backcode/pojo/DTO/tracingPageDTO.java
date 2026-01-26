package com.yukasl.backcode.pojo.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class tracingPageDTO {
    private String maliciousIp;
    private String threatSource;
    private Integer pageNum = 1;
    private Integer pageSize = 10;
}