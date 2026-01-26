package com.yukasl.backcode.pojo.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class collectionHostPageDTO {
    private String hostIp;
    private Integer collectStatus;
    private Integer pageNum = 1;
    private Integer pageSize = 10;
}