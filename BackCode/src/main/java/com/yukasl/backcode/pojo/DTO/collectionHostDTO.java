package com.yukasl.backcode.pojo.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class collectionHostDTO {
    private String hostIp;
    private Integer collectFreq;
    private Integer collectStatus;
}