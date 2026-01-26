package com.yukasl.backcode.pojo.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class pageTrafficDateDTO {
    private String attackType;
    private String sourceIp;
    private String targetIp;
    private LocalDateTime statTimeStart;
    private LocalDateTime statTimeEnd;
    private Integer pageNum = 1;
    private Integer pageSize = 10;
}