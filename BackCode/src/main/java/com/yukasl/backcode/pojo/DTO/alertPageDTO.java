package com.yukasl.backcode.pojo.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class alertPageDTO {
    private Integer id;
    private LocalDateTime occurTimeStart;
    private LocalDateTime occurTimeEnd;
    private Integer threatLevel;
    private Integer pageNum = 1;
    private Integer pageSize = 10;
}