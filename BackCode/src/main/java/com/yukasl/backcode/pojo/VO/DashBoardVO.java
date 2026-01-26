package com.yukasl.backcode.pojo.VO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DashBoardVO {
    private Integer securityScore;
    private Integer totalAttacksToday;
    private Integer activeThreats;
    private Integer protectedAssets;
    private String  idsStatus;
}
