package com.yukasl.backcode.pojo.DTO;

import lombok.Data;

@Data
public class OrgInfoDTO {
    private Integer id;
    private String orgId;
    private String orgName;
    private Integer memberCount;
    private Integer maxMemberCount;
    private Integer adminPermission;
    private Integer pageNum = 1;
    private Integer pageSize = 10;
}