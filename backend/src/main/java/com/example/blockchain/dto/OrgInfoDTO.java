package com.example.blockchain.dto;

import lombok.Data;

@Data
public class OrgInfoDTO {
    private Integer id;
    private String orgId;
    private String orgName;
    private Integer memberCount;
    private Integer adminPermission;
    private String createTime;
    private String updateTime;

    public Integer getId() { return id; }
    public void setId(Integer id) { this.id = id; }
    public String getOrgId() { return orgId; }
    public void setOrgId(String orgId) { this.orgId = orgId; }
    public String getOrgName() { return orgName; }
    public void setOrgName(String orgName) { this.orgName = orgName; }
    public Integer getMemberCount() { return memberCount; }
    public void setMemberCount(Integer memberCount) { this.memberCount = memberCount; }
    public Integer getAdminPermission() { return adminPermission; }
    public void setAdminPermission(Integer adminPermission) { this.adminPermission = adminPermission; }
    public String getCreateTime() { return createTime; }
    public void setCreateTime(String createTime) { this.createTime = createTime; }
    public String getUpdateTime() { return updateTime; }
    public void setUpdateTime(String updateTime) { this.updateTime = updateTime; }
}
