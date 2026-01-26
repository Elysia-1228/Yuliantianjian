package com.example.blockchain.dto;

import lombok.Data;

@Data
public class TrafficStatDTO {
    private Integer id;
    private String attackType;
    private String sourceIp;
    private String targetIp;
    private String statTime;
    private Integer attackCount;
    private String createTime;

    public Integer getId() { return id; }
    public void setId(Integer id) { this.id = id; }
    public String getAttackType() { return attackType; }
    public void setAttackType(String attackType) { this.attackType = attackType; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getTargetIp() { return targetIp; }
    public void setTargetIp(String targetIp) { this.targetIp = targetIp; }
    public String getStatTime() { return statTime; }
    public void setStatTime(String statTime) { this.statTime = statTime; }
    public Integer getAttackCount() { return attackCount; }
    public void setAttackCount(Integer attackCount) { this.attackCount = attackCount; }
    public String getCreateTime() { return createTime; }
    public void setCreateTime(String createTime) { this.createTime = createTime; }
}
