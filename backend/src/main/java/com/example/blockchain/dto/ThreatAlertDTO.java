package com.example.blockchain.dto;

import lombok.Data;

@Data
public class ThreatAlertDTO {
    private Integer id;
    private String threatId;
    private Integer threatLevel;
    private String impactScope;
    private String occurTime;
    private String createTime;

    public Integer getId() { return id; }
    public void setId(Integer id) { this.id = id; }
    public String getThreatId() { return threatId; }
    public void setThreatId(String threatId) { this.threatId = threatId; }
    public Integer getThreatLevel() { return threatLevel; }
    public void setThreatLevel(Integer threatLevel) { this.threatLevel = threatLevel; }
    public String getImpactScope() { return impactScope; }
    public void setImpactScope(String impactScope) { this.impactScope = impactScope; }
    public String getOccurTime() { return occurTime; }
    public void setOccurTime(String occurTime) { this.occurTime = occurTime; }
    public String getCreateTime() { return createTime; }
    public void setCreateTime(String createTime) { this.createTime = createTime; }
}
