package com.example.blockchain.dto;

import lombok.Data;

@Data
public class SourceTracingDTO {
    private Integer id;
    private String threatSource;
    private String maliciousIp;
    private String attackCmd;
    private String malwareOrigin;
    private String attackPath;
    private String flowCharm;
    private String createTime;

    public Integer getId() { return id; }
    public void setId(Integer id) { this.id = id; }
    public String getThreatSource() { return threatSource; }
    public void setThreatSource(String threatSource) { this.threatSource = threatSource; }
    public String getMaliciousIp() { return maliciousIp; }
    public void setMaliciousIp(String maliciousIp) { this.maliciousIp = maliciousIp; }
    public String getAttackCmd() { return attackCmd; }
    public void setAttackCmd(String attackCmd) { this.attackCmd = attackCmd; }
    public String getMalwareOrigin() { return malwareOrigin; }
    public void setMalwareOrigin(String malwareOrigin) { this.malwareOrigin = malwareOrigin; }
    public String getAttackPath() { return attackPath; }
    public void setAttackPath(String attackPath) { this.attackPath = attackPath; }
    public String getFlowCharm() { return flowCharm; }
    public void setFlowCharm(String flowCharm) { this.flowCharm = flowCharm; }
    public String getCreateTime() { return createTime; }
    public void setCreateTime(String createTime) { this.createTime = createTime; }
}
