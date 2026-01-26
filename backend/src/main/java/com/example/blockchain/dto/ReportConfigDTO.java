package com.example.blockchain.dto;

import lombok.Data;

@Data
public class ReportConfigDTO {
    private Integer id;
    private String reportType;
    private String startTime;
    private String endTime;
    private Integer reportStatus;
    private String reportUrl;
    private String createTime;
    private String updateTime;

    public Integer getId() { return id; }
    public void setId(Integer id) { this.id = id; }
    public String getReportType() { return reportType; }
    public void setReportType(String reportType) { this.reportType = reportType; }
    public String getStartTime() { return startTime; }
    public void setStartTime(String startTime) { this.startTime = startTime; }
    public String getEndTime() { return endTime; }
    public void setEndTime(String endTime) { this.endTime = endTime; }
    public Integer getReportStatus() { return reportStatus; }
    public void setReportStatus(Integer reportStatus) { this.reportStatus = reportStatus; }
    public String getReportUrl() { return reportUrl; }
    public void setReportUrl(String reportUrl) { this.reportUrl = reportUrl; }
    public String getCreateTime() { return createTime; }
    public void setCreateTime(String createTime) { this.createTime = createTime; }
    public String getUpdateTime() { return updateTime; }
    public void setUpdateTime(String updateTime) { this.updateTime = updateTime; }
}
