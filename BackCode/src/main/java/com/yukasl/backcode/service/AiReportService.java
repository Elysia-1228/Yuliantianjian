package com.yukasl.backcode.service;

import com.yukasl.backcode.pojo.entity.ThreatReportHistory;
import java.util.List;

public interface AiReportService {
    String generateReport(String type);
    List<ThreatReportHistory> getHistory();
    void renameReport(Integer id, String newTitle);
    void deleteReport(Integer id);
}
