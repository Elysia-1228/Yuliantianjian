package com.yukasl.backcode.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import lombok.extern.slf4j.Slf4j;

/**
 * 数据库自动更新工具
 * 用于在应用启动时自动同步数据库表结构，防止因缺少字段导致报错
 */
@Component
@Slf4j
public class DatabaseAutoUpdater implements CommandLineRunner {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public void run(String... args) throws Exception {
        log.info("=============================================");
        log.info("       Checking Database Schema...           ");
        log.info("=============================================");
        
        updateTable("host_status_monitor", "disk_usage", "ALTER TABLE host_status_monitor ADD COLUMN disk_usage double NULL COMMENT '磁盘使用率'");
        updateTable("host_status_monitor", "disk_info", "ALTER TABLE host_status_monitor ADD COLUMN disk_info varchar(255) NULL COMMENT '磁盘详情'");
        updateTable("host_status_monitor", "file_status", "ALTER TABLE host_status_monitor ADD COLUMN file_status text NULL COMMENT '核心文件状态(JSON)'");
        
        // Ensure report history table exists
        createTable("threat_report_history", "CREATE TABLE IF NOT EXISTS threat_report_history (" +
                "id INT AUTO_INCREMENT PRIMARY KEY, " +
                "title VARCHAR(255) NOT NULL, " +
                "report_type VARCHAR(50) NOT NULL, " +
                "content LONGTEXT, " +
                "create_time DATETIME DEFAULT CURRENT_TIMESTAMP" +
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

        log.info("=============================================");
        log.info("       Database Schema Check Completed       ");
        log.info("=============================================");
    }

    private void createTable(String tableName, String sql) {
        try {
            jdbcTemplate.execute(sql);
            log.info("[SUCCESS] Created/Checked table '{}'", tableName);
        } catch (Exception e) {
             log.warn("[WARNING] Failed to create table '{}': {}", tableName, e.getMessage());
        }
    }

    private void updateTable(String tableName, String columnName, String sql) {
        try {
            // 简单检查列是否存在可能会比较复杂（不同数据库语法不同）
            // 这里采用直接执行 ADD COLUMN，如果报错说明可能已存在
            // 为了更优雅，可以先查询 information_schema，但为了通用性，catch异常也是一种策略
            
            // 尝试执行
            jdbcTemplate.execute(sql);
            log.info("[SUCCESS] Added column '{}' to table '{}'", columnName, tableName);
        } catch (Exception e) {
            // 忽略错误，通常是因为列已存在
            if (e.getMessage().contains("Duplicate column name") || e.getMessage().contains("exists")) {
                log.info("[SKIPPED] Column '{}' already exists in table '{}'", columnName, tableName);
            } else {
                log.warn("[WARNING] Failed to add column '{}': {}", columnName, e.getMessage());
            }
        }
    }
}
