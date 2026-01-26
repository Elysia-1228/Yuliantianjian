-- ============================================
-- 数据库升级脚本：全景统一视图支持
-- 功能：为 potential_threat_alert 表添加主机层数据字段
-- 日期：2026-01-22
-- ============================================

-- 添加攻击类型字段
ALTER TABLE potential_threat_alert 
ADD COLUMN attack_type VARCHAR(100) COMMENT '攻击类型' AFTER target_ip;

-- 添加受影响进程字段
ALTER TABLE potential_threat_alert 
ADD COLUMN affected_process VARCHAR(255) COMMENT '受影响的进程名' AFTER attack_type;

-- 添加受影响文件字段
ALTER TABLE potential_threat_alert 
ADD COLUMN affected_file VARCHAR(500) COMMENT '受影响的文件路径' AFTER affected_process;

-- 添加详细消息字段
ALTER TABLE potential_threat_alert 
ADD COLUMN message TEXT COMMENT '详细告警信息' AFTER affected_file;

-- 为新字段添加索引（提升查询性能）
CREATE INDEX idx_source_target ON potential_threat_alert(source_ip, target_ip, occur_time);
CREATE INDEX idx_attack_type ON potential_threat_alert(attack_type);

-- 验证表结构
SHOW COLUMNS FROM potential_threat_alert;
