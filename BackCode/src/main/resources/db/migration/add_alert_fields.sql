-- 为 potential_threat_alert 表添加缺失的字段
-- 用于支持 PIDS 因果溯源图谱的主机层数据

USE `net_safe`;

-- 添加攻击类型字段
ALTER TABLE `potential_threat_alert` 
ADD COLUMN `attack_type` VARCHAR(128) NULL COMMENT '攻击类型' AFTER `target_ip`;

-- 添加受影响进程字段
ALTER TABLE `potential_threat_alert` 
ADD COLUMN `affected_process` VARCHAR(255) NULL COMMENT '受影响进程' AFTER `attack_type`;

-- 添加受影响文件字段
ALTER TABLE `potential_threat_alert` 
ADD COLUMN `affected_file` VARCHAR(255) NULL COMMENT '受影响文件' AFTER `affected_process`;

-- 添加消息字段
ALTER TABLE `potential_threat_alert` 
ADD COLUMN `message` TEXT NULL COMMENT '告警消息' AFTER `affected_file`;

-- 添加索引以提高查询性能
CREATE INDEX `idx_source_ip` ON `potential_threat_alert`(`source_ip`);
CREATE INDEX `idx_attack_type` ON `potential_threat_alert`(`attack_type`);
