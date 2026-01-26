-- Upgrade script for host_status_monitor table to support new agent fields
-- Run this script in your MySQL database

ALTER TABLE host_status_monitor ADD COLUMN cpu_model VARCHAR(128) COMMENT 'CPU型号';
ALTER TABLE host_status_monitor ADD COLUMN cpu_cores INT COMMENT 'CPU核心数';
ALTER TABLE host_status_monitor ADD COLUMN cpu_freq DOUBLE COMMENT 'CPU频率(GHz)';
ALTER TABLE host_status_monitor ADD COLUMN memory_info VARCHAR(128) COMMENT '内存信息';
ALTER TABLE host_status_monitor ADD COLUMN memory_total_gb DOUBLE COMMENT '内存总大小(GB)';
ALTER TABLE host_status_monitor ADD COLUMN memory_used_gb DOUBLE COMMENT '内存已用(GB)';
ALTER TABLE host_status_monitor ADD COLUMN disk_total_gb DOUBLE COMMENT '磁盘总大小(GB)';
ALTER TABLE host_status_monitor ADD COLUMN disk_used_gb DOUBLE COMMENT '磁盘已用(GB)';
ALTER TABLE host_status_monitor ADD COLUMN disk_free_gb DOUBLE COMMENT '磁盘剩余(GB)';
ALTER TABLE host_status_monitor ADD COLUMN disk_partitions TEXT COMMENT '磁盘分区详情(JSON)';
