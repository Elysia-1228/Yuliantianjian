-- ============================================================
-- PIDS 特征提取引擎 - 数据库表结构
-- 御链天鉴开发团队
-- ============================================================

-- 特征向量表
CREATE TABLE IF NOT EXISTS `pids_feature_vectors` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT '主键ID',
    `threat_id` VARCHAR(64) NOT NULL COMMENT '威胁ID',
    `attack_type` VARCHAR(64) DEFAULT NULL COMMENT '攻击类型',
    `source_ip` VARCHAR(45) DEFAULT NULL COMMENT '攻击源IP',
    `target_ip` VARCHAR(45) DEFAULT NULL COMMENT '目标IP',
    `feature_vector` JSON NOT NULL COMMENT '130维特征向量',
    `feature_groups` JSON DEFAULT NULL COMMENT '分组特征',
    `node_count` INT DEFAULT 0 COMMENT '节点数量',
    `edge_count` INT DEFAULT 0 COMMENT '边数量',
    `threat_score` FLOAT DEFAULT 0 COMMENT '威胁得分',
    `anomaly_score` FLOAT DEFAULT 0 COMMENT '异常得分',
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    INDEX `idx_threat_id` (`threat_id`),
    INDEX `idx_attack_type` (`attack_type`),
    INDEX `idx_source_ip` (`source_ip`),
    INDEX `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='PIDS特征向量表';

-- 特征统计表（用于训练基线）
CREATE TABLE IF NOT EXISTS `pids_feature_statistics` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT '主键ID',
    `feature_name` VARCHAR(64) NOT NULL COMMENT '特征名称',
    `feature_index` INT NOT NULL COMMENT '特征索引(0-129)',
    `feature_group` VARCHAR(32) NOT NULL COMMENT '特征分组',
    `normal_mean` FLOAT DEFAULT 0 COMMENT '正常值均值',
    `normal_std` FLOAT DEFAULT 0 COMMENT '正常值标准差',
    `normal_min` FLOAT DEFAULT 0 COMMENT '正常值最小值',
    `normal_max` FLOAT DEFAULT 0 COMMENT '正常值最大值',
    `threshold_low` FLOAT DEFAULT 0 COMMENT '异常阈值下限',
    `threshold_high` FLOAT DEFAULT 0 COMMENT '异常阈值上限',
    `sample_count` INT DEFAULT 0 COMMENT '样本数量',
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    UNIQUE KEY `uk_feature_name` (`feature_name`),
    INDEX `idx_feature_group` (`feature_group`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='PIDS特征统计表';

-- 检测模型表
CREATE TABLE IF NOT EXISTS `pids_detection_models` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT '主键ID',
    `model_name` VARCHAR(64) NOT NULL COMMENT '模型名称',
    `model_type` VARCHAR(32) NOT NULL COMMENT '模型类型(autoencoder/isolation_forest/one_class_svm/gnn/lstm)',
    `model_version` VARCHAR(16) DEFAULT '1.0' COMMENT '模型版本',
    `model_path` VARCHAR(256) DEFAULT NULL COMMENT '模型文件路径',
    `model_params` JSON DEFAULT NULL COMMENT '模型参数',
    `accuracy` FLOAT DEFAULT 0 COMMENT '准确率',
    `precision_score` FLOAT DEFAULT 0 COMMENT '精确率',
    `recall` FLOAT DEFAULT 0 COMMENT '召回率',
    `f1_score` FLOAT DEFAULT 0 COMMENT 'F1分数',
    `auc_roc` FLOAT DEFAULT 0 COMMENT 'AUC-ROC',
    `training_samples` INT DEFAULT 0 COMMENT '训练样本数',
    `is_active` TINYINT(1) DEFAULT 0 COMMENT '是否激活',
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    INDEX `idx_model_type` (`model_type`),
    INDEX `idx_is_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='PIDS检测模型表';

-- 检测结果表
CREATE TABLE IF NOT EXISTS `pids_detection_results` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT '主键ID',
    `threat_id` VARCHAR(64) NOT NULL COMMENT '威胁ID',
    `model_id` BIGINT DEFAULT NULL COMMENT '使用的模型ID',
    `prediction` VARCHAR(16) NOT NULL COMMENT '预测结果(normal/anomaly)',
    `confidence` FLOAT DEFAULT 0 COMMENT '置信度',
    `anomaly_score` FLOAT DEFAULT 0 COMMENT '异常得分',
    `detection_time_ms` INT DEFAULT 0 COMMENT '检测耗时(毫秒)',
    `feature_highlights` JSON DEFAULT NULL COMMENT '异常特征高亮',
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    INDEX `idx_threat_id` (`threat_id`),
    INDEX `idx_prediction` (`prediction`),
    FOREIGN KEY (`model_id`) REFERENCES `pids_detection_models`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='PIDS检测结果表';

-- ============================================================
-- 初始化数据
-- ============================================================

-- 插入默认模型记录
INSERT INTO `pids_detection_models` (`model_name`, `model_type`, `model_version`, `is_active`) VALUES
('默认异常检测器', 'isolation_forest', '1.0', 1)
ON DUPLICATE KEY UPDATE `updated_at` = CURRENT_TIMESTAMP;
