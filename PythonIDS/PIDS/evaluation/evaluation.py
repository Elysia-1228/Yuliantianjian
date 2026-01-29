# -*- coding: utf-8 -*-
"""
PIDS 检测性能评估模块
======================

多维度评估异常检测模型的性能，包括：
1. 准确率、精确率、召回率、F1分数
2. AUC-ROC曲线
3. 分类别检测率
4. 检测延迟统计

御链天鉴开发团队
"""

import json
import logging
import numpy as np
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import Counter

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
    precision_recall_curve, roc_curve
)

# 日志配置
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PIDS-Evaluation")


@dataclass
class EvaluationMetrics:
    """评估指标"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: float
    confusion_matrix: List[List[int]]
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    total_samples: int
    anomaly_samples: int
    normal_samples: int
    detection_time_mean_ms: float
    detection_time_std_ms: float
    evaluation_timestamp: str


@dataclass
class CategoryMetrics:
    """分类别指标"""
    attack_type: str
    total_count: int
    detected_count: int
    detection_rate: float
    avg_anomaly_score: float


class PerformanceEvaluator:
    """
    PIDS 检测性能评估器
    
    评估异常检测模型的各项性能指标
    """
    
    def __init__(self):
        """初始化评估器"""
        self.evaluation_history: List[EvaluationMetrics] = []
        self.category_metrics: Dict[str, CategoryMetrics] = {}
        logger.info("📊 性能评估器初始化完成")
    
    def evaluate(self,
                 y_true: np.ndarray,
                 y_pred: np.ndarray,
                 y_scores: np.ndarray = None,
                 detection_times: List[float] = None,
                 attack_types: List[str] = None) -> EvaluationMetrics:
        """
        评估模型性能
        
        Args:
            y_true: 真实标签 (0=正常, 1=异常)
            y_pred: 预测标签 (0=正常, 1=异常)
            y_scores: 异常得分 (可选)
            detection_times: 检测耗时列表 (ms)
            attack_types: 攻击类型列表 (用于分类别统计)
        
        Returns:
            评估指标
        """
        logger.info(f"📈 开始评估 | 样本数: {len(y_true)}")
        
        # 基础指标
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        # AUC-ROC
        if y_scores is not None and len(np.unique(y_true)) > 1:
            auc = roc_auc_score(y_true, y_scores)
        else:
            auc = 0.0
        
        # 混淆矩阵
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        
        # 检测时间统计
        if detection_times:
            time_mean = np.mean(detection_times)
            time_std = np.std(detection_times)
        else:
            time_mean, time_std = 0.0, 0.0
        
        metrics = EvaluationMetrics(
            accuracy=float(acc),
            precision=float(prec),
            recall=float(rec),
            f1_score=float(f1),
            auc_roc=float(auc),
            confusion_matrix=cm.tolist(),
            true_positives=int(tp),
            true_negatives=int(tn),
            false_positives=int(fp),
            false_negatives=int(fn),
            total_samples=len(y_true),
            anomaly_samples=int(np.sum(y_true == 1)),
            normal_samples=int(np.sum(y_true == 0)),
            detection_time_mean_ms=float(time_mean),
            detection_time_std_ms=float(time_std),
            evaluation_timestamp=datetime.now().isoformat()
        )
        
        # 保存历史
        self.evaluation_history.append(metrics)
        
        # 分类别统计
        if attack_types:
            self._calculate_category_metrics(y_true, y_pred, y_scores, attack_types)
        
        logger.info(f"✅ 评估完成 | 准确率: {acc:.4f} | F1: {f1:.4f} | AUC: {auc:.4f}")
        
        return metrics
    
    def _calculate_category_metrics(self,
                                     y_true: np.ndarray,
                                     y_pred: np.ndarray,
                                     y_scores: np.ndarray,
                                     attack_types: List[str]):
        """计算分类别指标"""
        self.category_metrics = {}
        
        type_counter = Counter(attack_types)
        
        for attack_type in set(attack_types):
            indices = [i for i, t in enumerate(attack_types) if t == attack_type]
            if not indices:
                continue
            
            total = len(indices)
            detected = sum(1 for i in indices if y_pred[i] == 1)
            scores = [y_scores[i] for i in indices] if y_scores is not None else [0.5] * total
            
            self.category_metrics[attack_type] = CategoryMetrics(
                attack_type=attack_type,
                total_count=total,
                detected_count=detected,
                detection_rate=detected / total if total > 0 else 0,
                avg_anomaly_score=float(np.mean(scores))
            )
    
    def get_roc_curve_data(self, y_true: np.ndarray, y_scores: np.ndarray) -> Dict[str, List[float]]:
        """获取ROC曲线数据"""
        if len(np.unique(y_true)) < 2:
            return {"fpr": [0, 1], "tpr": [0, 1], "thresholds": [1, 0]}
        
        fpr, tpr, thresholds = roc_curve(y_true, y_scores)
        return {
            "fpr": fpr.tolist(),
            "tpr": tpr.tolist(),
            "thresholds": thresholds.tolist()
        }
    
    def get_pr_curve_data(self, y_true: np.ndarray, y_scores: np.ndarray) -> Dict[str, List[float]]:
        """获取PR曲线数据"""
        if len(np.unique(y_true)) < 2:
            return {"precision": [1], "recall": [0], "thresholds": [1]}
        
        precision, recall, thresholds = precision_recall_curve(y_true, y_scores)
        return {
            "precision": precision.tolist(),
            "recall": recall.tolist(),
            "thresholds": thresholds.tolist() + [1.0]  # 补齐长度
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """获取评估摘要"""
        if not self.evaluation_history:
            return {"status": "no_evaluations"}
        
        latest = self.evaluation_history[-1]
        
        return {
            "status": "evaluated",
            "latest_evaluation": asdict(latest),
            "total_evaluations": len(self.evaluation_history),
            "category_metrics": {k: asdict(v) for k, v in self.category_metrics.items()},
            "history_summary": {
                "avg_accuracy": np.mean([e.accuracy for e in self.evaluation_history]),
                "avg_f1": np.mean([e.f1_score for e in self.evaluation_history]),
                "avg_auc": np.mean([e.auc_roc for e in self.evaluation_history])
            }
        }
    
    def generate_report(self) -> str:
        """生成评估报告"""
        if not self.evaluation_history:
            return "暂无评估数据"
        
        latest = self.evaluation_history[-1]
        
        report = []
        report.append("=" * 60)
        report.append("PIDS 检测性能评估报告")
        report.append("=" * 60)
        report.append(f"评估时间: {latest.evaluation_timestamp}")
        report.append(f"样本总数: {latest.total_samples}")
        report.append(f"  - 正常样本: {latest.normal_samples}")
        report.append(f"  - 异常样本: {latest.anomaly_samples}")
        report.append("")
        report.append("# 基础指标")
        report.append(f"  准确率 (Accuracy):  {latest.accuracy:.4f}")
        report.append(f"  精确率 (Precision): {latest.precision:.4f}")
        report.append(f"  召回率 (Recall):    {latest.recall:.4f}")
        report.append(f"  F1分数:             {latest.f1_score:.4f}")
        report.append(f"  AUC-ROC:            {latest.auc_roc:.4f}")
        report.append("")
        report.append("# 混淆矩阵")
        report.append(f"  真阳性 (TP): {latest.true_positives}")
        report.append(f"  真阴性 (TN): {latest.true_negatives}")
        report.append(f"  假阳性 (FP): {latest.false_positives}")
        report.append(f"  假阴性 (FN): {latest.false_negatives}")
        report.append("")
        report.append("# 检测效率")
        report.append(f"  平均检测时间: {latest.detection_time_mean_ms:.2f} ms")
        report.append(f"  时间标准差:   {latest.detection_time_std_ms:.2f} ms")
        
        if self.category_metrics:
            report.append("")
            report.append("# 分类别检测率")
            for attack_type, metrics in self.category_metrics.items():
                report.append(f"  {attack_type}:")
                report.append(f"    检测率: {metrics.detection_rate:.2%} ({metrics.detected_count}/{metrics.total_count})")
                report.append(f"    平均得分: {metrics.avg_anomaly_score:.4f}")
        
        report.append("")
        report.append("=" * 60)
        report.append("御链天鉴 - PIDS智能分析系统")
        report.append("=" * 60)
        
        return "\n".join(report)


# ============ 测试代码 ============
if __name__ == "__main__":
    print("=" * 60)
    print("📊 PIDS 性能评估模块测试")
    print("=" * 60)
    
    # 模拟数据
    np.random.seed(42)
    n_samples = 200
    
    # 真实标签
    y_true = np.array([0] * 150 + [1] * 50)
    
    # 预测标签（模拟一些错误）
    y_pred = y_true.copy()
    # 添加一些误判
    y_pred[140:148] = 1  # 8个假阳性
    y_pred[160:165] = 0  # 5个假阴性
    
    # 异常得分
    y_scores = np.random.rand(n_samples)
    y_scores[:150] *= 0.4  # 正常样本得分低
    y_scores[150:] = 0.6 + y_scores[150:] * 0.4  # 异常样本得分高
    
    # 攻击类型
    attack_types = ['normal'] * 150 + ['SQL注入'] * 20 + ['XSS攻击'] * 15 + ['命令执行'] * 15
    
    # 检测时间
    detection_times = np.random.exponential(20, n_samples).tolist()
    
    # 评估
    evaluator = PerformanceEvaluator()
    metrics = evaluator.evaluate(y_true, y_pred, y_scores, detection_times, attack_types)
    
    # 打印报告
    print(evaluator.generate_report())
    
    # 获取摘要
    print("\n摘要 (JSON):")
    summary = evaluator.get_summary()
    print(json.dumps(summary, indent=2, ensure_ascii=False, default=str))
