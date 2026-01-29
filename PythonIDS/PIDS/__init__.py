# -*- coding: utf-8 -*-
"""
PIDS 因果溯源图智能分析模块
===========================

本模块实现 PIDS 因果溯源图的智能分析功能，包括：
1. 特征提取引擎 - 从溯源图中提取130维特征向量
2. 行为建模系统 - 训练异常检测模型
3. 检测性能评估 - 多维度评估检测效果

使用示例：
    from PIDS.feature_extractor import FeatureExtractor
    
    extractor = FeatureExtractor()
    features = extractor.extract(graph_data)
"""

__version__ = "1.0.0"
__author__ = "御链天鉴开发团队"

from .feature_extraction import FeatureExtractor
from .behavior_modeling import BehaviorModeler, ModelConfig, DetectionResult
from .evaluation import PerformanceEvaluator

__all__ = [
    'FeatureExtractor',
    'BehaviorModeler', 'ModelConfig', 'DetectionResult',
    'PerformanceEvaluator'
]
