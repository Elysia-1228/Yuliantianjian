# -*- coding: utf-8 -*-
"""
行为建模系统模块
================

训练异常检测模型，支持多种算法

御链天鉴开发团队
"""

from .behavior_modeling import BehaviorModeler, ModelConfig, DetectionResult

__all__ = ['BehaviorModeler', 'ModelConfig', 'DetectionResult']
