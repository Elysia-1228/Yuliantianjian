# -*- coding: utf-8 -*-
"""
PIDS 行为建模系统
==================

基于特征向量训练异常检测模型，支持多种算法：
1. Isolation Forest - 孤立森林
2. One-Class SVM - 单类支持向量机
3. Autoencoder - 自编码器
4. Local Outlier Factor - 局部异常因子

御链天鉴开发团队
"""

import os
import json
import pickle
import logging
import numpy as np
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

# 机器学习库
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

# 日志配置
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PIDS-Modeling")


@dataclass
class ModelConfig:
    """模型配置"""
    model_type: str  # isolation_forest, one_class_svm, autoencoder, lof
    model_name: str
    version: str = "1.0"
    contamination: float = 0.1  # 异常比例
    random_state: int = 42
    params: Dict = None
    
    def __post_init__(self):
        if self.params is None:
            self.params = {}


@dataclass
class DetectionResult:
    """检测结果"""
    threat_id: str
    prediction: str  # "normal" or "anomaly"
    anomaly_score: float  # 0-1之间，越高越异常
    confidence: float  # 置信度
    feature_highlights: List[Dict]  # 异常特征高亮
    detection_time_ms: int
    model_name: str
    timestamp: str


class BehaviorModeler:
    """
    PIDS 行为建模器
    
    负责训练和使用异常检测模型
    """
    
    # 支持的模型类型
    SUPPORTED_MODELS = ['isolation_forest', 'one_class_svm', 'lof']
    
    def __init__(self, model_dir: str = None):
        """
        初始化行为建模器
        
        Args:
            model_dir: 模型保存目录
        """
        self.model_dir = model_dir or os.path.join(os.path.dirname(__file__), 'models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        self.scaler = StandardScaler()
        self.model = None
        self.model_config: Optional[ModelConfig] = None
        self.is_fitted = False
        
        # 特征名称（130维）
        self.feature_names = self._get_feature_names()
        
        logger.info(f"🧠 行为建模器初始化完成 | 模型目录: {self.model_dir}")
    
    def _get_feature_names(self) -> List[str]:
        """获取130维特征名称"""
        names = []
        # 图结构特征 (15维)
        names.extend([f'graph_{i}' for i in range(15)])
        # 节点特征 (40维)
        names.extend([f'node_{i}' for i in range(40)])
        # 边特征 (25维)
        names.extend([f'edge_{i}' for i in range(25)])
        # 序列特征 (30维)
        names.extend([f'seq_{i}' for i in range(30)])
        # 语义特征 (20维)
        names.extend([f'sem_{i}' for i in range(20)])
        return names
    
    def create_model(self, config: ModelConfig) -> Any:
        """
        创建模型实例
        
        Args:
            config: 模型配置
        
        Returns:
            模型实例
        """
        model_type = config.model_type.lower()
        
        if model_type == 'isolation_forest':
            return IsolationForest(
                n_estimators=config.params.get('n_estimators', 100),
                contamination=config.contamination,
                random_state=config.random_state,
                max_samples=config.params.get('max_samples', 'auto'),
                n_jobs=-1
            )
        elif model_type == 'one_class_svm':
            return OneClassSVM(
                kernel=config.params.get('kernel', 'rbf'),
                gamma=config.params.get('gamma', 'scale'),
                nu=config.contamination
            )
        elif model_type == 'lof':
            return LocalOutlierFactor(
                n_neighbors=config.params.get('n_neighbors', 20),
                contamination=config.contamination,
                novelty=True,  # 允许在新数据上预测
                n_jobs=-1
            )
        else:
            raise ValueError(f"不支持的模型类型: {model_type}")
    
    def train(self, 
              features: np.ndarray, 
              config: ModelConfig,
              validation_split: float = 0.2) -> Dict[str, Any]:
        """
        训练异常检测模型
        
        Args:
            features: 特征矩阵 (n_samples, 130)
            config: 模型配置
            validation_split: 验证集比例
        
        Returns:
            训练结果统计
        """
        logger.info(f"🚀 开始训练模型 | 类型: {config.model_type} | 样本数: {len(features)}")
        
        start_time = datetime.now()
        
        # 数据预处理
        X = np.array(features)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        
        # 标准化
        X_scaled = self.scaler.fit_transform(X)
        
        # 划分训练集和验证集
        if len(X_scaled) > 10:
            X_train, X_val = train_test_split(X_scaled, test_size=validation_split, random_state=42)
        else:
            X_train, X_val = X_scaled, X_scaled
        
        # 创建并训练模型
        self.model = self.create_model(config)
        self.model.fit(X_train)
        self.model_config = config
        self.is_fitted = True
        
        # 计算训练集得分
        train_scores = self._calculate_anomaly_scores(X_train)
        val_scores = self._calculate_anomaly_scores(X_val)
        
        # 统计结果
        training_time = (datetime.now() - start_time).total_seconds()
        
        result = {
            'model_type': config.model_type,
            'model_name': config.model_name,
            'version': config.version,
            'training_samples': len(X_train),
            'validation_samples': len(X_val),
            'training_time_seconds': training_time,
            'train_score_mean': float(np.mean(train_scores)),
            'train_score_std': float(np.std(train_scores)),
            'val_score_mean': float(np.mean(val_scores)),
            'val_score_std': float(np.std(val_scores)),
            'contamination': config.contamination,
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"✅ 模型训练完成 | 耗时: {training_time:.2f}s | 训练样本: {len(X_train)}")
        
        return result
    
    def _calculate_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """计算异常得分（归一化到0-1）"""
        if not self.is_fitted:
            return np.zeros(len(X))
        
        if isinstance(self.model, IsolationForest):
            # IsolationForest: decision_function返回负数表示异常
            raw_scores = -self.model.decision_function(X)
            # 归一化到0-1
            scores = (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-10)
        elif isinstance(self.model, OneClassSVM):
            raw_scores = -self.model.decision_function(X)
            scores = 1 / (1 + np.exp(-raw_scores))  # Sigmoid归一化
        elif isinstance(self.model, LocalOutlierFactor):
            raw_scores = -self.model.decision_function(X)
            scores = (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-10)
        else:
            scores = np.zeros(len(X))
        
        return np.clip(scores, 0, 1)
    
    def predict(self, 
                features: np.ndarray, 
                threat_id: str = None,
                threshold: float = 0.5) -> DetectionResult:
        """
        对单个样本进行异常检测
        
        Args:
            features: 130维特征向量
            threat_id: 威胁ID
            threshold: 异常阈值
        
        Returns:
            检测结果
        """
        if not self.is_fitted:
            raise RuntimeError("模型未训练，请先调用train方法")
        
        start_time = datetime.now()
        
        # 预处理
        X = np.array(features).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        
        # 预测
        anomaly_score = float(self._calculate_anomaly_scores(X_scaled)[0])
        prediction = "anomaly" if anomaly_score > threshold else "normal"
        
        # 计算置信度
        confidence = abs(anomaly_score - 0.5) * 2  # 距离阈值越远，置信度越高
        
        # 找出异常特征
        feature_highlights = self._find_anomaly_features(X[0], anomaly_score)
        
        detection_time = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return DetectionResult(
            threat_id=threat_id or f"threat_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            prediction=prediction,
            anomaly_score=anomaly_score,
            confidence=confidence,
            feature_highlights=feature_highlights,
            detection_time_ms=detection_time,
            model_name=self.model_config.model_name if self.model_config else "unknown",
            timestamp=datetime.now().isoformat()
        )
    
    def _find_anomaly_features(self, features: np.ndarray, anomaly_score: float, top_k: int = 5) -> List[Dict]:
        """找出最异常的特征"""
        # 简化实现：根据特征值的绝对大小排序
        feature_values = list(zip(self.feature_names, features))
        sorted_features = sorted(feature_values, key=lambda x: abs(x[1]), reverse=True)
        
        highlights = []
        for name, value in sorted_features[:top_k]:
            highlights.append({
                'name': name,
                'value': float(value),
                'contribution': float(abs(value) / (np.sum(np.abs(features)) + 1e-10))
            })
        
        return highlights
    
    def save_model(self, filename: str = None) -> str:
        """保存模型到文件"""
        if not self.is_fitted:
            raise RuntimeError("模型未训练，无法保存")
        
        filename = filename or f"{self.model_config.model_name}_{self.model_config.version}.pkl"
        filepath = os.path.join(self.model_dir, filename)
        
        save_data = {
            'model': self.model,
            'scaler': self.scaler,
            'config': asdict(self.model_config),
            'feature_names': self.feature_names,
            'saved_at': datetime.now().isoformat()
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(save_data, f)
        
        logger.info(f"💾 模型已保存: {filepath}")
        return filepath
    
    def load_model(self, filename: str) -> bool:
        """从文件加载模型"""
        filepath = os.path.join(self.model_dir, filename)
        
        if not os.path.exists(filepath):
            logger.error(f"模型文件不存在: {filepath}")
            return False
        
        with open(filepath, 'rb') as f:
            save_data = pickle.load(f)
        
        self.model = save_data['model']
        self.scaler = save_data['scaler']
        self.model_config = ModelConfig(**save_data['config'])
        self.feature_names = save_data['feature_names']
        self.is_fitted = True
        
        logger.info(f"📂 模型已加载: {filename}")
        return True
    
    def get_model_info(self) -> Dict[str, Any]:
        """获取当前模型信息"""
        if not self.model_config:
            return {'status': 'no_model'}
        
        return {
            'status': 'ready' if self.is_fitted else 'not_fitted',
            'model_type': self.model_config.model_type,
            'model_name': self.model_config.model_name,
            'version': self.model_config.version,
            'contamination': self.model_config.contamination,
            'feature_dimensions': len(self.feature_names)
        }


# ============ 测试代码 ============
if __name__ == "__main__":
    print("=" * 60)
    print("🧠 PIDS 行为建模系统测试")
    print("=" * 60)
    
    # 生成模拟数据
    np.random.seed(42)
    normal_samples = np.random.randn(100, 130) * 0.5  # 正常样本
    anomaly_samples = np.random.randn(10, 130) * 2 + 3  # 异常样本
    
    # 创建建模器
    modeler = BehaviorModeler()
    
    # 配置模型
    config = ModelConfig(
        model_type='isolation_forest',
        model_name='pids_anomaly_detector',
        version='1.0',
        contamination=0.1
    )
    
    # 训练模型
    result = modeler.train(normal_samples, config)
    print("\n训练结果:")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    
    # 测试检测
    print("\n检测正常样本:")
    normal_result = modeler.predict(normal_samples[0], "test_normal")
    print(f"  预测: {normal_result.prediction} | 得分: {normal_result.anomaly_score:.4f}")
    
    print("\n检测异常样本:")
    anomaly_result = modeler.predict(anomaly_samples[0], "test_anomaly")
    print(f"  预测: {anomaly_result.prediction} | 得分: {anomaly_result.anomaly_score:.4f}")
    
    # 保存模型
    model_path = modeler.save_model()
    print(f"\n模型保存路径: {model_path}")
    
    # 模型信息
    print("\n模型信息:")
    print(json.dumps(modeler.get_model_info(), indent=2, ensure_ascii=False))
