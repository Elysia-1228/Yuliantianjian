# -*- coding: utf-8 -*-
"""
PIDS 行为建模训练脚本（一体化）
================================

功能：
  L1: 集成异常检测器（IsolationForest + LOF + OCSVM + XGBoost）
  L2: VAE + MLP 双任务分类器（PyTorch）
  评估: ROC/PR/混淆矩阵/分类报告 + HTML报告

运行方式（在5880服务器上）：
  cd /home/test/YuLianTianJian_Core/data/preprocessed_data
  python train_models.py --data_dir pids_data --output_dir pids_models

依赖：
  pip install numpy scikit-learn xgboost torch matplotlib seaborn -i https://pypi.tuna.tsinghua.edu.cn/simple
"""

import os
import sys
import json
import time
import pickle
import logging
import argparse
import warnings
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
from collections import Counter

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, precision_recall_curve, average_precision_score,
    confusion_matrix, classification_report
)

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


# ============================================================
# L1: 集成异常检测器
# ============================================================

class EnsembleDetector:
    """
    L1 集成异常检测器

    集成 IsolationForest + LOF + OCSVM + XGBoost，通过加权投票产生最终预测。
    """

    def __init__(self, contamination: float = 0.2):
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.models = {}
        self.weights = {}
        self.xgb_model = None
        self.is_fitted = False
        self.threshold = 0.3  # 默认较低阈值，偏向高Recall

    def fit(self, X_train: np.ndarray, y_train: np.ndarray = None,
            X_val: np.ndarray = None, y_val: np.ndarray = None):
        """
        训练集成模型

        Args:
            X_train: 训练特征 (n_samples, 130)
            y_train: 训练标签 (可选，用于XGBoost有监督分类)
        """
        logger.info(f"训练集成检测器 | 样本数={X_train.shape[0]}, 特征维度={X_train.shape[1]}")

        # 标准化
        X_scaled = self.scaler.fit_transform(X_train)

        # 1. Isolation Forest
        logger.info("  训练 IsolationForest...")
        t0 = time.time()
        self.models['isolation_forest'] = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42,
            max_samples='auto',
            n_jobs=-1
        )
        self.models['isolation_forest'].fit(X_scaled)
        logger.info(f"    完成 ({time.time()-t0:.1f}s)")

        # 2. Local Outlier Factor
        logger.info("  训练 LocalOutlierFactor...")
        t0 = time.time()
        self.models['lof'] = LocalOutlierFactor(
            n_neighbors=20,
            contamination=self.contamination,
            novelty=True,
            n_jobs=-1
        )
        self.models['lof'].fit(X_scaled)
        logger.info(f"    完成 ({time.time()-t0:.1f}s)")

        # 3. One-Class SVM
        logger.info("  训练 OneClassSVM...")
        t0 = time.time()
        self.models['ocsvm'] = OneClassSVM(
            kernel='rbf',
            gamma='scale',
            nu=self.contamination
        )
        self.models['ocsvm'].fit(X_scaled)
        logger.info(f"    完成 ({time.time()-t0:.1f}s)")

        # 4. XGBoost（有监督，需要标签）
        if y_train is not None:
            try:
                import xgboost as xgb
                logger.info("  训练 XGBoost...")
                t0 = time.time()
                self.xgb_model = xgb.XGBClassifier(
                    n_estimators=200,
                    max_depth=6,
                    learning_rate=0.1,
                    use_label_encoder=False,
                    eval_metric='logloss',
                    random_state=42,
                    n_jobs=-1
                )
                self.xgb_model.fit(X_scaled, y_train)
                logger.info(f"    完成 ({time.time()-t0:.1f}s)")
            except ImportError:
                logger.warning("  XGBoost 未安装，跳过有监督分类器")
                self.xgb_model = None

        # 设置权重
        self.weights = {
            'isolation_forest': 0.25,
            'lof': 0.25,
            'ocsvm': 0.20,
        }
        if self.xgb_model is not None:
            self.weights['xgboost'] = 0.30
            # 重新归一化
            total = sum(self.weights.values())
            self.weights = {k: v/total for k, v in self.weights.items()}

        self.is_fitted = True
        logger.info(f"  集成权重: {self.weights}")

        # 自动调优阈值（在验证集上寻找最佳F1的阈值）
        if y_train is not None:
            val_X = X_val if X_val is not None else X_train
            val_y = y_val if y_val is not None else y_train
            self._optimize_threshold(val_X, val_y)

    def _optimize_threshold(self, X: np.ndarray, y: np.ndarray):
        """在验证数据上搜索最佳F1阈值"""
        scores = self.predict_scores(X)
        best_f1 = 0
        best_t = 0.3
        for t in np.arange(0.1, 0.9, 0.02):
            pred = (scores >= t).astype(int)
            f1 = f1_score(y, pred, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_t = t
        self.threshold = best_t
        logger.info(f"  最优阈值: {best_t:.2f} (F1={best_f1:.4f})")

    def predict_scores(self, X: np.ndarray) -> np.ndarray:
        """
        计算集成异常得分 (0~1, 越高越异常)
        """
        X_scaled = self.scaler.transform(X)
        scores = np.zeros(len(X))

        for name, model in self.models.items():
            raw = -model.decision_function(X_scaled)
            # min-max 归一化
            s_min, s_max = raw.min(), raw.max()
            if s_max > s_min:
                normalized = (raw - s_min) / (s_max - s_min)
            else:
                normalized = np.zeros_like(raw)
            scores += self.weights.get(name, 0) * normalized

        if self.xgb_model is not None:
            xgb_proba = self.xgb_model.predict_proba(X_scaled)[:, 1]
            scores += self.weights.get('xgboost', 0) * xgb_proba

        return np.clip(scores, 0, 1)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """预测标签: 0=正常, 1=异常"""
        scores = self.predict_scores(X)
        return (scores >= self.threshold).astype(int)

    def save(self, path: str):
        """保存模型"""
        data = {
            'models': self.models,
            'xgb_model': self.xgb_model,
            'scaler': self.scaler,
            'weights': self.weights,
            'threshold': self.threshold,
            'contamination': self.contamination,
            'is_fitted': self.is_fitted,
            'saved_at': datetime.now().isoformat(),
        }
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(data, f)
        logger.info(f"L1 模型已保存: {path}")

    def load(self, path: str):
        """加载模型"""
        with open(path, 'rb') as f:
            data = pickle.load(f)
        self.models = data['models']
        self.xgb_model = data['xgb_model']
        self.scaler = data['scaler']
        self.weights = data['weights']
        self.threshold = data['threshold']
        self.contamination = data['contamination']
        self.is_fitted = data['is_fitted']
        logger.info(f"L1 模型已加载: {path}")


# ============================================================
# L2: VAE + MLP 双任务分类器 (PyTorch)
# ============================================================

class VAEClassifier:
    """
    L2 VAE + MLP 双任务模型

    任务1: VAE重建 → 异常得分（重建误差越大越异常）
    任务2: MLP分类 → 二分类（正常/异常）
    """

    def __init__(self, input_dim: int = 130, latent_dim: int = 32,
                 hidden_dim: int = 64, lr: float = 1e-3, device: str = 'cpu'):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.hidden_dim = hidden_dim
        self.lr = lr
        self.device_name = device
        self.scaler = StandardScaler()
        self.model = None
        self.optimizer = None
        self.train_losses = []
        self.val_losses = []
        self.is_fitted = False

    def _build_model(self):
        """构建 PyTorch 模型"""
        import torch
        import torch.nn as nn

        device = torch.device(self.device_name)

        class VAEClassifierNet(nn.Module):
            def __init__(self, input_dim, hidden_dim, latent_dim):
                super().__init__()
                # Encoder
                self.enc_fc1 = nn.Linear(input_dim, hidden_dim)
                self.enc_fc2 = nn.Linear(hidden_dim, hidden_dim)
                self.enc_mu = nn.Linear(hidden_dim, latent_dim)
                self.enc_logvar = nn.Linear(hidden_dim, latent_dim)

                # Decoder
                self.dec_fc1 = nn.Linear(latent_dim, hidden_dim)
                self.dec_fc2 = nn.Linear(hidden_dim, hidden_dim)
                self.dec_out = nn.Linear(hidden_dim, input_dim)

                # Classifier
                self.cls_fc1 = nn.Linear(latent_dim, hidden_dim)
                self.cls_fc2 = nn.Linear(hidden_dim, 32)
                self.cls_out = nn.Linear(32, 2)

                self.relu = nn.ReLU()
                self.dropout = nn.Dropout(0.3)

            def encode(self, x):
                h = self.relu(self.enc_fc1(x))
                h = self.dropout(self.relu(self.enc_fc2(h)))
                return self.enc_mu(h), self.enc_logvar(h)

            def reparameterize(self, mu, logvar):
                std = torch.exp(0.5 * logvar)
                eps = torch.randn_like(std)
                return mu + eps * std

            def decode(self, z):
                h = self.relu(self.dec_fc1(z))
                h = self.dropout(self.relu(self.dec_fc2(h)))
                return self.dec_out(h)

            def classify(self, z):
                h = self.relu(self.cls_fc1(z))
                h = self.dropout(self.relu(self.cls_fc2(h)))
                return self.cls_out(h)

            def forward(self, x):
                mu, logvar = self.encode(x)
                z = self.reparameterize(mu, logvar)
                recon = self.decode(z)
                cls_logits = self.classify(z)
                return recon, mu, logvar, cls_logits

        self.model = VAEClassifierNet(self.input_dim, self.hidden_dim, self.latent_dim).to(device)
        self.optimizer = torch.optim.AdamW(self.model.parameters(), lr=self.lr, weight_decay=1e-5)

    def fit(self, X_train: np.ndarray, y_train: np.ndarray,
            X_val: np.ndarray = None, y_val: np.ndarray = None,
            epochs: int = 200, batch_size: int = 64, patience: int = 20,
            alpha: float = 1.0, beta: float = 1.0):
        """
        训练 VAE + MLP 双任务模型

        Args:
            X_train, y_train: 训练数据
            X_val, y_val: 验证数据
            epochs: 最大训练轮数
            batch_size: 批大小
            patience: 早停耐心值
            alpha: 重建损失权重
            beta: 分类损失权重
        """
        import torch
        import torch.nn as nn
        from torch.utils.data import TensorDataset, DataLoader

        device = torch.device(self.device_name)
        self._build_model()

        # 标准化
        X_train_scaled = self.scaler.fit_transform(X_train)
        train_X = torch.FloatTensor(X_train_scaled).to(device)
        train_y = torch.LongTensor(y_train).to(device)
        train_loader = DataLoader(TensorDataset(train_X, train_y),
                                  batch_size=batch_size, shuffle=True)

        if X_val is not None and y_val is not None:
            X_val_scaled = self.scaler.transform(X_val)
            val_X = torch.FloatTensor(X_val_scaled).to(device)
            val_y = torch.LongTensor(y_val).to(device)
        else:
            val_X, val_y = None, None

        # 类别权重（处理不平衡）
        class_counts = Counter(y_train)
        total = len(y_train)
        weight_0 = total / (2 * class_counts.get(0, 1))
        weight_1 = total / (2 * class_counts.get(1, 1))
        class_weight = torch.FloatTensor([weight_0, weight_1]).to(device)

        cls_criterion = nn.CrossEntropyLoss(weight=class_weight)
        mse_criterion = nn.MSELoss()

        best_val_loss = float('inf')
        patience_counter = 0
        best_state = None

        logger.info(f"开始训练 VAE+MLP | epochs={epochs}, batch_size={batch_size}, "
                    f"device={self.device_name}, 类别权重={class_weight.cpu().numpy()}")

        for epoch in range(epochs):
            self.model.train()
            epoch_recon_loss = 0
            epoch_kl_loss = 0
            epoch_cls_loss = 0
            n_batches = 0

            for batch_X, batch_y in train_loader:
                recon, mu, logvar, cls_logits = self.model(batch_X)

                # 重建损失
                recon_loss = mse_criterion(recon, batch_X)
                # KL散度
                kl_loss = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp())
                # 分类损失
                cls_loss = cls_criterion(cls_logits, batch_y)

                loss = alpha * (recon_loss + 0.1 * kl_loss) + beta * cls_loss

                self.optimizer.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                self.optimizer.step()

                epoch_recon_loss += recon_loss.item()
                epoch_kl_loss += kl_loss.item()
                epoch_cls_loss += cls_loss.item()
                n_batches += 1

            avg_train_loss = (epoch_recon_loss + epoch_kl_loss + epoch_cls_loss) / n_batches
            self.train_losses.append(avg_train_loss)

            # 验证
            val_loss = avg_train_loss
            if val_X is not None:
                self.model.eval()
                with torch.no_grad():
                    recon, mu, logvar, cls_logits = self.model(val_X)
                    v_recon = mse_criterion(recon, val_X).item()
                    v_kl = (-0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp())).item()
                    v_cls = cls_criterion(cls_logits, val_y).item()
                    val_loss = v_recon + v_kl + v_cls
            self.val_losses.append(val_loss)

            if (epoch + 1) % 10 == 0:
                logger.info(f"  Epoch {epoch+1}/{epochs} | "
                            f"train_loss={avg_train_loss:.4f} | val_loss={val_loss:.4f}")

            # 早停
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                best_state = {k: v.cpu().clone() for k, v in self.model.state_dict().items()}
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    logger.info(f"  早停于 Epoch {epoch+1}")
                    break

        # 恢复最佳模型
        if best_state is not None:
            self.model.load_state_dict({k: v.to(device) for k, v in best_state.items()})

        self.is_fitted = True
        logger.info(f"VAE+MLP 训练完成 | 最佳 val_loss={best_val_loss:.4f}")

    def predict_scores(self, X: np.ndarray) -> np.ndarray:
        """计算异常得分（基于 logit 差值 sigmoid，避免 softmax 过饱和）"""
        import torch

        device = torch.device(self.device_name)
        self.model.eval()

        X_scaled = self.scaler.transform(X)
        X_t = torch.FloatTensor(X_scaled).to(device)

        with torch.no_grad():
            recon, mu, logvar, cls_logits = self.model(X_t)

            # 用 logit 差值 + sigmoid（比 softmax 有更多梯度信息）
            logit_diff = (cls_logits[:, 1] - cls_logits[:, 0]).cpu().numpy()
            scores = 1.0 / (1.0 + np.exp(-logit_diff))

        return np.clip(scores, 0, 1)

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """预测标签"""
        scores = self.predict_scores(X)
        return (scores >= threshold).astype(int)

    def save(self, path: str):
        """保存模型"""
        import torch
        data = {
            'model_state': self.model.state_dict() if self.model else None,
            'scaler': self.scaler,
            'input_dim': self.input_dim,
            'latent_dim': self.latent_dim,
            'hidden_dim': self.hidden_dim,
            'device_name': self.device_name,
            'train_losses': self.train_losses,
            'val_losses': self.val_losses,
            'is_fitted': self.is_fitted,
            'saved_at': datetime.now().isoformat(),
        }
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        torch.save(data, path)
        logger.info(f"L2 模型已保存: {path}")

    def load(self, path: str):
        """加载模型"""
        import torch
        data = torch.load(path, map_location=self.device_name, weights_only=False)
        self.scaler = data['scaler']
        self.input_dim = data['input_dim']
        self.latent_dim = data['latent_dim']
        self.hidden_dim = data['hidden_dim']
        self.train_losses = data['train_losses']
        self.val_losses = data['val_losses']
        self.is_fitted = data['is_fitted']
        self._build_model()
        self.model.load_state_dict(data['model_state'])
        self.model.eval()
        logger.info(f"L2 模型已加载: {path}")


# ============================================================
# 评估 + 可视化
# ============================================================

def evaluate_model(y_true: np.ndarray, y_pred: np.ndarray, y_scores: np.ndarray,
                   model_name: str) -> Dict[str, Any]:
    """全面评估模型性能"""
    metrics = {
        'model_name': model_name,
        'accuracy': accuracy_score(y_true, y_pred),
        'precision': precision_score(y_true, y_pred, zero_division=0),
        'recall': recall_score(y_true, y_pred, zero_division=0),
        'f1': f1_score(y_true, y_pred, zero_division=0),
    }

    try:
        metrics['auc_roc'] = roc_auc_score(y_true, y_scores)
    except ValueError:
        metrics['auc_roc'] = 0.0

    try:
        metrics['auc_pr'] = average_precision_score(y_true, y_scores)
    except ValueError:
        metrics['auc_pr'] = 0.0

    metrics['confusion_matrix'] = confusion_matrix(y_true, y_pred).tolist()

    report = classification_report(y_true, y_pred, target_names=['正常', '异常'], output_dict=True)
    metrics['classification_report'] = report

    return metrics


def generate_evaluation_plots(results: Dict, output_dir: str):
    """生成评估可视化图表"""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.font_manager as fm
        plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans']
        plt.rcParams['axes.unicode_minus'] = False
    except ImportError:
        logger.warning("matplotlib 未安装，跳过可视化")
        return

    os.makedirs(output_dir, exist_ok=True)

    for model_name, data in results.items():
        y_true = np.array(data['y_true'])
        y_scores = np.array(data['y_scores'])
        y_pred = np.array(data['y_pred'])
        metrics = data['metrics']

        fig, axes = plt.subplots(2, 2, figsize=(14, 12))
        fig.suptitle(f'PIDS Model Evaluation - {model_name}', fontsize=16, fontweight='bold')

        # 1. ROC Curve
        ax = axes[0, 0]
        try:
            fpr, tpr, _ = roc_curve(y_true, y_scores)
            ax.plot(fpr, tpr, 'b-', linewidth=2,
                    label=f'AUC = {metrics["auc_roc"]:.4f}')
            ax.plot([0, 1], [0, 1], 'r--', alpha=0.5)
            ax.set_xlabel('False Positive Rate')
            ax.set_ylabel('True Positive Rate')
            ax.set_title('ROC Curve')
            ax.legend(loc='lower right')
            ax.grid(True, alpha=0.3)
        except Exception:
            ax.text(0.5, 0.5, 'ROC N/A', ha='center', va='center')

        # 2. PR Curve
        ax = axes[0, 1]
        try:
            prec, rec, _ = precision_recall_curve(y_true, y_scores)
            ax.plot(rec, prec, 'g-', linewidth=2,
                    label=f'AP = {metrics["auc_pr"]:.4f}')
            ax.set_xlabel('Recall')
            ax.set_ylabel('Precision')
            ax.set_title('Precision-Recall Curve')
            ax.legend(loc='lower left')
            ax.grid(True, alpha=0.3)
        except Exception:
            ax.text(0.5, 0.5, 'PR N/A', ha='center', va='center')

        # 3. Confusion Matrix
        ax = axes[1, 0]
        cm = np.array(metrics['confusion_matrix'])
        try:
            import seaborn as sns
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                        xticklabels=['Normal', 'Anomaly'],
                        yticklabels=['Normal', 'Anomaly'])
        except ImportError:
            ax.imshow(cm, cmap='Blues')
            for i in range(cm.shape[0]):
                for j in range(cm.shape[1]):
                    ax.text(j, i, str(cm[i, j]), ha='center', va='center', fontsize=14)
            ax.set_xticks([0, 1])
            ax.set_xticklabels(['Normal', 'Anomaly'])
            ax.set_yticks([0, 1])
            ax.set_yticklabels(['Normal', 'Anomaly'])
        ax.set_xlabel('Predicted')
        ax.set_ylabel('Actual')
        ax.set_title('Confusion Matrix')

        # 4. Metrics Bar
        ax = axes[1, 1]
        metric_names = ['Accuracy', 'Precision', 'Recall', 'F1', 'AUC-ROC']
        metric_values = [metrics['accuracy'], metrics['precision'], metrics['recall'],
                         metrics['f1'], metrics['auc_roc']]
        colors = ['#2196F3', '#4CAF50', '#FF9800', '#F44336', '#9C27B0']
        bars = ax.bar(metric_names, metric_values, color=colors, alpha=0.8)
        for bar, val in zip(bars, metric_values):
            ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.01,
                    f'{val:.3f}', ha='center', va='bottom', fontweight='bold')
        ax.set_ylim(0, 1.15)
        ax.set_title('Performance Metrics')
        ax.grid(True, alpha=0.3, axis='y')

        plt.tight_layout()
        plot_path = os.path.join(output_dir, f'{model_name}_evaluation.png')
        plt.savefig(plot_path, dpi=150, bbox_inches='tight')
        plt.close()
        logger.info(f"评估图表已保存: {plot_path}")


def generate_html_report(all_results: Dict, output_path: str):
    """生成HTML评估报告"""
    html_parts = ["""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>PIDS 模型评估报告</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; color: #333; }
.container { max-width: 1000px; margin: auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); }
h1 { color: #1a237e; border-bottom: 3px solid #3f51b5; padding-bottom: 12px; }
h2 { color: #283593; margin-top: 30px; }
table { width: 100%; border-collapse: collapse; margin: 16px 0; }
th, td { padding: 10px 14px; text-align: center; border: 1px solid #e0e0e0; }
th { background: #3f51b5; color: white; }
tr:nth-child(even) { background: #f5f5f5; }
.good { color: #2e7d32; font-weight: bold; }
.warn { color: #f57f17; font-weight: bold; }
.bad { color: #c62828; font-weight: bold; }
.metric-card { display: inline-block; text-align: center; padding: 16px 24px; margin: 8px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; min-width: 120px; }
.metric-card .value { font-size: 28px; font-weight: bold; }
.metric-card .label { font-size: 12px; opacity: 0.9; }
img { max-width: 100%; margin: 16px 0; border-radius: 8px; }
.timestamp { color: #999; font-size: 13px; }
</style>
</head>
<body>
<div class="container">
<h1>PIDS 行为建模评估报告</h1>
<p class="timestamp">生成时间: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """ | 御链天鉴开发团队</p>
"""]

    for model_name, data in all_results.items():
        m = data['metrics']
        html_parts.append(f"<h2>{model_name}</h2>")

        # 指标卡片
        html_parts.append('<div>')
        for label, key in [('Accuracy', 'accuracy'), ('Precision', 'precision'),
                           ('Recall', 'recall'), ('F1-Score', 'f1'), ('AUC-ROC', 'auc_roc')]:
            val = m[key]
            html_parts.append(f'<div class="metric-card"><div class="value">{val:.3f}</div><div class="label">{label}</div></div>')
        html_parts.append('</div>')

        # 混淆矩阵表格
        cm = m['confusion_matrix']
        html_parts.append("""
        <h3>混淆矩阵</h3>
        <table>
        <tr><th></th><th>预测: 正常</th><th>预测: 异常</th></tr>
        """)
        html_parts.append(f'<tr><th>实际: 正常</th><td>{cm[0][0]}</td><td>{cm[0][1]}</td></tr>')
        html_parts.append(f'<tr><th>实际: 异常</th><td>{cm[1][0]}</td><td>{cm[1][1]}</td></tr>')
        html_parts.append('</table>')

        # 图表
        img_path = f'{model_name}_evaluation.png'
        if os.path.exists(os.path.join(os.path.dirname(output_path), img_path)):
            html_parts.append(f'<img src="{img_path}" alt="Evaluation Plot">')

    # 对比表
    html_parts.append('<h2>模型对比</h2><table>')
    html_parts.append('<tr><th>模型</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th><th>AUC-ROC</th></tr>')
    for model_name, data in all_results.items():
        m = data['metrics']

        def color_cls(v):
            if v >= 0.90:
                return 'good'
            elif v >= 0.75:
                return 'warn'
            return 'bad'

        html_parts.append(f'<tr><td>{model_name}</td>')
        for key in ['accuracy', 'precision', 'recall', 'f1', 'auc_roc']:
            v = m[key]
            html_parts.append(f'<td class="{color_cls(v)}">{v:.4f}</td>')
        html_parts.append('</tr>')
    html_parts.append('</table>')

    html_parts.append('</div></body></html>')

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html_parts))
    logger.info(f"HTML 评估报告已生成: {output_path}")


# ============================================================
# 主流程
# ============================================================

def load_dataset(data_dir: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """加载数据集"""
    train = np.load(os.path.join(data_dir, 'train_dataset.npz'))
    val = np.load(os.path.join(data_dir, 'val_dataset.npz'))
    test = np.load(os.path.join(data_dir, 'test_dataset.npz'))

    X_train, y_train = train['features'], train['labels']
    X_val, y_val = val['features'], val['labels']
    X_test, y_test = test['features'], test['labels']

    logger.info(f"数据集加载完成:")
    logger.info(f"  训练集: {X_train.shape}, 正常={np.sum(y_train==0)}, 异常={np.sum(y_train==1)}")
    logger.info(f"  验证集: {X_val.shape}, 正常={np.sum(y_val==0)}, 异常={np.sum(y_val==1)}")
    logger.info(f"  测试集: {X_test.shape}, 正常={np.sum(y_test==0)}, 异常={np.sum(y_test==1)}")

    return X_train, y_train, X_val, y_val, X_test, y_test


def main():
    parser = argparse.ArgumentParser(description="PIDS 行为建模训练")
    parser.add_argument("--data_dir", type=str, required=True,
                        help="数据集目录 (含train/val/test_dataset.npz)")
    parser.add_argument("--output_dir", type=str, default="pids_models",
                        help="模型和报告输出目录")
    parser.add_argument("--device", type=str, default="cuda",
                        help="PyTorch 设备 (cuda/cpu)")
    parser.add_argument("--epochs", type=int, default=200,
                        help="VAE 训练轮数")
    parser.add_argument("--skip_l1", action='store_true', help="跳过 L1 训练")
    parser.add_argument("--skip_l2", action='store_true', help="跳过 L2 训练")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # 加载数据
    X_train, y_train, X_val, y_val, X_test, y_test = load_dataset(args.data_dir)

    all_results = {}

    # ===== L1: 集成检测器 =====
    if not args.skip_l1:
        logger.info("=" * 60)
        logger.info("Phase 1: L1 集成异常检测器")
        logger.info("=" * 60)

        l1 = EnsembleDetector(contamination=0.2)
        l1.fit(X_train, y_train, X_val, y_val)

        # 在测试集上评估
        l1_scores = l1.predict_scores(X_test)
        l1_pred = l1.predict(X_test)

        l1_metrics = evaluate_model(y_test, l1_pred, l1_scores, "L1_Ensemble")
        logger.info(f"L1 测试结果: Acc={l1_metrics['accuracy']:.4f} | "
                    f"P={l1_metrics['precision']:.4f} | R={l1_metrics['recall']:.4f} | "
                    f"F1={l1_metrics['f1']:.4f} | AUC={l1_metrics['auc_roc']:.4f}")

        # 保存模型
        l1_path = os.path.join(args.output_dir, 'ensemble_v1.0.pkl')
        l1.save(l1_path)

        all_results['L1_Ensemble'] = {
            'metrics': l1_metrics,
            'y_true': y_test.tolist(),
            'y_pred': l1_pred.tolist(),
            'y_scores': l1_scores.tolist(),
        }

    # ===== L2: VAE + MLP =====
    if not args.skip_l2:
        logger.info("=" * 60)
        logger.info("Phase 2: L2 VAE + MLP 分类器")
        logger.info("=" * 60)

        # 检测设备
        device = args.device
        try:
            import torch
            if device == 'cuda' and not torch.cuda.is_available():
                logger.warning("CUDA 不可用，回退到 CPU")
                device = 'cpu'
            else:
                logger.info(f"使用设备: {device} ({torch.cuda.get_device_name(0) if device == 'cuda' else 'CPU'})")
        except ImportError:
            logger.error("PyTorch 未安装，跳过 L2 训练")
            device = None

        if device is not None:
            l2 = VAEClassifier(input_dim=130, latent_dim=32, hidden_dim=64,
                               lr=1e-3, device=device)
            l2.fit(X_train, y_train, X_val, y_val,
                   epochs=args.epochs, batch_size=64, patience=20)

            # 测试集评估
            l2_scores = l2.predict_scores(X_test)
            l2_pred = l2.predict(X_test)

            l2_metrics = evaluate_model(y_test, l2_pred, l2_scores, "L2_VAE_MLP")
            logger.info(f"L2 测试结果: Acc={l2_metrics['accuracy']:.4f} | "
                        f"P={l2_metrics['precision']:.4f} | R={l2_metrics['recall']:.4f} | "
                        f"F1={l2_metrics['f1']:.4f} | AUC={l2_metrics['auc_roc']:.4f}")

            # 保存模型
            l2_path = os.path.join(args.output_dir, 'vae_classifier_v1.0.pt')
            l2.save(l2_path)

            all_results['L2_VAE_MLP'] = {
                'metrics': l2_metrics,
                'y_true': y_test.tolist(),
                'y_pred': l2_pred.tolist(),
                'y_scores': l2_scores.tolist(),
            }

    # ===== 评估报告 =====
    if all_results:
        logger.info("=" * 60)
        logger.info("Phase 3: 生成评估报告")
        logger.info("=" * 60)

        # 可视化图表
        generate_evaluation_plots(all_results, args.output_dir)

        # HTML 报告
        report_path = os.path.join(args.output_dir, 'eval_report_v1.0.html')
        generate_html_report(all_results, report_path)

        # 保存指标 JSON
        metrics_path = os.path.join(args.output_dir, 'metrics.json')
        metrics_json = {}
        for name, data in all_results.items():
            metrics_json[name] = data['metrics']
        with open(metrics_path, 'w', encoding='utf-8') as f:
            json.dump(metrics_json, f, ensure_ascii=False, indent=2)
        logger.info(f"指标 JSON 已保存: {metrics_path}")

    logger.info("=" * 60)
    logger.info("全部训练完成！")
    logger.info(f"输出目录: {args.output_dir}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
