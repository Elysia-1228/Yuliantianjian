# -*- coding: utf-8 -*-
"""
NIDS 模型评估脚本
=================

在测试集上评估 TransEC-GAN Discriminator 的分类性能。

运行方式（在5880服务器上）：
  cd /home/test/ids_project
  python nids_evaluate.py \
    --data_dir preprocessed \
    --model_path transec_gan_model/best_model_4x5880_max.pth \
    --output_dir eval_reports

御链天鉴开发团队
"""

import os
import sys
import json
import argparse
import logging
import warnings
import numpy as np
import torch
import torch.nn as nn
from collections import Counter
from datetime import datetime
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve,
    precision_recall_curve, average_precision_score
)
from sklearn.preprocessing import label_binarize

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# 导入模型定义
from nids_train_transec_gan import TransformerEncoder, Discriminator


def evaluate_on_test(model_path: str, data_dir: str, output_dir: str, device: str = 'cuda'):
    """在测试集上全面评估模型"""
    os.makedirs(output_dir, exist_ok=True)

    # 加载数据配置
    with open(os.path.join(data_dir, 'data_stats.json'), 'r', encoding='utf-8') as f:
        data_stats = json.load(f)

    pca_dim = data_stats['pca_dim']
    num_classes = data_stats['num_classes']
    seq_len = data_stats['seq_len']
    class_names = data_stats['class_names']

    # 加载模型
    logger.info(f"加载模型: {model_path}")
    checkpoint = torch.load(model_path, map_location=device, weights_only=False)

    disc = Discriminator(pca_dim, num_classes, seq_len).to(device)
    disc_state = checkpoint['discriminator_state_dict']
    # 处理 DataParallel 前缀
    if any(k.startswith('module.') for k in disc_state.keys()):
        disc_state = {k.replace('module.', ''): v for k, v in disc_state.items()}
    disc.load_state_dict(disc_state)
    disc.eval()

    train_epoch = checkpoint.get('epoch', '?')
    train_acc = checkpoint.get('val_accuracy', 0)
    logger.info(f"模型训练 Epoch={train_epoch}, Val_acc={train_acc*100:.2f}%")

    # 加载测试集
    test_data = np.load(os.path.join(data_dir, 'test_sequences.npz'))
    X_test, y_test = test_data['X'], test_data['y']
    logger.info(f"测试集: {X_test.shape}, 类别分布: {dict(Counter(y_test.tolist()))}")

    # 推理
    logger.info("开始推理...")
    all_preds = []
    all_scores = []
    all_real_scores = []

    batch_size = 512
    with torch.no_grad():
        for i in range(0, len(X_test), batch_size):
            batch = torch.FloatTensor(X_test[i:i+batch_size]).to(device)
            real_score, class_logits = disc(batch)

            probs = torch.softmax(class_logits, dim=1).cpu().numpy()
            preds = class_logits.argmax(dim=1).cpu().numpy()
            r_scores = torch.sigmoid(real_score).cpu().numpy().flatten()

            all_preds.extend(preds.tolist())
            all_scores.append(probs)
            all_real_scores.extend(r_scores.tolist())

    y_pred = np.array(all_preds)
    y_scores = np.vstack(all_scores)
    real_scores = np.array(all_real_scores)

    # ===== 计算指标 =====
    acc = accuracy_score(y_test, y_pred)
    precision_macro = precision_score(y_test, y_pred, labels=list(range(num_classes)), average='macro', zero_division=0)
    recall_macro = recall_score(y_test, y_pred, labels=list(range(num_classes)), average='macro', zero_division=0)
    f1_macro = f1_score(y_test, y_pred, labels=list(range(num_classes)), average='macro', zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, labels=list(range(num_classes)), average='weighted', zero_division=0)

    # AUC-ROC (One-vs-Rest)
    y_test_bin = label_binarize(y_test, classes=list(range(num_classes)))
    try:
        auc_macro = roc_auc_score(y_test_bin, y_scores, average='macro', multi_class='ovr')
        auc_weighted = roc_auc_score(y_test_bin, y_scores, average='weighted', multi_class='ovr')
    except ValueError:
        auc_macro = 0.0
        auc_weighted = 0.0

    all_labels = list(range(num_classes))
    cm = confusion_matrix(y_test, y_pred, labels=all_labels)
    cls_report = classification_report(y_test, y_pred, labels=all_labels,
                                       target_names=class_names, digits=4,
                                       zero_division=0)

    logger.info("\n" + "=" * 60)
    logger.info("评估结果")
    logger.info("=" * 60)
    logger.info(f"Accuracy:          {acc*100:.2f}%")
    logger.info(f"Precision (macro): {precision_macro*100:.2f}%")
    logger.info(f"Recall (macro):    {recall_macro*100:.2f}%")
    logger.info(f"F1 (macro):        {f1_macro*100:.2f}%")
    logger.info(f"F1 (weighted):     {f1_weighted*100:.2f}%")
    logger.info(f"AUC-ROC (macro):   {auc_macro:.4f}")
    logger.info(f"AUC-ROC (weighted):{auc_weighted:.4f}")
    logger.info(f"\n分类报告:\n{cls_report}")
    logger.info(f"混淆矩阵:\n{cm}")

    # 保存指标 JSON
    metrics = {
        'accuracy': float(acc),
        'precision_macro': float(precision_macro),
        'recall_macro': float(recall_macro),
        'f1_macro': float(f1_macro),
        'f1_weighted': float(f1_weighted),
        'auc_roc_macro': float(auc_macro),
        'auc_roc_weighted': float(auc_weighted),
        'confusion_matrix': cm.tolist(),
        'classification_report': cls_report,
        'per_class': {},
        'real_score_mean': float(np.mean(real_scores)),
        'real_score_std': float(np.std(real_scores)),
        'model_epoch': train_epoch,
        'model_val_accuracy': float(train_acc),
        'test_samples': len(y_test),
        'timestamp': datetime.now().isoformat(),
    }

    # 每类指标
    for cls_id, cls_name in enumerate(class_names):
        cls_mask = (y_test == cls_id)
        if cls_mask.sum() > 0:
            cls_pred = y_pred[cls_mask]
            cls_acc = (cls_pred == cls_id).mean()
            cls_count = int(cls_mask.sum())
            metrics['per_class'][cls_name] = {
                'accuracy': float(cls_acc),
                'count': cls_count,
            }

    with open(os.path.join(output_dir, 'metrics.json'), 'w', encoding='utf-8') as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)

    # ===== 生成图表 =====
    generate_plots(y_test, y_pred, y_scores, y_test_bin, real_scores,
                   class_names, num_classes, cm, metrics, output_dir)

    # ===== 生成 HTML 报告 =====
    generate_html_report(metrics, class_names, output_dir)

    logger.info(f"\n所有评估文件已保存到: {output_dir}")
    return metrics


def generate_plots(y_test, y_pred, y_scores, y_test_bin, real_scores,
                   class_names, num_classes, cm, metrics, output_dir):
    """生成评估图表"""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.font_manager as fm
        plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans']
        plt.rcParams['axes.unicode_minus'] = False
    except ImportError:
        logger.warning("matplotlib 未安装，跳过图表")
        return

    # 1. 混淆矩阵热力图
    fig, ax = plt.subplots(figsize=(10, 8))
    im = ax.imshow(cm, interpolation='nearest', cmap='Blues')
    ax.figure.colorbar(im, ax=ax)
    ax.set(xticks=np.arange(num_classes), yticks=np.arange(num_classes),
           xticklabels=class_names, yticklabels=class_names,
           ylabel='True Label', xlabel='Predicted Label',
           title='Confusion Matrix')
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    # 在格子中显示数字
    thresh = cm.max() / 2.
    for i in range(num_classes):
        for j in range(num_classes):
            ax.text(j, i, format(cm[i, j], 'd'),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black", fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'), dpi=150)
    plt.close()

    # 2. ROC 曲线
    fig, ax = plt.subplots(figsize=(10, 8))
    for i, name in enumerate(class_names):
        if y_test_bin[:, i].sum() > 0:
            fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_scores[:, i])
            auc_val = roc_auc_score(y_test_bin[:, i], y_scores[:, i])
            ax.plot(fpr, tpr, label=f'{name} (AUC={auc_val:.3f})')
    ax.plot([0, 1], [0, 1], 'k--', alpha=0.3)
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    ax.set_title('ROC Curves (One-vs-Rest)')
    ax.legend(loc='lower right', fontsize=8)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'roc_curves.png'), dpi=150)
    plt.close()

    # 3. 指标柱状图
    fig, ax = plt.subplots(figsize=(8, 5))
    metric_names = ['Accuracy', 'Precision', 'Recall', 'F1 (macro)', 'AUC-ROC']
    metric_vals = [metrics['accuracy'], metrics['precision_macro'],
                   metrics['recall_macro'], metrics['f1_macro'], metrics['auc_roc_macro']]
    colors = ['#3498db' if v >= 0.9 else '#e74c3c' if v < 0.8 else '#f39c12' for v in metric_vals]
    bars = ax.bar(metric_names, metric_vals, color=colors)
    for bar, val in zip(bars, metric_vals):
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.01,
                f'{val:.3f}', ha='center', va='bottom', fontsize=10)
    ax.set_ylim([0, 1.1])
    ax.set_title('Overall Performance Metrics')
    ax.grid(True, alpha=0.3, axis='y')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'metrics_bar.png'), dpi=150)
    plt.close()

    # 4. Real Score 分布
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(real_scores, bins=50, alpha=0.7, color='steelblue', edgecolor='white')
    ax.set_xlabel('Discriminator Real Score')
    ax.set_ylabel('Count')
    ax.set_title('Real Score Distribution on Test Set')
    ax.axvline(x=0.5, color='red', linestyle='--', alpha=0.5, label='Threshold=0.5')
    ax.legend()
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'real_score_dist.png'), dpi=150)
    plt.close()

    logger.info("评估图表已生成")


def generate_html_report(metrics, class_names, output_dir):
    """生成 HTML 评估报告"""
    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>NIDS TransEC-GAN 评估报告</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; color: #333; }}
.container {{ max-width: 1100px; margin: auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); }}
h1 {{ color: #1a237e; border-bottom: 3px solid #3f51b5; padding-bottom: 12px; }}
h2 {{ color: #283593; margin-top: 30px; }}
table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
th, td {{ padding: 10px 14px; text-align: center; border: 1px solid #e0e0e0; }}
th {{ background: #3f51b5; color: white; }}
tr:nth-child(even) {{ background: #f5f5f5; }}
.metric-card {{ display: inline-block; text-align: center; padding: 16px 24px; margin: 8px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; min-width: 120px; }}
.metric-card .value {{ font-size: 28px; font-weight: bold; }}
.metric-card .label {{ font-size: 12px; opacity: 0.9; }}
.good {{ color: #2e7d32; font-weight: bold; }}
.warn {{ color: #f57f17; font-weight: bold; }}
.bad {{ color: #c62828; font-weight: bold; }}
img {{ max-width: 100%; margin: 16px 0; border-radius: 8px; }}
.timestamp {{ color: #999; font-size: 13px; }}
pre {{ background: #f8f8f8; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
<h1>NIDS TransEC-GAN 评估报告</h1>
<p class="timestamp">生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 御链天鉴开发团队</p>
<p>模型: TransEC-GAN (Transformer Encoder + GAN) | 数据集: CICIDS2017 | 测试样本: {metrics['test_samples']:,}</p>

<h2>总体指标</h2>
<div>
"""

    for label, key in [('Accuracy', 'accuracy'), ('Precision', 'precision_macro'),
                       ('Recall', 'recall_macro'), ('F1 (macro)', 'f1_macro'),
                       ('AUC-ROC', 'auc_roc_macro')]:
        val = metrics[key]
        html += f'<div class="metric-card"><div class="value">{val:.3f}</div><div class="label">{label}</div></div>\n'

    html += """</div>

<h2>指标柱状图</h2>
<img src="metrics_bar.png" alt="Metrics Bar Chart">

<h2>混淆矩阵</h2>
<img src="confusion_matrix.png" alt="Confusion Matrix">

<h2>ROC 曲线</h2>
<img src="roc_curves.png" alt="ROC Curves">

<h2>Real Score 分布</h2>
<img src="real_score_dist.png" alt="Real Score Distribution">

<h2>分类报告</h2>
<pre>"""
    html += metrics['classification_report']
    html += """</pre>

<h2>每类准确率</h2>
<table>
<tr><th>类别</th><th>准确率</th><th>样本数</th></tr>
"""
    for cls_name, cls_data in metrics.get('per_class', {}).items():
        acc = cls_data['accuracy']
        cls_class = 'good' if acc >= 0.9 else ('warn' if acc >= 0.75 else 'bad')
        html += f'<tr><td>{cls_name}</td><td class="{cls_class}">{acc*100:.2f}%</td><td>{cls_data["count"]:,}</td></tr>\n'

    html += """</table>
</div>
</body>
</html>"""

    report_path = os.path.join(output_dir, 'eval_report.html')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html)
    logger.info(f"HTML 评估报告已生成: {report_path}")


def main():
    parser = argparse.ArgumentParser(description="NIDS 模型评估")
    parser.add_argument("--data_dir", type=str, required=True,
                        help="预处理数据目录")
    parser.add_argument("--model_path", type=str, required=True,
                        help="模型 .pth 文件路径")
    parser.add_argument("--output_dir", type=str, default="eval_reports",
                        help="评估报告输出目录")
    parser.add_argument("--device", type=str, default="cuda",
                        help="设备 (cuda/cpu)")
    args = parser.parse_args()

    device = args.device
    if device == 'cuda' and not torch.cuda.is_available():
        logger.warning("CUDA 不可用，回退到 CPU")
        device = 'cpu'

    evaluate_on_test(args.model_path, args.data_dir, args.output_dir, device)


if __name__ == '__main__':
    main()
