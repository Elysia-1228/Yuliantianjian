# -*- coding: utf-8 -*-
"""
NIDS 数据预处理脚本
==================

将 CICIDS2017 CSV 数据集转换为 TransEC-GAN 训练所需的序列格式。

数据流：
  CICIDS2017 CSV(78列) → 清洗 → 标签合并(8类) → StandardScaler → PCA(自动) → 序列窗口(32步) → npz

运行方式（在5880服务器上）：
  cd /home/test/ids_project
  python nids_data_preprocess.py --data_dir data --output_dir preprocessed

依赖：
  pip install numpy pandas scikit-learn joblib tqdm -i https://pypi.tuna.tsinghua.edu.cn/simple

御链天鉴开发团队
"""

import os
import sys
import json
import time
import argparse
import logging
import warnings
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split
from collections import Counter

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# ============================================================
# 配置
# ============================================================

# CICIDS2017 标签合并映射（15类 → 8类）
LABEL_MAP = {
    'BENIGN': 'Benign',
    'FTP-Patator': 'BruteForce',
    'SSH-Patator': 'BruteForce',
    'DoS Hulk': 'DoS',
    'DoS GoldenEye': 'DoS',
    'DoS slowloris': 'DoS',
    'DoS Slowhttptest': 'DoS',
    'Heartbleed': 'DoS',
    'Web Attack \x96 Brute Force': 'WebAttack',
    'Web Attack \x96 XSS': 'WebAttack',
    'Web Attack \x96 Sql Injection': 'WebAttack',
    'Web Attack – Brute Force': 'WebAttack',
    'Web Attack – XSS': 'WebAttack',
    'Web Attack – Sql Injection': 'WebAttack',
    'Infiltration': 'Infiltration',
    'Bot': 'Bot',
    'PortScan': 'PortScan',
    'DDoS': 'DDoS',
}

# 合并后的类别名称（有序）
CLASS_NAMES = ['Benign', 'BruteForce', 'DoS', 'WebAttack', 'Infiltration', 'Bot', 'PortScan', 'DDoS']
NUM_CLASSES = len(CLASS_NAMES)

# 需要从 CSV 中排除的非特征列
NON_FEATURE_COLS = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label',
                    'Src IP', 'Dst IP', 'Flow ID.1']

# TransEC-GAN 序列参数
SEQ_LEN = 32
PCA_VARIANCE_RATIO = 0.95  # PCA 保留 95% 方差


# ============================================================
# Step 1: 加载 CSV
# ============================================================

def load_csv_files(data_dir: str) -> pd.DataFrame:
    """加载所有 CICIDS2017 CSV 文件并合并"""
    csv_files = sorted([f for f in os.listdir(data_dir) if f.endswith(('.csv', '.CSV'))])
    
    if not csv_files:
        # 尝试查找 XLS 格式（实际是 CSV）
        csv_files = sorted([f for f in os.listdir(data_dir) if 'WorkingHours' in f or 'workingHours' in f])
    
    if not csv_files:
        raise FileNotFoundError(f"在 {data_dir} 中未找到 CSV 文件")
    
    logger.info(f"找到 {len(csv_files)} 个数据文件:")
    for f in csv_files:
        size_mb = os.path.getsize(os.path.join(data_dir, f)) / 1024 / 1024
        logger.info(f"  {f} ({size_mb:.1f} MB)")
    
    dfs = []
    for f in csv_files:
        path = os.path.join(data_dir, f)
        logger.info(f"加载 {f}...")
        try:
            df = pd.read_csv(path, encoding='utf-8', low_memory=False)
        except UnicodeDecodeError:
            df = pd.read_csv(path, encoding='latin-1', low_memory=False)
        
        # 清理列名（去除前后空格）
        df.columns = df.columns.str.strip()
        
        logger.info(f"  {len(df)} 行, {len(df.columns)} 列")
        dfs.append(df)
    
    combined = pd.concat(dfs, ignore_index=True)
    logger.info(f"合并完成: {len(combined)} 行 × {len(combined.columns)} 列")
    return combined


# ============================================================
# Step 2: 数据清洗
# ============================================================

def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """清洗数据：处理缺失值、无穷值、重复行"""
    original_len = len(df)
    
    # 找到 Label 列（可能叫 Label 或 label）
    label_col = None
    for col in df.columns:
        if col.strip().lower() == 'label':
            label_col = col
            break
    if label_col is None:
        raise ValueError(f"找不到 Label 列，可用列: {list(df.columns[:10])}...")
    
    # 统一 Label 列名
    if label_col != 'Label':
        df = df.rename(columns={label_col: 'Label'})
    
    # 删除 Label 为空的行
    df = df.dropna(subset=['Label'])
    
    # 将数值列转为 float
    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLS]
    for col in feature_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    
    # 替换 inf → NaN
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # 删除含 NaN 的行
    nan_count = df[feature_cols].isna().any(axis=1).sum()
    df = df.dropna(subset=feature_cols)
    
    # 删除完全重复的行
    dup_count = df.duplicated().sum()
    df = df.drop_duplicates()
    
    logger.info(f"数据清洗: {original_len} → {len(df)} 行 "
                f"(删除 NaN={nan_count}, 重复={dup_count})")
    
    return df


# ============================================================
# Step 3: 标签合并
# ============================================================

def merge_labels(df: pd.DataFrame) -> pd.DataFrame:
    """将 CICIDS2017 的 15 种标签合并为 8 类"""
    # 清理 Label 列空格
    df['Label'] = df['Label'].str.strip()
    
    # 打印原始标签分布
    logger.info("原始标签分布:")
    for label, count in df['Label'].value_counts().items():
        logger.info(f"  {label}: {count:,}")
    
    # 应用映射
    df['MergedLabel'] = df['Label'].map(LABEL_MAP)
    
    # 检查未映射的标签
    unmapped = df[df['MergedLabel'].isna()]['Label'].unique()
    if len(unmapped) > 0:
        logger.warning(f"未映射的标签: {unmapped}，将归类为 Benign")
        df.loc[df['MergedLabel'].isna(), 'MergedLabel'] = 'Benign'
    
    # 编码为数字
    label_to_id = {name: i for i, name in enumerate(CLASS_NAMES)}
    df['LabelID'] = df['MergedLabel'].map(label_to_id)
    
    # 打印合并后分布
    logger.info(f"\n合并后标签分布 ({NUM_CLASSES} 类):")
    for name in CLASS_NAMES:
        count = (df['MergedLabel'] == name).sum()
        logger.info(f"  [{label_to_id[name]}] {name}: {count:,}")
    
    return df


# ============================================================
# Step 4: 特征提取
# ============================================================

def extract_features(df: pd.DataFrame) -> tuple:
    """提取特征矩阵和标签"""
    # 确定特征列（排除非特征列 + Label 相关列）
    exclude_cols = set(NON_FEATURE_COLS + ['MergedLabel', 'LabelID'])
    feature_cols = [c for c in df.columns if c not in exclude_cols]
    
    logger.info(f"使用 {len(feature_cols)} 维特征:")
    for i, col in enumerate(feature_cols):
        if i < 10 or i >= len(feature_cols) - 3:
            logger.info(f"  [{i:2d}] {col}")
        elif i == 10:
            logger.info(f"  ... (省略 {len(feature_cols) - 13} 列)")
    
    X = df[feature_cols].values.astype(np.float32)
    y = df['LabelID'].values.astype(np.int64)
    
    logger.info(f"特征矩阵: {X.shape}, 标签: {y.shape}")
    return X, y, feature_cols


# ============================================================
# Step 5: 数据划分 + 预处理
# ============================================================

def preprocess_and_split(X: np.ndarray, y: np.ndarray) -> dict:
    """数据划分、标准化、PCA"""
    
    # 分层划分：70% train / 15% val / 15% test
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )
    
    logger.info(f"数据划分:")
    logger.info(f"  训练集: {X_train.shape[0]:,} ({X_train.shape[0]/len(X)*100:.1f}%)")
    logger.info(f"  验证集: {X_val.shape[0]:,} ({X_val.shape[0]/len(X)*100:.1f}%)")
    logger.info(f"  测试集: {X_test.shape[0]:,} ({X_test.shape[0]/len(X)*100:.1f}%)")
    
    for split_name, split_y in [('训练', y_train), ('验证', y_val), ('测试', y_test)]:
        counts = Counter(split_y)
        dist = ', '.join([f"{CLASS_NAMES[k]}={v}" for k, v in sorted(counts.items())])
        logger.info(f"  {split_name}集类别: {dist}")
    
    # StandardScaler（仅在训练集上 fit）
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)
    
    logger.info(f"StandardScaler: mean={X_train_scaled.mean():.6f}, std={X_train_scaled.std():.6f}")
    
    # PCA（自动选择保留 95% 方差的成分数）
    pca_full = PCA(n_components=min(X_train_scaled.shape[1], X_train_scaled.shape[0]))
    pca_full.fit(X_train_scaled)
    
    cumvar = np.cumsum(pca_full.explained_variance_ratio_)
    n_components = int(np.searchsorted(cumvar, PCA_VARIANCE_RATIO) + 1)
    n_components = max(n_components, 12)  # 最少 12 维
    n_components = min(n_components, X_train_scaled.shape[1])  # 不超过原始维度
    
    logger.info(f"PCA 方差解释率: {cumvar[n_components-1]*100:.1f}% ({n_components} 维)")
    logger.info(f"  前 5 维累计: {cumvar[4]*100:.1f}%")
    logger.info(f"  前 10 维累计: {cumvar[9]*100:.1f}%" if len(cumvar) > 9 else "")
    logger.info(f"  前 20 维累计: {cumvar[19]*100:.1f}%" if len(cumvar) > 19 else "")
    
    pca = PCA(n_components=n_components)
    X_train_pca = pca.fit_transform(X_train_scaled)
    X_val_pca = pca.transform(X_val_scaled)
    X_test_pca = pca.transform(X_test_scaled)
    
    logger.info(f"PCA 输出维度: {X_train_pca.shape[1]} (PCA_DIM={n_components})")
    
    return {
        'X_train': X_train_pca, 'y_train': y_train,
        'X_val': X_val_pca, 'y_val': y_val,
        'X_test': X_test_pca, 'y_test': y_test,
        'scaler': scaler, 'pca': pca,
        'n_components': n_components,
    }


# ============================================================
# Step 6: 序列化（滑动窗口）
# ============================================================

def create_sequences(X: np.ndarray, y: np.ndarray, seq_len: int = 32,
                     stride: int = 16) -> tuple:
    """
    将样本按类别分组，然后用滑动窗口生成序列。
    
    对于同一类别的连续样本，用窗口 (seq_len, pca_dim) 切割。
    不足 seq_len 的用零填充。
    """
    pca_dim = X.shape[1]
    sequences = []
    seq_labels = []
    
    # 按类别分组
    for cls_id in range(NUM_CLASSES):
        cls_mask = (y == cls_id)
        cls_X = X[cls_mask]
        
        if len(cls_X) == 0:
            continue
        
        # 滑动窗口
        n_seqs = 0
        for start in range(0, len(cls_X), stride):
            end = start + seq_len
            if end <= len(cls_X):
                seq = cls_X[start:end]
            else:
                # 末尾不足，用零填充
                seq = np.zeros((seq_len, pca_dim), dtype=np.float32)
                remaining = cls_X[start:]
                seq[:len(remaining)] = remaining
            
            sequences.append(seq)
            seq_labels.append(cls_id)
            n_seqs += 1
        
        logger.info(f"  类别 [{cls_id}] {CLASS_NAMES[cls_id]}: "
                    f"{len(cls_X):,} 样本 → {n_seqs:,} 序列")
    
    X_seq = np.array(sequences, dtype=np.float32)
    y_seq = np.array(seq_labels, dtype=np.int64)
    
    # 打乱顺序
    perm = np.random.RandomState(42).permutation(len(X_seq))
    X_seq = X_seq[perm]
    y_seq = y_seq[perm]
    
    logger.info(f"序列化完成: {X_seq.shape} (N={len(X_seq)}, T={seq_len}, D={pca_dim})")
    return X_seq, y_seq


# ============================================================
# 主流程
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="NIDS CICIDS2017 数据预处理")
    parser.add_argument("--data_dir", type=str, default="data",
                        help="CICIDS2017 CSV 文件所在目录")
    parser.add_argument("--output_dir", type=str, default="preprocessed",
                        help="预处理输出目录")
    parser.add_argument("--seq_len", type=int, default=SEQ_LEN,
                        help=f"序列窗口长度 (默认: {SEQ_LEN})")
    parser.add_argument("--stride", type=int, default=16,
                        help="滑动窗口步长 (默认: 16)")
    args = parser.parse_args()
    
    os.makedirs(args.output_dir, exist_ok=True)
    t_start = time.time()
    
    logger.info("=" * 60)
    logger.info("NIDS 数据预处理 - CICIDS2017 → TransEC-GAN")
    logger.info("=" * 60)
    
    # Step 1: 加载
    df = load_csv_files(args.data_dir)
    
    # Step 2: 清洗
    df = clean_data(df)
    
    # Step 3: 标签合并
    df = merge_labels(df)
    
    # Step 4: 特征提取
    X, y, feature_cols = extract_features(df)
    del df  # 释放内存
    
    # Step 5: 划分 + 标准化 + PCA
    result = preprocess_and_split(X, y)
    del X, y
    
    pca_dim = result['n_components']
    
    # Step 6: 序列化
    logger.info("\n序列化训练集...")
    X_train_seq, y_train_seq = create_sequences(
        result['X_train'], result['y_train'], args.seq_len, args.stride)
    
    logger.info("\n序列化验证集...")
    X_val_seq, y_val_seq = create_sequences(
        result['X_val'], result['y_val'], args.seq_len, args.stride)
    
    logger.info("\n序列化测试集...")
    X_test_seq, y_test_seq = create_sequences(
        result['X_test'], result['y_test'], args.seq_len, args.stride)
    
    # 保存
    logger.info("\n保存文件...")
    
    np.savez_compressed(os.path.join(args.output_dir, 'train_sequences.npz'),
                        X=X_train_seq, y=y_train_seq)
    np.savez_compressed(os.path.join(args.output_dir, 'val_sequences.npz'),
                        X=X_val_seq, y=y_val_seq)
    np.savez_compressed(os.path.join(args.output_dir, 'test_sequences.npz'),
                        X=X_test_seq, y=y_test_seq)
    
    joblib.dump(result['scaler'], os.path.join(args.output_dir, 'scaler.pkl'))
    joblib.dump(result['pca'], os.path.join(args.output_dir, 'pca.pkl'))
    np.save(os.path.join(args.output_dir, 'label_encoder.npy'), np.array(CLASS_NAMES))
    
    with open(os.path.join(args.output_dir, 'feature_names.json'), 'w', encoding='utf-8') as f:
        json.dump(feature_cols, f, ensure_ascii=False, indent=2)
    
    # 保存统计信息和关键参数
    stats = {
        'dataset': 'CICIDS2017',
        'num_classes': NUM_CLASSES,
        'class_names': CLASS_NAMES,
        'feature_dim': len(feature_cols),
        'pca_dim': pca_dim,
        'seq_len': args.seq_len,
        'stride': args.stride,
        'pca_variance_explained': float(np.sum(result['pca'].explained_variance_ratio_)),
        'train_sequences': len(X_train_seq),
        'val_sequences': len(X_val_seq),
        'test_sequences': len(X_test_seq),
        'train_class_dist': dict(Counter(y_train_seq.tolist())),
        'val_class_dist': dict(Counter(y_val_seq.tolist())),
        'test_class_dist': dict(Counter(y_test_seq.tolist())),
        'scaler_mean_sample': result['scaler'].mean_[:5].tolist(),
        'processing_time_seconds': time.time() - t_start,
    }
    
    with open(os.path.join(args.output_dir, 'data_stats.json'), 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    
    elapsed = time.time() - t_start
    
    logger.info("\n" + "=" * 60)
    logger.info("数据预处理完成!")
    logger.info("=" * 60)
    logger.info(f"输出目录: {args.output_dir}")
    logger.info(f"特征维度: {len(feature_cols)} → PCA {pca_dim}")
    logger.info(f"序列形状: ({args.seq_len}, {pca_dim})")
    logger.info(f"NUM_CLASSES: {NUM_CLASSES}")
    logger.info(f"训练序列: {len(X_train_seq):,}")
    logger.info(f"验证序列: {len(X_val_seq):,}")
    logger.info(f"测试序列: {len(X_test_seq):,}")
    logger.info(f"总耗时: {elapsed:.1f}s")
    logger.info("")
    logger.info("下一步: 运行训练脚本")
    logger.info(f"  python nids_train_transec_gan.py --data_dir {args.output_dir} "
                f"--output_dir transec_gan_model --device cuda")


if __name__ == '__main__':
    main()
