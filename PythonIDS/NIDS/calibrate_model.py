#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NIDS 模型环境校准脚本
=====================

采集真实网络正常流量，微调 TransEC-GAN Discriminator 的分类头，
使模型适应当前网络环境，正确识别正常流量。

校准流程：
  1. 抓包采集正常流量 → 提取78维特征 → PCA降至25维
  2. 冻结 Transformer backbone，微调 head + class_fc
  3. 保存校准后的模型

用法：
  python calibrate_model.py --duration 120    # 采集2分钟正常流量并校准
  python calibrate_model.py --duration 300    # 采集5分钟（推荐）

⚠️ 校准期间请保持正常上网（浏览网页、看视频等），不要运行攻击脚本！

御链天鉴开发团队
"""

import os
import sys
import time
import copy
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from collections import deque
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP

from ids_common import (
    logger, COLORS, DEVICE, SEQ_LEN, PCA_DIM, NUM_CLASSES,
    flows, get_flow_key, extract_features, load_model,
    MODEL_DIR
)


def collect_normal_traffic(duration=120):
    """采集正常流量特征"""
    from ids_common import get_wlan_interface
    iface = get_wlan_interface()
    logger.info(f"采集接口: {iface}")
    logger.info(f"采集时长: {duration}s")
    logger.info(f"{COLORS['yellow']}⚠️ 请保持正常上网，不要运行攻击脚本!{COLORS['reset']}")

    collected_features = []
    packet_count = [0]

    def _callback(packet):
        packet_count[0] += 1
        result = extract_features(packet)
        if result is None:
            return
        flow_key, features = result
        collected_features.append(features.copy())

    logger.info(f"{COLORS['green']}🔄 开始采集正常流量...{COLORS['reset']}")
    start = time.time()
    try:
        sniff(iface=iface, prn=_callback, timeout=duration, store=False)
    except KeyboardInterrupt:
        pass

    elapsed = time.time() - start
    logger.info(f"采集完成: {elapsed:.0f}s, 包={packet_count[0]:,}, 特征样本={len(collected_features):,}")
    return np.array(collected_features) if collected_features else None


def calibrate(discriminator, generator, scaler, pca, features, epochs=10, lr=1e-3):
    """
    微调 Discriminator 分类头：真实正常流量(Benign) + Generator合成攻击(防遗忘)

    策略：
    - 冻结 transformer backbone（保留已学习的特征表示）
    - 微调 head + class_fc（调整分类决策边界）
    - 训练数据：真实正常流量(Benign) + Generator生成的合成攻击样本（7个攻击类别）
    - 防止灾难性遗忘：合成攻击样本保持模型对攻击类别的检测能力
    """
    logger.info(f"\n{'='*50}")
    logger.info(f"开始模型校准 (真实Benign + 合成攻击 混合训练)")
    logger.info(f"{'='*50}")

    # 特征预处理（限制样本量，CPU友好）
    MAX_BENIGN = 3000
    if len(features) > MAX_BENIGN:
        indices = np.random.choice(len(features), MAX_BENIGN, replace=False)
        features = features[indices]
    features_scaled = scaler.transform(features)
    features_pca = pca.transform(features_scaled).astype(np.float32)
    n_benign = len(features_pca)
    logger.info(f"真实 Benign 样本: {n_benign} 个")

    # 用 Generator 生成合成攻击样本（每个攻击类别生成同等数量）
    n_attack_per_class = max(200, n_benign // 7)  # 每类攻击生成的样本数
    logger.info(f"生成合成攻击样本: 7类 × {n_attack_per_class} = {7 * n_attack_per_class} 个")

    generator.eval()
    attack_pca_list = []
    attack_labels = []

    with torch.no_grad():
        for cls_id in range(1, NUM_CLASSES):  # 1-7 为攻击类别
            for batch_start in range(0, n_attack_per_class, 128):
                batch_size = min(128, n_attack_per_class - batch_start)
                z = torch.randn(batch_size, 128, device=DEVICE)
                labels_onehot = torch.zeros(batch_size, NUM_CLASSES, device=DEVICE)
                labels_onehot[:, cls_id] = 1.0
                fake_seq = generator(z, labels_onehot)  # (batch, seq_len, pca_dim)
                # 取序列均值作为特征
                fake_features = fake_seq[:, 0, :].cpu().numpy()  # 取第一帧
                attack_pca_list.append(fake_features)
                attack_labels.extend([cls_id] * batch_size)

    attack_pca = np.vstack(attack_pca_list).astype(np.float32)
    attack_labels = np.array(attack_labels, dtype=np.int64)
    logger.info(f"合成攻击样本: {len(attack_pca)} 个, 类别分布={dict(zip(*np.unique(attack_labels, return_counts=True)))}")

    # 合并：真实Benign + 合成攻击
    X_benign = np.array([np.tile(f, (SEQ_LEN, 1)) for f in features_pca])
    y_benign = np.zeros(n_benign, dtype=np.int64)

    X_attack = np.array([np.tile(f, (SEQ_LEN, 1)) for f in attack_pca])
    y_attack = attack_labels

    X_train = np.concatenate([X_benign, X_attack], axis=0)
    y_train = np.concatenate([y_benign, y_attack], axis=0)

    # 打乱
    indices = np.random.permutation(len(X_train))
    X_train = X_train[indices]
    y_train = y_train[indices]

    logger.info(f"总训练样本: {len(X_train)} (Benign={n_benign}, Attack={len(attack_pca)})")

    # 转 Tensor
    X_tensor = torch.FloatTensor(X_train).to(DEVICE)
    y_tensor = torch.LongTensor(y_train).to(DEVICE)

    # 冻结 transformer backbone
    for param in discriminator.transformer.parameters():
        param.requires_grad = False

    # 只微调 head + class_fc + real_fc
    trainable_params = (
        list(discriminator.head.parameters()) +
        list(discriminator.class_fc.parameters()) +
        list(discriminator.real_fc.parameters())
    )
    optimizer = optim.Adam(trainable_params, lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-5)
    criterion = nn.CrossEntropyLoss()

    logger.info(f"可训练参数: {sum(p.numel() for p in trainable_params):,}")
    logger.info(f"Epochs: {epochs}, LR: {lr}")

    # 微调训练
    batch_size = min(256, len(X_tensor))
    best_acc = 0.0
    best_state = None

    for epoch in range(epochs):
        discriminator.train()
        total_loss = 0.0
        correct = 0
        total = 0

        for i in range(0, len(X_tensor), batch_size):
            batch_x = X_tensor[i:i+batch_size]
            batch_y = y_tensor[i:i+batch_size]

            optimizer.zero_grad()
            _, class_logits = discriminator(batch_x)
            loss = criterion(class_logits, batch_y)
            loss.backward()
            optimizer.step()

            total_loss += loss.item() * len(batch_x)
            preds = class_logits.argmax(dim=1)
            correct += (preds == batch_y).sum().item()
            total += len(batch_x)

        scheduler.step()
        acc = correct / total
        avg_loss = total_loss / total

        if acc > best_acc:
            best_acc = acc
            best_state = copy.deepcopy(discriminator.state_dict())

        logger.info(f"  Epoch {epoch+1:3d}/{epochs} | Loss={avg_loss:.4f} | Acc={acc:.2%}")

        if acc >= 0.98:
            logger.info(f"  ★ 达到98%准确率，提前停止")
            break

    # 恢复最佳状态
    if best_state:
        discriminator.load_state_dict(best_state)
    logger.info(f"校准完成! 最佳准确率: {best_acc:.2%} (Benign+Attack 混合)")

    # 解冻所有参数（推理时需要）
    for param in discriminator.parameters():
        param.requires_grad = False

    discriminator.eval()
    return discriminator


def save_calibrated_model(discriminator, generator):
    """保存校准后的模型"""
    save_path = os.path.join(MODEL_DIR, "transec_gan_calibrated.pth")
    checkpoint = {
        "discriminator_state_dict": discriminator.state_dict(),
        "generator_state_dict": generator.state_dict() if generator else None,
        "calibrated": True,
        "calibration_time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    torch.save(checkpoint, save_path)
    logger.info(f"校准模型已保存: {save_path}")
    return save_path


def verify_calibration(discriminator, scaler, pca, features):
    """验证校准效果"""
    logger.info(f"\n{'='*50}")
    logger.info(f"验证校准效果")
    logger.info(f"{'='*50}")

    # 随机取50个样本验证
    n = min(50, len(features))
    indices = np.random.choice(len(features), n, replace=False)
    sample_features = features[indices]

    features_scaled = scaler.transform(sample_features)
    features_pca = pca.transform(features_scaled).astype(np.float32)

    benign_count = 0
    attack_count = 0

    discriminator.eval()
    with torch.no_grad():
        for f in features_pca:
            x = torch.FloatTensor(np.tile(f, (SEQ_LEN, 1))).unsqueeze(0).to(DEVICE)
            real_score, class_logits = discriminator(x)
            real_prob = torch.sigmoid(real_score).item()
            pred_class = int(class_logits.argmax(dim=1).item())
            confidence = torch.softmax(class_logits, dim=1).max().item()

            if pred_class == 0:
                benign_count += 1
            else:
                attack_count += 1

    benign_rate = benign_count / n
    logger.info(f"正常流量识别率: {benign_rate:.1%} ({benign_count}/{n})")
    if benign_rate >= 0.8:
        logger.info(f"{COLORS['green']}✅ 校准成功! 正常流量误报率低{COLORS['reset']}")
    else:
        logger.info(f"{COLORS['yellow']}⚠️ 校准效果一般，建议增加采集时间重新校准{COLORS['reset']}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="NIDS 模型环境校准 - 御链天鉴")
    parser.add_argument("--duration", "-d", type=int, default=120,
                        help="正常流量采集时长(秒), 默认120s, 推荐300s")
    parser.add_argument("--epochs", "-e", type=int, default=10, help="微调轮数(通常1-3轮即可收敛)")
    parser.add_argument("--lr", type=float, default=1e-3, help="学习率")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("NIDS 模型环境校准 - 御链天鉴")
    logger.info("=" * 60)

    # 加载原始模型
    discriminator, generator, scaler, pca, label_classes = load_model()

    # 采集正常流量
    features = collect_normal_traffic(duration=args.duration)
    if features is None or len(features) < 50:
        logger.error(f"采集样本不足(需要至少50个, 当前{len(features) if features is not None else 0})")
        logger.error("请延长采集时间或在采集期间多浏览网页")
        return

    # 校准（真实Benign + Generator合成攻击 混合训练）
    discriminator = calibrate(discriminator, generator, scaler, pca, features,
                              epochs=args.epochs, lr=args.lr)

    # 验证
    verify_calibration(discriminator, scaler, pca, features)

    # 保存
    save_calibrated_model(discriminator, generator)

    logger.info(f"\n{'='*60}")
    logger.info(f"校准完成! 请使用以下命令启动检测:")
    logger.info(f"  python realtime_detection.py")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    main()
