# -*- coding: utf-8 -*-
"""
TransEC-GAN 训练脚本
====================

在 CICIDS2017 预处理数据上训练 TransEC-GAN 模型。

数据输入：nids_data_preprocess.py 的输出（序列 npz + scaler/pca）
模型输出：best_model_4x5880_max.pth

运行方式（在5880服务器上）：
  cd /home/test/ids_project
  python nids_train_transec_gan.py \
    --data_dir preprocessed \
    --output_dir transec_gan_model \
    --epochs 200 --batch_size 8192 --device cuda --num_gpus 4

依赖：
  pip install numpy torch tqdm matplotlib -i https://pypi.tuna.tsinghua.edu.cn/simple

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
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader
from collections import Counter
from datetime import datetime

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


# ============================================================
# 模型定义（TransEC-GAN 架构）
# ============================================================

class TransformerEncoder(nn.Module):
    """Transformer 编码器（大容量版）"""
    def __init__(self, input_dim, d_model=256, nhead=8, num_layers=6, seq_len=32, dropout=0.1):
        super().__init__()
        self.linear = nn.Linear(input_dim, d_model)
        self.pos_encoder = nn.Embedding(seq_len, d_model)
        self.input_norm = nn.LayerNorm(d_model)
        self.input_dropout = nn.Dropout(dropout)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=1024,
            activation="gelu", batch_first=True, norm_first=True,
            dropout=dropout
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.seq_len = seq_len

    def forward(self, x):
        batch_size, seq_len = x.shape[0], x.shape[1]
        x = self.linear(x)
        pos = torch.arange(seq_len, device=x.device).unsqueeze(0).expand(batch_size, -1)
        x = x + self.pos_encoder(pos)
        x = self.input_dropout(self.input_norm(x))
        return self.transformer(x).mean(dim=1)


class Generator(nn.Module):
    """生成器：噪声 + 类别条件 → 合成序列（大容量版）"""
    def __init__(self, latent_dim, num_classes, pca_dim, seq_len=32, dropout=0.1):
        super().__init__()
        self.seq_len = seq_len
        self.noise_linear = nn.Sequential(
            nn.Linear(latent_dim + num_classes, 256),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(256, 256)
        )
        self.transformer = TransformerEncoder(input_dim=256, d_model=256, seq_len=seq_len, dropout=dropout)
        self.fc = nn.Sequential(
            nn.Linear(256, 512),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(512, pca_dim)
        )

    def forward(self, z, labels_onehot):
        x = torch.cat([z, labels_onehot], dim=1)
        x = self.noise_linear(x).unsqueeze(1).expand(-1, self.seq_len, -1)
        x = self.transformer(x)
        x = self.fc(x).unsqueeze(1).expand(-1, self.seq_len, -1)
        return x


class Discriminator(nn.Module):
    """判别器：序列 → 真/假分数 + 分类（大容量版）"""
    def __init__(self, pca_dim, num_classes, seq_len=32, dropout=0.1):
        super().__init__()
        self.transformer = TransformerEncoder(input_dim=pca_dim, d_model=256, seq_len=seq_len, dropout=dropout)
        self.head = nn.Sequential(
            nn.Linear(256, 512),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        self.real_fc = nn.Linear(512, 1)
        self.class_fc = nn.Linear(512, num_classes)

    def forward(self, x):
        feat = self.transformer(x)
        feat = self.head(feat)
        real_pred = self.real_fc(feat)
        class_pred = self.class_fc(feat)
        return real_pred, class_pred


# ============================================================
# 训练器
# ============================================================

class TransECGANTrainer:
    def __init__(self, pca_dim, num_classes, seq_len=32, latent_dim=128,
                 lr_d=2e-4, lr_g=1e-4, device='cuda', num_gpus=1, use_amp=True):
        self.pca_dim = pca_dim
        self.num_classes = num_classes
        self.seq_len = seq_len
        self.latent_dim = latent_dim
        self.device = torch.device(device)
        self.num_gpus = num_gpus
        self.use_amp = use_amp and device != 'cpu'

        # CUDA 加速配置
        if self.device.type == 'cuda':
            torch.backends.cudnn.benchmark = True
            torch.backends.cuda.matmul.allow_tf32 = True
            torch.backends.cudnn.allow_tf32 = True

        # 初始化模型
        self.generator = Generator(latent_dim, num_classes, pca_dim, seq_len).to(self.device)
        self.discriminator = Discriminator(pca_dim, num_classes, seq_len).to(self.device)

        # 多 GPU
        if num_gpus > 1 and torch.cuda.device_count() >= num_gpus:
            logger.info(f"使用 {num_gpus} 个 GPU (DataParallel)")
            self.generator = nn.DataParallel(self.generator)
            self.discriminator = nn.DataParallel(self.discriminator)

        # 优化器
        self.opt_G = optim.Adam(self.generator.parameters(), lr=lr_g, betas=(0.5, 0.999))
        self.opt_D = optim.Adam(self.discriminator.parameters(), lr=lr_d, betas=(0.5, 0.999))

        # 学习率调度
        self.sched_G = optim.lr_scheduler.CosineAnnealingLR(self.opt_G, T_max=200, eta_min=1e-6)
        self.sched_D = optim.lr_scheduler.CosineAnnealingLR(self.opt_D, T_max=200, eta_min=1e-6)

        # AMP 混合精度
        self.scaler_D = torch.amp.GradScaler('cuda', enabled=self.use_amp)
        self.scaler_G = torch.amp.GradScaler('cuda', enabled=self.use_amp)

        # 损失函数
        self.bce_loss = nn.BCEWithLogitsLoss()

        # 记录
        self.train_history = {'d_loss': [], 'g_loss': [], 'val_acc': [], 'val_loss': []}
        self.best_val_acc = 0.0
        self.best_state = None

        g_params = sum(p.numel() for p in self.generator.parameters())
        d_params = sum(p.numel() for p in self.discriminator.parameters())
        logger.info(f"Generator 参数量: {g_params:,}")
        logger.info(f"Discriminator 参数量: {d_params:,}")
        logger.info(f"总参数量: {g_params + d_params:,}")

    def _get_class_weights(self, y_train):
        """计算类别权重（处理不平衡）"""
        counts = Counter(y_train.tolist())
        total = len(y_train)
        weights = torch.zeros(self.num_classes)
        for cls_id, count in counts.items():
            weights[cls_id] = total / (self.num_classes * count)
        # 归一化
        weights = weights / weights.sum() * self.num_classes
        return weights.to(self.device)

    def train(self, train_loader, val_loader, epochs=200, patience=20,
              label_smooth_real=0.9, label_smooth_fake=0.1,
              output_dir='transec_gan_model'):
        """TransEC-GAN 对抗训练"""
        os.makedirs(output_dir, exist_ok=True)

        # 计算类别权重
        all_labels = []
        for _, labels in train_loader:
            all_labels.extend(labels.tolist())
        class_weights = self._get_class_weights(np.array(all_labels))
        cls_criterion = nn.CrossEntropyLoss(weight=class_weights)
        logger.info(f"类别权重: {class_weights.cpu().numpy()}")

        patience_counter = 0

        for epoch in range(epochs):
            t_epoch = time.time()
            self.generator.train()
            self.discriminator.train()

            d_loss_sum, g_loss_sum, cls_loss_sum = 0.0, 0.0, 0.0
            n_batches = 0

            for real_data, real_labels in train_loader:
                batch_size = real_data.size(0)
                real_data = real_data.to(self.device, non_blocking=True)
                real_labels = real_labels.to(self.device, non_blocking=True)

                # ===== 训练 Discriminator (AMP) =====
                self.opt_D.zero_grad(set_to_none=True)

                with torch.amp.autocast('cuda', enabled=self.use_amp):
                    real_score, real_class = self.discriminator(real_data)
                    real_target = torch.full((batch_size, 1), label_smooth_real, device=self.device)
                    d_real_loss = self.bce_loss(real_score, real_target)
                    d_cls_loss = cls_criterion(real_class, real_labels)

                    z = torch.randn(batch_size, self.latent_dim, device=self.device)
                    labels_onehot = torch.zeros(batch_size, self.num_classes, device=self.device)
                    labels_onehot.scatter_(1, real_labels.unsqueeze(1), 1)
                    fake_data = self.generator(z, labels_onehot)

                    fake_score, _ = self.discriminator(fake_data.detach())
                    fake_target = torch.full((batch_size, 1), label_smooth_fake, device=self.device)
                    d_fake_loss = self.bce_loss(fake_score, fake_target)

                    d_loss = d_real_loss + d_fake_loss + d_cls_loss

                self.scaler_D.scale(d_loss).backward()
                self.scaler_D.unscale_(self.opt_D)
                torch.nn.utils.clip_grad_norm_(self.discriminator.parameters(), 1.0)
                self.scaler_D.step(self.opt_D)
                self.scaler_D.update()

                # ===== 训练 Generator (AMP) =====
                self.opt_G.zero_grad(set_to_none=True)

                with torch.amp.autocast('cuda', enabled=self.use_amp):
                    z = torch.randn(batch_size, self.latent_dim, device=self.device)
                    rand_labels = torch.randint(0, self.num_classes, (batch_size,), device=self.device)
                    labels_onehot = torch.zeros(batch_size, self.num_classes, device=self.device)
                    labels_onehot.scatter_(1, rand_labels.unsqueeze(1), 1)
                    fake_data = self.generator(z, labels_onehot)

                    fake_score, fake_class = self.discriminator(fake_data)
                    g_real_target = torch.ones(batch_size, 1, device=self.device)
                    g_loss = self.bce_loss(fake_score, g_real_target)

                self.scaler_G.scale(g_loss).backward()
                self.scaler_G.unscale_(self.opt_G)
                torch.nn.utils.clip_grad_norm_(self.generator.parameters(), 1.0)
                self.scaler_G.step(self.opt_G)
                self.scaler_G.update()

                d_loss_sum += d_loss.item()
                g_loss_sum += g_loss.item()
                cls_loss_sum += d_cls_loss.item()
                n_batches += 1

            self.sched_D.step()
            self.sched_G.step()

            avg_d_loss = d_loss_sum / n_batches
            avg_g_loss = g_loss_sum / n_batches
            avg_cls_loss = cls_loss_sum / n_batches

            # ===== 验证 =====
            val_acc, val_loss = self._validate(val_loader, cls_criterion)

            self.train_history['d_loss'].append(avg_d_loss)
            self.train_history['g_loss'].append(avg_g_loss)
            self.train_history['val_acc'].append(val_acc)
            self.train_history['val_loss'].append(val_loss)

            elapsed = time.time() - t_epoch

            if True:  # 每个 epoch 都打印
                logger.info(
                    f"Epoch {epoch+1:3d}/{epochs} | "
                    f"D_loss={avg_d_loss:.4f} | G_loss={avg_g_loss:.4f} | "
                    f"CLS_loss={avg_cls_loss:.4f} | "
                    f"Val_acc={val_acc*100:.2f}% | Val_loss={val_loss:.4f} | "
                    f"{elapsed:.1f}s"
                )

            # 保存最佳模型
            if val_acc > self.best_val_acc:
                self.best_val_acc = val_acc
                patience_counter = 0
                self._save_checkpoint(output_dir, epoch, val_acc)
                logger.info(f"  ★ 新最佳模型! Val_acc={val_acc*100:.2f}%")
            else:
                patience_counter += 1

            # 早停
            if patience_counter >= patience:
                logger.info(f"早停于 Epoch {epoch+1} (patience={patience})")
                break

        # 训练结束
        logger.info(f"\n训练完成! 最佳 Val_acc={self.best_val_acc*100:.2f}%")
        return self.train_history

    def _validate(self, val_loader, cls_criterion):
        """在验证集上评估分类准确率"""
        self.discriminator.eval()
        correct = 0
        total = 0
        total_loss = 0.0
        n_batches = 0

        with torch.no_grad(), torch.amp.autocast('cuda', enabled=self.use_amp):
            for data, labels in val_loader:
                data = data.to(self.device, non_blocking=True)
                labels = labels.to(self.device, non_blocking=True)
                _, class_pred = self.discriminator(data)

                loss = cls_criterion(class_pred, labels)
                total_loss += loss.item()
                n_batches += 1

                pred = class_pred.argmax(dim=1)
                correct += (pred == labels).sum().item()
                total += labels.size(0)

        acc = correct / total if total > 0 else 0.0
        avg_loss = total_loss / n_batches if n_batches > 0 else 0.0
        return acc, avg_loss

    def _save_checkpoint(self, output_dir, epoch, val_acc):
        """保存模型检查点"""
        # 获取原始模型（去除 DataParallel wrapper）
        disc_state = (self.discriminator.module.state_dict()
                      if hasattr(self.discriminator, 'module')
                      else self.discriminator.state_dict())
        gen_state = (self.generator.module.state_dict()
                     if hasattr(self.generator, 'module')
                     else self.generator.state_dict())

        checkpoint = {
            'discriminator_state_dict': disc_state,
            'generator_state_dict': gen_state,
            'epoch': epoch + 1,
            'val_accuracy': val_acc,
            'label_classes': None,  # 训练完成后由 main() 填入
            'pca_dim': self.pca_dim,
            'num_classes': self.num_classes,
            'seq_len': self.seq_len,
            'latent_dim': self.latent_dim,
            'saved_at': datetime.now().isoformat(),
        }

        path = os.path.join(output_dir, 'best_model_4x5880_max.pth')
        torch.save(checkpoint, path)
        self.best_state = checkpoint

    def generate_training_plots(self, output_dir):
        """生成训练过程图表"""
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt

            fig, axes = plt.subplots(1, 3, figsize=(18, 5))

            # D/G Loss
            axes[0].plot(self.train_history['d_loss'], label='D Loss', alpha=0.8)
            axes[0].plot(self.train_history['g_loss'], label='G Loss', alpha=0.8)
            axes[0].set_title('GAN Training Loss')
            axes[0].set_xlabel('Epoch')
            axes[0].set_ylabel('Loss')
            axes[0].legend()
            axes[0].grid(True, alpha=0.3)

            # Validation Accuracy
            axes[1].plot(self.train_history['val_acc'], color='green')
            axes[1].set_title('Validation Accuracy')
            axes[1].set_xlabel('Epoch')
            axes[1].set_ylabel('Accuracy')
            axes[1].grid(True, alpha=0.3)
            axes[1].set_ylim([0, 1])

            # Validation Loss
            axes[2].plot(self.train_history['val_loss'], color='red')
            axes[2].set_title('Validation Loss')
            axes[2].set_xlabel('Epoch')
            axes[2].set_ylabel('Loss')
            axes[2].grid(True, alpha=0.3)

            plt.tight_layout()
            path = os.path.join(output_dir, 'training_curves.png')
            plt.savefig(path, dpi=150, bbox_inches='tight')
            plt.close()
            logger.info(f"训练曲线已保存: {path}")
        except ImportError:
            logger.warning("matplotlib 未安装，跳过图表生成")


# ============================================================
# 主流程
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="TransEC-GAN 训练")
    parser.add_argument("--data_dir", type=str, required=True,
                        help="预处理数据目录 (含 train/val/test_sequences.npz)")
    parser.add_argument("--output_dir", type=str, default="transec_gan_model",
                        help="模型输出目录")
    parser.add_argument("--epochs", type=int, default=200, help="训练轮数")
    parser.add_argument("--batch_size", type=int, default=8192, help="批大小 (4xRTX5880建议8192+)")
    parser.add_argument("--lr_d", type=float, default=2e-4, help="Discriminator 学习率")
    parser.add_argument("--lr_g", type=float, default=1e-4, help="Generator 学习率")
    parser.add_argument("--patience", type=int, default=20, help="早停耐心值")
    parser.add_argument("--device", type=str, default="cuda", help="设备 (cuda/cpu)")
    parser.add_argument("--num_gpus", type=int, default=4, help="GPU 数量")
    parser.add_argument("--latent_dim", type=int, default=128, help="噪声维度")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("TransEC-GAN 训练 - 御链天鉴 NIDS")
    logger.info("=" * 60)

    # 加载数据统计
    stats_path = os.path.join(args.data_dir, 'data_stats.json')
    with open(stats_path, 'r', encoding='utf-8') as f:
        data_stats = json.load(f)

    pca_dim = data_stats['pca_dim']
    num_classes = data_stats['num_classes']
    seq_len = data_stats['seq_len']
    class_names = data_stats['class_names']

    logger.info(f"PCA_DIM={pca_dim}, NUM_CLASSES={num_classes}, SEQ_LEN={seq_len}")
    logger.info(f"类别: {class_names}")

    # 加载序列数据
    logger.info("加载训练数据...")
    train_data = np.load(os.path.join(args.data_dir, 'train_sequences.npz'))
    X_train, y_train = train_data['X'], train_data['y']
    logger.info(f"  训练集: {X_train.shape}, 标签分布: {dict(Counter(y_train.tolist()))}")

    val_data = np.load(os.path.join(args.data_dir, 'val_sequences.npz'))
    X_val, y_val = val_data['X'], val_data['y']
    logger.info(f"  验证集: {X_val.shape}")

    # DataLoader
    train_dataset = TensorDataset(torch.FloatTensor(X_train), torch.LongTensor(y_train))
    val_dataset = TensorDataset(torch.FloatTensor(X_val), torch.LongTensor(y_val))

    nw = min(16, os.cpu_count() or 4)
    train_loader = DataLoader(train_dataset, batch_size=args.batch_size,
                              shuffle=True, num_workers=nw, pin_memory=True,
                              persistent_workers=True, prefetch_factor=4,
                              drop_last=True)
    val_loader = DataLoader(val_dataset, batch_size=args.batch_size * 2,
                            shuffle=False, num_workers=nw, pin_memory=True,
                            persistent_workers=True, prefetch_factor=4)

    # 设备检测
    device = args.device
    if device == 'cuda' and not torch.cuda.is_available():
        logger.warning("CUDA 不可用，回退到 CPU")
        device = 'cpu'
    elif device == 'cuda':
        gpu_name = torch.cuda.get_device_name(0)
        gpu_count = torch.cuda.device_count()
        vram = torch.cuda.get_device_properties(0).total_memory / 1024**3
        logger.info(f"GPU: {gpu_name} × {gpu_count} ({vram:.0f}GB each)")
        logger.info(f"AMP 混合精度: 启用")
        logger.info(f"CUDNN Benchmark: 启用")
        logger.info(f"DataLoader Workers: {nw}, Prefetch: 4")

    # 初始化训练器
    trainer = TransECGANTrainer(
        pca_dim=pca_dim,
        num_classes=num_classes,
        seq_len=seq_len,
        latent_dim=args.latent_dim,
        lr_d=args.lr_d,
        lr_g=args.lr_g,
        device=device,
        num_gpus=min(args.num_gpus, torch.cuda.device_count() if device == 'cuda' else 1)
    )

    # 训练
    t_start = time.time()
    history = trainer.train(
        train_loader, val_loader,
        epochs=args.epochs,
        patience=args.patience,
        output_dir=args.output_dir
    )

    # 更新 checkpoint 中的 label_classes
    ckpt_path = os.path.join(args.output_dir, 'best_model_4x5880_max.pth')
    if os.path.exists(ckpt_path):
        ckpt = torch.load(ckpt_path, map_location='cpu', weights_only=False)
        ckpt['label_classes'] = class_names
        torch.save(ckpt, ckpt_path)
        logger.info(f"已更新 label_classes: {class_names}")

    # 生成训练曲线
    trainer.generate_training_plots(args.output_dir)

    # 保存训练历史
    history_path = os.path.join(args.output_dir, 'training_history.json')
    with open(history_path, 'w', encoding='utf-8') as f:
        json.dump({k: [float(v) for v in vals] for k, vals in history.items()},
                  f, indent=2)

    elapsed = time.time() - t_start
    logger.info("\n" + "=" * 60)
    logger.info("训练完成!")
    logger.info("=" * 60)
    logger.info(f"最佳验证准确率: {trainer.best_val_acc*100:.2f}%")
    logger.info(f"模型文件: {ckpt_path}")
    logger.info(f"总训练时间: {elapsed/60:.1f} 分钟")
    logger.info("")
    logger.info("下一步: 运行评估脚本")
    logger.info(f"  python nids_evaluate.py --data_dir {args.data_dir} "
                f"--model_path {ckpt_path}")


if __name__ == '__main__':
    main()
