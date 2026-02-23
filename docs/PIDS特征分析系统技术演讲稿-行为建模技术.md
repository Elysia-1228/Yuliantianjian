# PIDS 特征分析系统技术演讲稿 - 行为建模技术

## 1. AI异常检测模型架构

### 1.1 多算法集成策略
```
PIDS 行为建模引擎
├── Isolation Forest (孤立森林)
│   ├── 全局异常检测
│   ├── 高维数据适应性强
│   └── 无需标注数据
├── One-Class SVM (单类支持向量机)
│   ├── 边界清晰的异常检测
│   ├── 核函数灵活性
│   └── 小样本学习能力
└── Local Outlier Factor (局部异常因子)
    ├── 局部密度异常检测
    ├── 适应数据分布变化
    └── 邻域敏感检测
```

### 1.2 算法选择策略
```python
class ModelSelector:
    """智能模型选择器"""
    
    ALGORITHM_CHARACTERISTICS = {
        'isolation_forest': {
            'best_for': ['high_dimensional', 'global_outliers', 'large_datasets'],
            'complexity': 'O(n log n)',
            'memory_usage': 'medium',
            'training_speed': 'fast'
        },
        'one_class_svm': {
            'best_for': ['clear_boundaries', 'small_datasets', 'kernel_tricks'],
            'complexity': 'O(n²)',
            'memory_usage': 'high', 
            'training_speed': 'slow'
        },
        'local_outlier_factor': {
            'best_for': ['local_outliers', 'varying_density', 'neighborhood_analysis'],
            'complexity': 'O(n²)',
            'memory_usage': 'medium',
            'training_speed': 'medium'
        }
    }
    
    def select_optimal_algorithm(self, data_characteristics):
        """基于数据特征自动选择最优算法"""
        scores = {}
        
        for algo, chars in self.ALGORITHM_CHARACTERISTICS.items():
            score = self._calculate_compatibility_score(data_characteristics, chars)
            scores[algo] = score
        
        return max(scores, key=scores.get)
```

## 2. Isolation Forest 技术实现

### 2.1 核心算法原理
```python
class OptimizedIsolationForest:
    """优化的孤立森林实现"""
    
    def __init__(self, n_estimators=100, contamination=0.1, random_state=42):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.trees = []
        self.threshold = None
    
    def fit(self, X):
        """训练孤立森林"""
        np.random.seed(self.random_state)
        n_samples, n_features = X.shape
        
        # 构建多棵孤立树
        for i in range(self.n_estimators):
            # 随机采样
            sample_indices = np.random.choice(n_samples, 
                                            size=min(256, n_samples), 
                                            replace=False)
            sample_data = X[sample_indices]
            
            # 构建孤立树
            tree = self._build_isolation_tree(sample_data, 0, n_features)
            self.trees.append(tree)
        
        # 计算异常阈值
        scores = self.decision_function(X)
        self.threshold = np.percentile(scores, (1 - self.contamination) * 100)
        
        return self
    
    def _build_isolation_tree(self, X, current_height, max_height):
        """构建单棵孤立树"""
        if len(X) <= 1 or current_height >= max_height:
            return {'type': 'leaf', 'size': len(X)}
        
        # 随机选择分割特征和分割点
        n_features = X.shape[1]
        split_feature = np.random.randint(0, n_features)
        feature_values = X[:, split_feature]
        
        if len(np.unique(feature_values)) == 1:
            return {'type': 'leaf', 'size': len(X)}
        
        split_value = np.random.uniform(feature_values.min(), feature_values.max())
        
        # 分割数据
        left_mask = feature_values < split_value
        right_mask = ~left_mask
        
        return {
            'type': 'internal',
            'split_feature': split_feature,
            'split_value': split_value,
            'left': self._build_isolation_tree(X[left_mask], current_height + 1, max_height),
            'right': self._build_isolation_tree(X[right_mask], current_height + 1, max_height)
        }
```

### 2.2 异常分数计算
```python
def _calculate_path_length(self, x, tree, current_height=0):
    """计算样本在孤立树中的路径长度"""
    if tree['type'] == 'leaf':
        # 叶子节点：路径长度 + 剩余样本的平均路径长度估计
        return current_height + self._average_path_length(tree['size'])
    
    # 内部节点：继续遍历
    if x[tree['split_feature']] < tree['split_value']:
        return self._calculate_path_length(x, tree['left'], current_height + 1)
    else:
        return self._calculate_path_length(x, tree['right'], current_height + 1)

def decision_function(self, X):
    """计算异常分数"""
    scores = []
    
    for x in X:
        # 计算在所有树中的平均路径长度
        path_lengths = [self._calculate_path_length(x, tree) for tree in self.trees]
        avg_path_length = np.mean(path_lengths)
        
        # 异常分数：路径长度越短，异常程度越高
        score = 2 ** (-avg_path_length / self._average_path_length(len(X)))
        scores.append(score)
    
    return np.array(scores)
```

## 3. One-Class SVM 技术实现

### 3.1 核函数优化
```python
class AdaptiveOneClassSVM:
    """自适应单类SVM"""
    
    def __init__(self, kernel='rbf', gamma='scale', nu=0.1):
        self.kernel = kernel
        self.gamma = gamma
        self.nu = nu
        self.model = None
        self.scaler = StandardScaler()
    
    def fit(self, X):
        """训练单类SVM"""
        # 数据标准化
        X_scaled = self.scaler.fit_transform(X)
        
        # 自适应参数调优
        if self.gamma == 'scale':
            self.gamma = 1.0 / (X.shape[1] * X.var())
        
        # 训练模型
        self.model = OneClassSVM(
            kernel=self.kernel,
            gamma=self.gamma,
            nu=self.nu
        )
        
        self.model.fit(X_scaled)
        return self
    
    def decision_function(self, X):
        """计算决策函数值"""
        X_scaled = self.scaler.transform(X)
        return self.model.decision_function(X_scaled)
    
    def predict(self, X):
        """预测异常"""
        scores = self.decision_function(X)
        return np.where(scores < 0, -1, 1)  # -1: 异常, 1: 正常
```

### 3.2 核函数自动选择
```python
def select_optimal_kernel(self, X, kernels=['rbf', 'poly', 'sigmoid']):
    """自动选择最优核函数"""
    best_kernel = None
    best_score = -np.inf
    
    # 交叉验证评估不同核函数
    for kernel in kernels:
        scores = []
        kfold = KFold(n_splits=5, shuffle=True, random_state=42)
        
        for train_idx, val_idx in kfold.split(X):
            X_train, X_val = X[train_idx], X[val_idx]
            
            model = OneClassSVM(kernel=kernel, nu=self.nu)
            model.fit(X_train)
            
            # 使用重构误差作为评估指标
            val_scores = model.decision_function(X_val)
            score = np.mean(val_scores)
            scores.append(score)
        
        avg_score = np.mean(scores)
        if avg_score > best_score:
            best_score = avg_score
            best_kernel = kernel
    
    return best_kernel
```

## 4. Local Outlier Factor 技术实现

### 4.1 局部密度计算
```python
class EnhancedLOF:
    """增强的局部异常因子"""
    
    def __init__(self, n_neighbors=20, contamination=0.1):
        self.n_neighbors = n_neighbors
        self.contamination = contamination
        self.lof_scores = None
        self.threshold = None
    
    def fit_predict(self, X):
        """训练并预测"""
        # 计算k距离和k邻域
        distances, indices = self._compute_k_distances(X)
        
        # 计算局部可达密度
        lrd_scores = self._compute_local_reachability_density(X, distances, indices)
        
        # 计算LOF分数
        self.lof_scores = self._compute_lof_scores(X, lrd_scores, indices)
        
        # 确定异常阈值
        self.threshold = np.percentile(self.lof_scores, 
                                     (1 - self.contamination) * 100)
        
        return np.where(self.lof_scores > self.threshold, -1, 1)
    
    def _compute_k_distances(self, X):
        """计算k距离和k邻域"""
        from sklearn.neighbors import NearestNeighbors
        
        nbrs = NearestNeighbors(n_neighbors=self.n_neighbors + 1)
        nbrs.fit(X)
        distances, indices = nbrs.kneighbors(X)
        
        # 排除自身
        return distances[:, 1:], indices[:, 1:]
    
    def _compute_local_reachability_density(self, X, distances, indices):
        """计算局部可达密度"""
        lrd_scores = np.zeros(len(X))
        
        for i in range(len(X)):
            # 计算可达距离
            reachability_distances = []
            for j in indices[i]:
                reach_dist = max(distances[i][np.where(indices[i] == j)[0][0]], 
                               distances[j][-1])  # k-distance of j
                reachability_distances.append(reach_dist)
            
            # 局部可达密度 = 1 / 平均可达距离
            avg_reach_dist = np.mean(reachability_distances)
            lrd_scores[i] = 1.0 / (avg_reach_dist + 1e-10)  # 避免除零
        
        return lrd_scores
    
    def _compute_lof_scores(self, X, lrd_scores, indices):
        """计算LOF分数"""
        lof_scores = np.zeros(len(X))
        
        for i in range(len(X)):
            # 邻域的局部可达密度比值
            neighbor_lrd_ratios = []
            for j in indices[i]:
                ratio = lrd_scores[j] / (lrd_scores[i] + 1e-10)
                neighbor_lrd_ratios.append(ratio)
            
            # LOF = 邻域密度比值的平均值
            lof_scores[i] = np.mean(neighbor_lrd_ratios)
        
        return lof_scores
```

## 5. 模型集成与融合

### 5.1 集成学习策略
```python
class EnsembleAnomalyDetector:
    """集成异常检测器"""
    
    def __init__(self, models=None, weights=None, fusion_method='weighted_average'):
        self.models = models or [
            ('isolation_forest', OptimizedIsolationForest()),
            ('one_class_svm', AdaptiveOneClassSVM()),
            ('lof', EnhancedLOF())
        ]
        self.weights = weights or [0.4, 0.3, 0.3]
        self.fusion_method = fusion_method
        self.fitted_models = {}
    
    def fit(self, X):
        """训练所有模型"""
        for name, model in self.models:
            print(f"Training {name}...")
            model.fit(X)
            self.fitted_models[name] = model
        
        return self
    
    def predict(self, X):
        """集成预测"""
        predictions = {}
        scores = {}
        
        # 获取各模型预测结果
        for name, model in self.fitted_models.items():
            if hasattr(model, 'decision_function'):
                scores[name] = model.decision_function(X)
            else:
                scores[name] = model.lof_scores if hasattr(model, 'lof_scores') else None
            
            predictions[name] = model.predict(X) if hasattr(model, 'predict') else None
        
        # 融合预测结果
        if self.fusion_method == 'weighted_average':
            return self._weighted_average_fusion(scores)
        elif self.fusion_method == 'majority_voting':
            return self._majority_voting_fusion(predictions)
        else:
            return self._adaptive_fusion(scores, predictions)
    
    def _weighted_average_fusion(self, scores):
        """加权平均融合"""
        final_scores = np.zeros(len(next(iter(scores.values()))))
        
        for i, (name, _) in enumerate(self.models):
            if name in scores and scores[name] is not None:
                # 标准化分数到[0,1]区间
                normalized_scores = self._normalize_scores(scores[name])
                final_scores += self.weights[i] * normalized_scores
        
        # 基于融合分数确定异常
        threshold = np.percentile(final_scores, 90)  # 前10%为异常
        return np.where(final_scores > threshold, -1, 1)
    
    def _normalize_scores(self, scores):
        """分数标准化"""
        min_score, max_score = scores.min(), scores.max()
        if max_score == min_score:
            return np.zeros_like(scores)
        return (scores - min_score) / (max_score - min_score)
```

### 5.2 自适应权重调整
```python
def adaptive_weight_adjustment(self, X, y_true):
    """基于性能自适应调整模型权重"""
    model_performances = {}
    
    # 计算各模型性能
    for name, model in self.fitted_models.items():
        y_pred = model.predict(X)
        f1 = f1_score(y_true, y_pred, average='weighted')
        precision = precision_score(y_true, y_pred, average='weighted')
        recall = recall_score(y_true, y_pred, average='weighted')
        
        # 综合性能分数
        performance = 0.4 * f1 + 0.3 * precision + 0.3 * recall
        model_performances[name] = performance
    
    # 基于性能调整权重
    total_performance = sum(model_performances.values())
    self.weights = [model_performances[name] / total_performance 
                   for name, _ in self.models]
    
    return self.weights
```

## 6. 特征重要性分析

### 6.1 SHAP值计算
```python
class FeatureImportanceAnalyzer:
    """特征重要性分析器"""
    
    def __init__(self, model, feature_names):
        self.model = model
        self.feature_names = feature_names
        self.importance_scores = None
    
    def analyze_feature_importance(self, X, method='permutation'):
        """分析特征重要性"""
        if method == 'permutation':
            return self._permutation_importance(X)
        elif method == 'shap':
            return self._shap_importance(X)
        else:
            return self._model_based_importance()
    
    def _permutation_importance(self, X):
        """置换重要性分析"""
        baseline_score = self._get_model_score(X)
        importance_scores = {}
        
        for i, feature_name in enumerate(self.feature_names):
            # 置换第i个特征
            X_permuted = X.copy()
            np.random.shuffle(X_permuted[:, i])
            
            # 计算性能下降
            permuted_score = self._get_model_score(X_permuted)
            importance = baseline_score - permuted_score
            importance_scores[feature_name] = importance
        
        self.importance_scores = importance_scores
        return importance_scores
    
    def get_top_features(self, n=10):
        """获取最重要的n个特征"""
        if self.importance_scores is None:
            raise ValueError("请先运行特征重要性分析")
        
        sorted_features = sorted(self.importance_scores.items(), 
                               key=lambda x: x[1], reverse=True)
        return sorted_features[:n]
```

## 7. 模型性能优化

### 7.1 超参数自动调优
```python
class HyperparameterOptimizer:
    """超参数自动调优器"""
    
    def __init__(self, model_type, param_space):
        self.model_type = model_type
        self.param_space = param_space
        self.best_params = None
        self.best_score = -np.inf
    
    def optimize(self, X, cv_folds=5, n_trials=100):
        """贝叶斯优化超参数"""
        from skopt import gp_minimize
        from skopt.space import Real, Integer, Categorical
        
        def objective(params):
            # 构建参数字典
            param_dict = dict(zip(self.param_space.keys(), params))
            
            # 交叉验证评估
            scores = []
            kfold = KFold(n_splits=cv_folds, shuffle=True, random_state=42)
            
            for train_idx, val_idx in kfold.split(X):
                X_train, X_val = X[train_idx], X[val_idx]
                
                # 训练模型
                model = self._create_model(param_dict)
                model.fit(X_train)
                
                # 评估性能
                val_scores = model.decision_function(X_val)
                score = self._calculate_silhouette_score(X_val, val_scores)
                scores.append(score)
            
            avg_score = np.mean(scores)
            return -avg_score  # 最小化负分数
        
        # 贝叶斯优化
        result = gp_minimize(
            func=objective,
            dimensions=list(self.param_space.values()),
            n_calls=n_trials,
            random_state=42
        )
        
        self.best_params = dict(zip(self.param_space.keys(), result.x))
        self.best_score = -result.fun
        
        return self.best_params
```

## 8. 实时检测优化

### 8.1 增量学习
```python
class IncrementalAnomalyDetector:
    """增量异常检测器"""
    
    def __init__(self, base_model, update_threshold=100):
        self.base_model = base_model
        self.update_threshold = update_threshold
        self.sample_buffer = []
        self.update_count = 0
    
    def partial_fit(self, X_new):
        """增量训练"""
        self.sample_buffer.extend(X_new)
        
        # 达到更新阈值时重新训练
        if len(self.sample_buffer) >= self.update_threshold:
            # 合并新旧数据
            X_combined = np.vstack([self.base_model.training_data, 
                                  np.array(self.sample_buffer)])
            
            # 重新训练模型
            self.base_model.fit(X_combined)
            
            # 清空缓冲区
            self.sample_buffer = []
            self.update_count += 1
    
    def predict_with_confidence(self, X):
        """带置信度的预测"""
        predictions = self.base_model.predict(X)
        scores = self.base_model.decision_function(X)
        
        # 计算预测置信度
        confidence = self._calculate_confidence(scores)
        
        return predictions, confidence
```

---

## 技术优势总结

1. **多算法融合**: 结合三种算法的优势，提高检测准确性
2. **自适应优化**: 根据数据特征自动选择最优算法和参数
3. **实时性能**: 优化的算法实现确保毫秒级响应
4. **可解释性**: 提供特征重要性分析和异常原因解释
5. **增量学习**: 支持在线学习和模型更新
6. **鲁棒性**: 多层次验证确保模型稳定性
