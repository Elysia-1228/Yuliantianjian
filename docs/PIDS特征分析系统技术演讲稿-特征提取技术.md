# PIDS 特征分析系统技术演讲稿 - 特征提取技术

## 1. 130维特征体系架构

### 1.1 特征维度分布
```
总计: 130维结构化特征向量
├── 图结构特征: 15维 (11.5%)
├── 节点特征: 40维 (30.8%) 
├── 边特征: 25维 (19.2%)
├── 序列特征: 30维 (23.1%)
└── 语义特征: 20维 (15.4%)
```

### 1.2 特征工程设计理念
- **多维度覆盖**: 从不同角度刻画系统行为
- **安全语义**: 每个特征都有明确的安全含义
- **区分能力**: 能够有效区分正常和异常行为
- **计算效率**: 优化算法确保实时性能

## 2. 图结构特征 (15维)

### 2.1 基础拓扑指标 (5维)
```python
def _extract_basic_topology(self, G):
    return [
        len(G.nodes()),           # 节点总数
        len(G.edges()),           # 边总数  
        nx.density(G),            # 图密度
        self._safe_diameter(G),   # 图直径
        nx.number_connected_components(G.to_undirected())  # 连通分量数
    ]
```

**安全意义**:
- 节点数反映攻击规模
- 边数体现操作复杂度
- 密度显示攻击集中度

### 2.2 中心性指标 (5维)
```python
def _extract_centrality_features(self, G):
    degree_centrality = nx.degree_centrality(G)
    betweenness_centrality = nx.betweenness_centrality(G)
    closeness_centrality = nx.closeness_centrality(G)
    
    return [
        np.mean(list(degree_centrality.values())),      # 平均度中心性
        np.std(list(degree_centrality.values())),       # 度中心性标准差
        np.mean(list(betweenness_centrality.values())), # 平均介数中心性
        np.mean(list(closeness_centrality.values())),   # 平均接近中心性
        max(degree_centrality.values()) if degree_centrality else 0  # 最大度中心性
    ]
```

### 2.3 高级图特征 (5维)
- **聚类系数**: 反映局部连接紧密度
- **平均路径长度**: 衡量图的紧凑性
- **度分布熵**: 描述度分布的均匀性

## 3. 节点特征 (40维)

### 3.1 节点类型分布 (10维)
```python
def _extract_node_type_features(self, nodes):
    type_counts = {}
    for node in nodes:
        node_type = node.get('type', 'unknown')
        type_counts[node_type] = type_counts.get(node_type, 0) + 1
    
    # 标准化的10种主要节点类型
    standard_types = ['process', 'file', 'network', 'registry', 
                     'service', 'user', 'system', 'memory', 'device', 'other']
    
    features = []
    total_nodes = len(nodes)
    for node_type in standard_types:
        ratio = type_counts.get(node_type, 0) / total_nodes if total_nodes > 0 else 0
        features.append(ratio)
    
    return features
```

### 3.2 节点属性统计 (15维)
- **权限级别分布**: 系统/用户/访客权限比例
- **活跃度指标**: 高/中/低活跃节点分布
- **生命周期**: 短期/长期/持久节点比例
- **访问频率**: 频繁/偶尔/罕见访问模式
- **资源消耗**: CPU/内存/IO密集型分布

### 3.3 节点关系特征 (15维)
```python
def _extract_node_relationship_features(self, nodes, edges):
    # 入度出度统计
    in_degrees = {}
    out_degrees = {}
    
    for edge in edges:
        source, target = edge['source'], edge['target']
        out_degrees[source] = out_degrees.get(source, 0) + 1
        in_degrees[target] = in_degrees.get(target, 0) + 1
    
    in_degree_values = list(in_degrees.values())
    out_degree_values = list(out_degrees.values())
    
    return [
        np.mean(in_degree_values) if in_degree_values else 0,   # 平均入度
        np.std(in_degree_values) if in_degree_values else 0,    # 入度标准差
        np.mean(out_degree_values) if out_degree_values else 0, # 平均出度
        np.std(out_degree_values) if out_degree_values else 0,  # 出度标准差
        max(in_degree_values) if in_degree_values else 0,       # 最大入度
        max(out_degree_values) if out_degree_values else 0,     # 最大出度
        # ... 更多关系特征
    ]
```

## 4. 边特征 (25维)

### 4.1 边类型分析 (10维)
```python
def _extract_edge_type_features(self, edges):
    edge_types = ['read', 'write', 'execute', 'create', 'delete', 
                 'modify', 'access', 'connect', 'spawn', 'other']
    
    type_counts = {}
    for edge in edges:
        edge_type = edge.get('type', 'other')
        type_counts[edge_type] = type_counts.get(edge_type, 0) + 1
    
    total_edges = len(edges)
    return [type_counts.get(t, 0) / total_edges if total_edges > 0 else 0 
            for t in edge_types]
```

### 4.2 边权重分布 (8维)
- **权重统计**: 最大/最小/平均/中位数权重
- **权重分布**: 高/中/低权重边比例
- **权重变异**: 标准差和变异系数

### 4.3 边时序特征 (7维)
- **时间间隔**: 边创建的时间间隔分布
- **并发度**: 同时发生的边数量
- **持续时间**: 边的生命周期统计

## 5. 序列特征 (30维)

### 5.1 时间序列分析 (15维)
```python
def _extract_sequence_features(self, nodes, edges):
    # 提取时间戳序列
    timestamps = self._extract_timestamps(nodes)
    
    if len(timestamps) < 2:
        return [0.0] * 30
    
    # 时间间隔分析
    intervals = np.diff(sorted(timestamps))
    
    features = [
        np.mean(intervals),           # 平均时间间隔
        np.std(intervals),            # 时间间隔标准差
        np.min(intervals),            # 最小时间间隔
        np.max(intervals),            # 最大时间间隔
        len(intervals),               # 事件总数
        self._calculate_time_entropy(intervals),  # 时间熵
        # ... 更多时序特征
    ]
    
    return features
```

### 5.2 行为模式识别 (15维)
- **周期性检测**: 识别重复行为模式
- **突发性分析**: 检测行为突发事件
- **趋势分析**: 行为强度变化趋势
- **异常间隔**: 识别异常的时间间隔

```python
def _detect_burst_patterns(self, timestamps):
    """检测突发行为模式"""
    if len(timestamps) < 3:
        return 0, 0.0
    
    intervals = np.diff(sorted(timestamps))
    threshold = np.mean(intervals) * 0.1  # 突发阈值
    
    burst_count = 0
    burst_intensity = 0
    current_burst_length = 0
    
    for interval in intervals:
        if interval < threshold:
            current_burst_length += 1
        else:
            if current_burst_length > 0:
                burst_count += 1
                burst_intensity = max(burst_intensity, current_burst_length)
                current_burst_length = 0
    
    return burst_count, burst_intensity / len(intervals) if intervals else 0.0
```

## 6. 语义特征 (20维)

### 6.1 命名模式分析 (10维)
```python
def _extract_semantic_features(self, nodes, edges):
    # 文件路径分析
    system_paths = 0
    user_paths = 0
    temp_paths = 0
    suspicious_paths = 0
    
    for node in nodes:
        if node.get('type') == 'file':
            path = node.get('path', '').lower()
            if any(sys_path in path for sys_path in ['/system/', 'c:\\windows\\', '/usr/']):
                system_paths += 1
            elif any(user_path in path for user_path in ['/home/', 'c:\\users\\', '/tmp/']):
                user_paths += 1
            # ... 更多路径分析
    
    total_files = sum(1 for n in nodes if n.get('type') == 'file')
    
    return [
        system_paths / total_files if total_files > 0 else 0,
        user_paths / total_files if total_files > 0 else 0,
        # ... 更多语义特征
    ]
```

### 6.2 行为语义分析 (10维)
- **权限提升**: 检测权限提升行为
- **横向移动**: 识别横向移动模式
- **数据渗透**: 检测数据泄露行为
- **持久化**: 识别持久化机制

## 7. 特征工程优化

### 7.1 特征标准化
```python
def _normalize_features(self, features):
    """特征标准化处理"""
    # Z-score标准化
    features_array = np.array(features)
    mean_vals = np.mean(features_array, axis=0)
    std_vals = np.std(features_array, axis=0)
    
    # 避免除零错误
    std_vals = np.where(std_vals == 0, 1, std_vals)
    
    normalized = (features_array - mean_vals) / std_vals
    return normalized.tolist()
```

### 7.2 特征选择策略
- **相关性分析**: 移除高度相关的冗余特征
- **重要性评估**: 基于模型的特征重要性排序
- **稳定性测试**: 确保特征在不同环境下的稳定性

### 7.3 实时性能优化
```python
class OptimizedFeatureExtractor:
    def __init__(self):
        self._feature_cache = {}
        self._computation_cache = {}
    
    @lru_cache(maxsize=1000)
    def _cached_graph_metrics(self, graph_hash):
        """缓存图指标计算结果"""
        return self._compute_expensive_metrics(graph_hash)
    
    def extract_with_caching(self, graph_data):
        """带缓存的特征提取"""
        graph_hash = self._hash_graph(graph_data)
        
        if graph_hash in self._feature_cache:
            return self._feature_cache[graph_hash]
        
        features = self.extract(graph_data)
        self._feature_cache[graph_hash] = features
        
        return features
```

## 8. 特征验证与质量保证

### 8.1 特征有效性验证
- **单调性测试**: 验证特征与威胁程度的单调关系
- **区分度测试**: 测试特征对正常/异常行为的区分能力
- **稳定性测试**: 验证特征在噪声环境下的稳定性

### 8.2 特征质量监控
```python
def validate_feature_quality(self, features):
    """特征质量验证"""
    quality_metrics = {
        'completeness': self._check_completeness(features),
        'consistency': self._check_consistency(features),
        'accuracy': self._check_accuracy(features),
        'uniqueness': self._check_uniqueness(features)
    }
    
    return quality_metrics
```

---

## 技术创新总结

1. **多维度特征体系**: 130维全面覆盖系统行为
2. **安全语义驱动**: 每个特征都有明确安全含义
3. **实时计算优化**: 缓存机制确保毫秒级响应
4. **自适应标准化**: 动态调整特征分布
5. **质量保证机制**: 多层次特征验证体系
