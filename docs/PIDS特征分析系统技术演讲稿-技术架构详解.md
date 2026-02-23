# PIDS 特征分析系统技术演讲稿 - 技术架构详解

## 1. 系统技术架构深度解析

### 1.1 整体技术栈
```
前端层: React + TypeScript + Ant Design
API网关: FastAPI (Python 3.8+)
核心引擎: NetworkX + NumPy + Scikit-learn
数据存储: 内存缓存 + 文件持久化
监控采集: Scapy + psutil + 系统调用跟踪
```

### 1.2 微服务架构设计
```
┌─────────────────────────────────────────────────────────────┐
│                    PIDS 微服务架构                            │
├─────────────────────────────────────────────────────────────┤
│  前端服务 (React)                                             │
│  ├── 特征可视化组件                                          │
│  ├── 检测结果展示                                            │
│  └── 系统监控面板                                            │
├─────────────────────────────────────────────────────────────┤
│  API 网关 (FastAPI)                                          │
│  ├── /api/pids/features/extract                             │
│  ├── /api/pids/features/{threat_id}                         │
│  ├── /api/pids/feature-names                                │
│  └── /api/pids/health                                       │
├─────────────────────────────────────────────────────────────┤
│  核心处理引擎                                                 │
│  ├── FeatureExtractor (特征提取)                             │
│  ├── BehaviorModeler (行为建模)                              │
│  └── PerformanceEvaluator (性能评估)                         │
├─────────────────────────────────────────────────────────────┤
│  数据层                                                       │
│  ├── 特征缓存 (内存)                                         │
│  ├── 模型持久化 (文件)                                       │
│  └── 配置管理                                                │
└─────────────────────────────────────────────────────────────┘
```

## 2. 核心模块技术实现

### 2.1 特征提取引擎 (FeatureExtractor)

#### 技术实现细节
```python
class FeatureExtractor:
    """130维特征提取引擎"""
    
    def __init__(self):
        self.feature_groups = {
            'graph_structure': 15,  # 图结构特征
            'node': 40,            # 节点特征  
            'edge': 25,            # 边特征
            'sequence': 30,        # 序列特征
            'semantic': 20         # 语义特征
        }
    
    def extract(self, graph_data: Dict) -> np.ndarray:
        """提取130维特征向量"""
        features = []
        nodes = graph_data.get('nodes', [])
        edges = graph_data.get('edges', [])
        
        # 五大特征组提取
        features.extend(self._extract_graph_structure_features(nodes, edges))
        features.extend(self._extract_node_features(nodes))
        features.extend(self._extract_edge_features(nodes, edges))
        features.extend(self._extract_sequence_features(nodes, edges))
        features.extend(self._extract_semantic_features(nodes, edges))
        
        return np.array(features, dtype=np.float32)
```

#### 图结构特征 (15维)
- **NetworkX集成**: 使用专业图分析库
- **拓扑指标**: 节点数、边数、密度、直径
- **连通性**: 连通分量、最大连通子图
- **中心性**: 度中心性、接近中心性、介数中心性

```python
def _extract_graph_structure_features(self, nodes, edges):
    """图结构特征提取"""
    G = nx.DiGraph()  # 有向图
    
    # 构建NetworkX图
    for node in nodes:
        G.add_node(node['id'], **node)
    for edge in edges:
        G.add_edge(edge['source'], edge['target'], **edge)
    
    features = [
        len(nodes),                    # 节点数量
        len(edges),                    # 边数量
        nx.density(G),                 # 图密度
        nx.diameter(G) if nx.is_connected(G.to_undirected()) else 0,
        nx.number_connected_components(G.to_undirected()),  # 连通分量
        # ... 更多图结构指标
    ]
    
    return features[:15]  # 确保15维
```

### 2.2 行为建模引擎 (BehaviorModeler)

#### 多算法集成架构
```python
class BehaviorModeler:
    """行为建模引擎 - 支持多种异常检测算法"""
    
    SUPPORTED_ALGORITHMS = {
        'isolation_forest': IsolationForest,
        'one_class_svm': OneClassSVM,
        'local_outlier_factor': LocalOutlierFactor
    }
    
    def create_model(self, config: ModelConfig):
        """动态创建模型"""
        algorithm = config.algorithm
        params = config.parameters
        
        if algorithm == 'isolation_forest':
            return IsolationForest(
                n_estimators=params.get('n_estimators', 100),
                contamination=params.get('contamination', 0.1),
                random_state=42
            )
        elif algorithm == 'one_class_svm':
            return OneClassSVM(
                kernel=params.get('kernel', 'rbf'),
                gamma=params.get('gamma', 'scale'),
                nu=params.get('nu', 0.1)
            )
        # ... 其他算法
```

#### 训练流程技术实现
```python
def train(self, features: np.ndarray, config: ModelConfig, validation_split=0.2):
    """模型训练流程"""
    
    # 1. 数据预处理
    self.scaler = StandardScaler()
    features_scaled = self.scaler.fit_transform(features)
    
    # 2. 训练验证分割
    X_train, X_val = train_test_split(
        features_scaled, test_size=validation_split, random_state=42
    )
    
    # 3. 模型训练
    self.model = self.create_model(config)
    start_time = time.time()
    self.model.fit(X_train)
    training_time = time.time() - start_time
    
    # 4. 验证评估
    val_scores = self._calculate_anomaly_scores(X_val)
    
    return {
        'training_time': training_time,
        'validation_scores': val_scores.tolist(),
        'model_params': self.model.get_params(),
        'feature_count': features.shape[1]
    }
```

### 2.3 性能评估模块 (PerformanceEvaluator)

#### 多维度评估体系
```python
class PerformanceEvaluator:
    """性能评估引擎"""
    
    def evaluate_detection_performance(self, y_true, y_pred, y_scores=None):
        """检测性能综合评估"""
        
        # 基础分类指标
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, average='weighted')
        recall = recall_score(y_true, y_pred, average='weighted')
        f1 = f1_score(y_true, y_pred, average='weighted')
        
        # ROC曲线分析
        if y_scores is not None:
            fpr, tpr, _ = roc_curve(y_true, y_scores)
            auc_roc = auc(fpr, tpr)
        else:
            fpr, tpr, auc_roc = None, None, None
        
        # 混淆矩阵
        cm = confusion_matrix(y_true, y_pred)
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'auc_roc': auc_roc,
            'confusion_matrix': cm.tolist(),
            'fpr': fpr.tolist() if fpr is not None else None,
            'tpr': tpr.tolist() if tpr is not None else None
        }
```

## 3. API服务架构 (FastAPI)

### 3.1 API设计模式
```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional

app = FastAPI(
    title="PIDS Feature Analysis API",
    description="基于溯源的入侵检测系统特征分析接口",
    version="1.0.0"
)

# 数据模型定义
class GraphNode(BaseModel):
    id: str
    type: str
    properties: Dict
    timestamp: Optional[str] = None

class GraphEdge(BaseModel):
    source: str
    target: str
    type: str
    properties: Dict
    timestamp: Optional[str] = None

class FeatureRequest(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    metadata: Optional[Dict] = None
```

### 3.2 核心API端点实现

#### 特征提取接口
```python
@app.post("/api/pids/features/extract", response_model=FeatureResponse)
async def extract_features(request: FeatureRequest):
    """特征提取主接口"""
    try:
        # 转换数据格式
        graph_data = {
            'nodes': [node.dict() for node in request.nodes],
            'edges': [edge.dict() for edge in request.edges]
        }
        
        # 特征提取
        extractor = FeatureExtractor()
        features = extractor.extract(graph_data)
        grouped_features = extractor.extract_grouped(graph_data)
        
        # 构建响应
        threat_id = f"threat_{int(time.time())}"
        
        # 缓存特征
        feature_cache[threat_id] = {
            'features': features,
            'grouped': grouped_features,
            'timestamp': datetime.now(),
            'graph_data': graph_data
        }
        
        return FeatureResponse(
            success=True,
            threatId=threat_id,
            rawVector=features.tolist(),
            featureVector=features.tolist(),
            featureGroups=grouped_features,
            extractTime=datetime.now().isoformat(),
            message="特征提取成功"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

### 3.3 性能优化策略

#### 缓存机制
```python
from functools import lru_cache
import time

# 内存缓存
feature_cache = {}
CACHE_EXPIRE_TIME = 3600  # 1小时

@lru_cache(maxsize=1000)
def get_cached_features(graph_hash: str):
    """LRU缓存机制"""
    return feature_cache.get(graph_hash)

def cleanup_expired_cache():
    """清理过期缓存"""
    current_time = time.time()
    expired_keys = [
        key for key, value in feature_cache.items()
        if current_time - value['timestamp'].timestamp() > CACHE_EXPIRE_TIME
    ]
    for key in expired_keys:
        del feature_cache[key]
```

## 4. 数据流处理架构

### 4.1 实时数据流
```
数据采集 → 溯源图构建 → 特征提取 → 异常检测 → 结果输出
   ↓           ↓           ↓          ↓          ↓
网络流量    节点/边      130维向量   异常分数    告警/日志
进程行为    时序关系    特征分组    置信度      可视化
系统调用    图结构      缓存存储    模型预测    API响应
```

### 4.2 批处理架构
```python
class BatchProcessor:
    """批处理引擎"""
    
    def process_batch(self, graph_batch: List[Dict]):
        """批量处理溯源图"""
        results = []
        
        for graph_data in graph_batch:
            # 并行特征提取
            features = self.extractor.extract(graph_data)
            
            # 异常检测
            if self.model:
                prediction = self.modeler.predict(features)
                results.append(prediction)
        
        return results
```

## 5. 系统集成与部署

### 5.1 Docker容器化
```dockerfile
FROM python:3.8-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 7890

CMD ["uvicorn", "pids_feature_api:app", "--host", "0.0.0.0", "--port", "7890"]
```

### 5.2 配置管理
```python
class PIDSConfig:
    """系统配置管理"""
    
    # API配置
    API_HOST = "0.0.0.0"
    API_PORT = 7890
    
    # 特征提取配置
    FEATURE_DIMENSION = 130
    CACHE_SIZE = 1000
    
    # 模型配置
    DEFAULT_ALGORITHM = "isolation_forest"
    MODEL_SAVE_PATH = "./models/"
    
    # 性能配置
    BATCH_SIZE = 100
    MAX_WORKERS = 4
```

---

## 技术亮点总结

1. **模块化架构**: 高内聚低耦合的设计模式
2. **多算法支持**: 灵活的异常检测算法选择
3. **高性能API**: FastAPI + 异步处理
4. **智能缓存**: LRU + 过期清理机制
5. **标准化接口**: RESTful API设计
6. **容器化部署**: Docker支持便于部署
