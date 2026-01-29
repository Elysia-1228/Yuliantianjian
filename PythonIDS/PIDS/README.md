# PIDS 因果溯源图智能分析模块

## 模块说明

本模块实现 PIDS 因果溯源图的智能分析功能，将溯源图谱转化为可量化的特征向量。

## 文件结构

```
PIDS/
├── __init__.py              # 模块入口
├── pids_feature_api.py      # FastAPI服务 (端口7890)
├── requirements.txt         # Python依赖
├── README.md                # 本文档
│
├── feature_extraction/      # 1. 特征提取引擎
│   ├── __init__.py
│   └── feature_extractor.py # 130维特征向量提取
│
├── behavior_modeling/       # 2. 行为建模系统
│   ├── __init__.py
│   └── behavior_modeling.py # 异常检测模型
│
├── evaluation/              # 3. 检测性能评估
│   ├── __init__.py
│   └── evaluation.py        # 多维度评估指标
│
├── sql/                     # 数据库脚本
│   └── pids_feature_tables.sql
└── models/                  # 训练好的模型文件
```

## 快速开始

```python
from PIDS.feature_extractor import FeatureExtractor

# 创建特征提取器
extractor = FeatureExtractor()

# 溯源图数据
graph_data = {
    "nodes": [
        {"id": "attacker_1", "label": "10.138.50.151", "type": "attacker"},
        {"id": "process_nginx", "label": "nginx", "type": "process"},
        {"id": "file_passwd", "label": "/etc/passwd", "type": "file"}
    ],
    "edges": [
        {"source": "attacker_1", "target": "process_nginx", "label": "攻击"},
        {"source": "process_nginx", "target": "file_passwd", "label": "访问"}
    ]
}

# 提取130维特征向量
features = extractor.extract(graph_data)
print(f"特征维度: {len(features)}")  # 130

# 获取带名称的特征
named_features = extractor.extract_with_names(graph_data)
for name, value in list(named_features.items())[:5]:
    print(f"{name}: {value}")

# 分组提取
grouped = extractor.extract_grouped(graph_data)
print(f"图结构特征: {len(grouped['graph_structure'])}维")
print(f"节点特征: {len(grouped['node'])}维")
```

## 特征维度说明

| 类别 | 维度 | 说明 |
|------|------|------|
| 图结构特征 | 15维 | 节点数、边数、密度、度数分布等 |
| 节点特征 | 40维 | 节点类型、关键进程频率等 |
| 边特征 | 25维 | 边类型、跨类型交互等 |
| 序列特征 | 30维 | 时间跨度、操作间隔等 |
| 语义特征 | 20维 | 攻击模式得分、敏感文件访问等 |
| **总计** | **130维** | |

## 运行测试

```bash
cd PythonIDS
python -m PIDS.feature_extractor
```

## 启动API服务

```bash
# 安装依赖
cd PythonIDS/PIDS
pip install -r requirements.txt

# 启动服务 (端口7890)
cd PythonIDS
python -m PIDS.pids_feature_api
```

**API文档**: http://localhost:7890/docs

### API端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/pids/health` | GET | 健康检查 |
| `/api/pids/features/extract` | POST | 提取特征向量 |
| `/api/pids/features/{threat_id}` | GET | 获取已存储的特征 |
| `/api/pids/feature-names` | GET | 获取特征名称列表 |

## 依赖

- Python 3.8+
- numpy
- fastapi
- uvicorn
