# -*- coding: utf-8 -*-
"""
PIDS 特征提取 API 服务
======================

提供 HTTP API 接口，供后端 Java 调用。

启动方式:
    python -m PIDS.api_server

API 端点:
    POST /api/pids/features/extract - 提取特征向量
    GET  /api/pids/features/{threat_id} - 获取已存储的特征
    GET  /api/pids/health - 健康检查
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

import numpy as np
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PIDS.feature_extraction import FeatureExtractor
from PIDS.behavior_modeling import BehaviorModeler, ModelConfig, DetectionResult, EnsembleDetector, VAEClassifier
from PIDS.evaluation import PerformanceEvaluator

# ============ 配置 ============
API_HOST = "0.0.0.0"
API_PORT = 7890
LOG_LEVEL = "INFO"

# ============ 日志配置 ============
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("PIDS-API")

# ============ 数据模型 ============
class GraphNode(BaseModel):
    """图谱节点"""
    id: str
    label: str
    type: Optional[str] = "other"
    category: Optional[int] = 0
    timestamp: Optional[str] = None
    cmdline: Optional[str] = None

class GraphEdge(BaseModel):
    """图谱边"""
    source: str
    target: str
    label: Optional[str] = "连接"

class GraphData(BaseModel):
    """溯源图数据"""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    threatId: Optional[str] = None
    attackType: Optional[str] = None

class FeatureRequest(BaseModel):
    """特征提取请求"""
    graphData: GraphData
    threatId: Optional[str] = None
    saveToDb: Optional[bool] = False

class FeatureGroupDetail(BaseModel):
    """特征组详情"""
    current: float  # 当前均值
    baseline: float  # 基线值
    topFeatures: List[str]  # 显著特征
    dimensions: List[Dict[str, Any]]  # 各维度详情

class FeatureResponse(BaseModel):
    """特征提取响应 - 增强版"""
    success: bool
    threatId: Optional[str] = None
    # 原始130维向量，供前端点阵图渲染
    rawVector: List[float]
    featureVector: List[float]  # 兼容旧版
    featureGroups: Dict[str, List[float]]
    # 增强版分组信息，包含基线对比
    groups: Optional[Dict[str, FeatureGroupDetail]] = None
    featureNames: List[str]
    # 130维特征详情（用于悬浮显示）
    featureDimensions: Optional[List[Dict[str, Any]]] = None
    extractTime: str
    message: Optional[str] = None

class HealthResponse(BaseModel):
    """健康检查响应"""
    status: str
    version: str
    timestamp: str

# ============ 创建应用 ============
app = FastAPI(
    title="PIDS 特征提取 API",
    description="御链天鉴 - PIDS因果溯源图特征提取服务",
    version="1.0.0"
)

# 跨域配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 特征提取器实例
extractor = FeatureExtractor()

# 行为建模器实例
modeler = BehaviorModeler()

# 性能评估器实例
evaluator = PerformanceEvaluator()

# ===== L1/L2 双层检测模型 =====
l1_detector: Optional[EnsembleDetector] = None
l2_detector: Optional[VAEClassifier] = None

def _load_trained_models():
    """启动时加载训练好的L1/L2模型（加载失败不阻塞启动）"""
    global l1_detector, l2_detector
    model_dir = os.path.join(os.path.dirname(__file__), 'behavior_modeling', 'models')
    
    # L1 集成检测器
    l1_path = os.path.join(model_dir, 'ensemble_v1.0.pkl')
    if os.path.exists(l1_path):
        try:
            l1_detector = EnsembleDetector()
            l1_detector.load(l1_path)
            logger.info(f"✅ L1 集成检测器已加载: {l1_path}")
        except Exception as e:
            logger.warning(f"⚠️ L1 模型加载失败(可能缺少xgboost等依赖): {e}")
            l1_detector = None
    else:
        logger.warning(f"⚠️ L1 模型不存在: {l1_path}")
    
    # L2 VAE+MLP
    l2_path = os.path.join(model_dir, 'vae_classifier_v1.0.pt')
    if os.path.exists(l2_path):
        try:
            l2_detector = VAEClassifier(input_dim=130, device='cpu')
            l2_detector.load(l2_path)
            logger.info(f"✅ L2 VAE+MLP已加载: {l2_path}")
        except Exception as e:
            logger.warning(f"⚠️ L2 模型加载失败(可能缺少torch等依赖): {e}")
            l2_detector = None
    else:
        logger.warning(f"⚠️ L2 模型不存在: {l2_path}")

_load_trained_models()

# 特征缓存（简易存储，后续可替换为数据库）
feature_cache: Dict[str, Dict] = {}

# ============ 异常处理器 ============
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """处理422验证错误，打印详细错误信息"""
    logger.error(f"❌ 请求验证失败:")
    logger.error(f"   URL: {request.url}")
    logger.error(f"   Method: {request.method}")
    logger.error(f"   错误详情: {exc.errors()}")
    try:
        body = await request.body()
        logger.error(f"   请求体: {body.decode('utf-8')[:500]}")
    except:
        pass
    
    return JSONResponse(
        status_code=422,
        content={
            "detail": exc.errors(),
            "body": str(exc.body) if hasattr(exc, 'body') else None
        }
    )

# ============ API 端点 ============

@app.get("/api/pids/health", response_model=HealthResponse)
async def health_check():
    """健康检查"""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.now().isoformat()
    )

# 特征维度配置（用于前端悬浮显示）
FEATURE_DIMENSION_CONFIG = {
    "graphStructure": {
        "name": "图结构特征",
        "baseline": 1.0,
        "dims": [
            {"idx": 0, "name": "node_count", "label": "节点数量", "unit": "个"},
            {"idx": 1, "name": "edge_count", "label": "边数量", "unit": "条"},
            {"idx": 2, "name": "graph_density", "label": "图密度", "unit": ""},
            {"idx": 3, "name": "avg_degree", "label": "平均度数", "unit": ""},
            {"idx": 4, "name": "max_degree", "label": "最大度数", "unit": ""},
            {"idx": 5, "name": "min_degree", "label": "最小度数", "unit": ""},
            {"idx": 6, "name": "max_path_length", "label": "最长路径", "unit": ""},
            {"idx": 7, "name": "avg_path_length", "label": "平均路径", "unit": ""},
            {"idx": 8, "name": "connected_components", "label": "连通分量数", "unit": "个"},
            {"idx": 9, "name": "clustering_coefficient", "label": "聚类系数", "unit": ""},
            {"idx": 10, "name": "graph_diameter", "label": "图直径", "unit": ""},
            {"idx": 11, "name": "graph_radius", "label": "图半径", "unit": ""},
            {"idx": 12, "name": "node_edge_ratio", "label": "节点边比率", "unit": ""},
            {"idx": 13, "name": "leaf_node_ratio", "label": "叶子节点比例", "unit": "%"},
            {"idx": 14, "name": "hub_node_ratio", "label": "枢纽节点比例", "unit": "%"}
        ]
    },
    "node": {
        "name": "节点特征",
        "baseline": 1.0,
        "dims": [
            {"idx": 15, "name": "process_node_count", "label": "进程节点数", "unit": "个"},
            {"idx": 16, "name": "file_node_count", "label": "文件节点数", "unit": "个"},
            {"idx": 17, "name": "socket_node_count", "label": "套接字节点数", "unit": "个"},
            {"idx": 18, "name": "attacker_node_count", "label": "攻击者节点数", "unit": "个"},
            {"idx": 19, "name": "other_node_count", "label": "其他节点数", "unit": "个"}
        ]
    },
    "edge": {
        "name": "边特征",
        "baseline": 1.0,
        "dims": [
            {"idx": 55, "name": "exec_edge_count", "label": "执行边数", "unit": "条"},
            {"idx": 56, "name": "read_edge_count", "label": "读取边数", "unit": "条"},
            {"idx": 57, "name": "write_edge_count", "label": "写入边数", "unit": "条"},
            {"idx": 58, "name": "connect_edge_count", "label": "连接边数", "unit": "条"},
            {"idx": 59, "name": "fork_edge_count", "label": "Fork边数", "unit": "条"},
            {"idx": 68, "name": "cross_type_ratio", "label": "跨层调用频率", "unit": "%"}
        ]
    },
    "sequence": {
        "name": "序列特征",
        "baseline": 1.0,
        "dims": [
            {"idx": 80, "name": "time_span_seconds", "label": "时间跨度(秒)", "unit": "s"},
            {"idx": 83, "name": "interval_mean", "label": "平均间隔", "unit": "s"},
            {"idx": 84, "name": "interval_std", "label": "间隔方差", "unit": "s"},
            {"idx": 90, "name": "burst_count", "label": "爆发次数", "unit": "次"},
            {"idx": 92, "name": "operation_entropy", "label": "操作熵", "unit": ""},
            {"idx": 98, "name": "periodic_pattern_score", "label": "周期性评分", "unit": ""}
        ]
    },
    "semantic": {
        "name": "语义特征",
        "baseline": 1.0,
        "dims": [
            {"idx": 110, "name": "sql_injection_score", "label": "SQL注入得分", "unit": ""},
            {"idx": 111, "name": "xss_score", "label": "XSS得分", "unit": ""},
            {"idx": 112, "name": "webshell_score", "label": "WebShell得分", "unit": ""},
            {"idx": 114, "name": "rce_score", "label": "RCE得分", "unit": ""},
            {"idx": 115, "name": "privilege_escalation_score", "label": "提权得分", "unit": ""},
            {"idx": 117, "name": "overall_threat_score", "label": "综合威胁得分", "unit": ""},
            {"idx": 119, "name": "anomaly_score", "label": "异常得分", "unit": ""}
        ]
    }
}

def build_feature_dimensions(features: list, feature_names: list) -> list:
    """构建130维特征详情列表，用于前端点阵悬浮显示"""
    dimensions = []
    for i, (value, name) in enumerate(zip(features, feature_names)):
        # 确定所属组
        if i < 15:
            group = "graphStructure"
        elif i < 55:
            group = "node"
        elif i < 80:
            group = "edge"
        elif i < 110:
            group = "sequence"
        else:
            group = "semantic"
        
        dimensions.append({
            "idx": i,
            "name": name,
            "value": float(value),
            "group": group,
            "label": f"dim_{i}: {name}"
        })
    return dimensions

def build_groups_detail(grouped: dict, features: list, feature_names: list = None) -> dict:
    """构建增强版分组详情 — 基于真实数据计算异常强度
    
    current: 该组所有维度中非零值的比例（0~1），反映该组特征的活跃程度
    baseline: 固定为 0，代表"无异常"
    
    前端直接用 current 值渲染百分比（如 current=0.35 → 显示 35%）
    """
    groups_detail = {}
    group_mapping = {
        "graph_structure": "graphStructure",
        "node": "node",
        "edge": "edge",
        "sequence": "sequence",
        "semantic": "semantic"
    }
    
    # 组在130维向量中的起始偏移
    group_offsets = {
        "graph_structure": 0,
        "node": 15,
        "edge": 55,
        "sequence": 80,
        "semantic": 110
    }
    
    for internal_key, external_key in group_mapping.items():
        values = grouped.get(internal_key, [])
        if hasattr(values, 'tolist'):
            values = values.tolist()
        
        config = FEATURE_DIMENSION_CONFIG.get(external_key, {})
        dims_config = config.get("dims", [])
        offset = group_offsets.get(internal_key, 0)
        
        # 收集代表性维度的真实值
        key_values = []
        for d in dims_config:
            global_idx = d["idx"]
            local_idx = global_idx - offset
            if 0 <= local_idx < len(values):
                key_values.append(float(values[local_idx]))
            else:
                key_values.append(0.0)
        
        # current = 代表性维度的均值（真实计算值）
        current = float(np.mean(key_values)) if key_values else 0.0
        
        # baseline = 该组所有维度均值（作为整体参考水平）
        all_mean = float(np.mean(values)) if values else 0.0
        baseline = all_mean
        
        # 找出值最大的3个代表性维度
        top_features = []
        if dims_config and key_values:
            dim_vals = [(d["name"], abs(key_values[i])) for i, d in enumerate(dims_config)]
            sorted_dims = sorted(dim_vals, key=lambda x: x[1], reverse=True)[:3]
            top_features = [d[0] for d in sorted_dims]
        
        # 构建维度详情（全部维度，使用真实特征名称）
        dimensions = []
        for i, v in enumerate(values):
            global_idx = offset + i
            if feature_names and global_idx < len(feature_names):
                real_name = feature_names[global_idx]
            else:
                real_name = f"dim_{global_idx}"
            dimensions.append({
                "name": real_name,
                "label": real_name,
                "value": float(v),
                "unit": ""
            })
        
        groups_detail[external_key] = FeatureGroupDetail(
            current=current,
            baseline=baseline,
            topFeatures=top_features,
            dimensions=dimensions
        )
    
    return groups_detail

@app.post("/api/pids/features/extract", response_model=FeatureResponse)
async def extract_features(request: FeatureRequest):
    """
    提取溯源图特征
    
    接收溯源图数据，返回130维特征向量
    增强版返回包含 rawVector 和详细维度信息
    """
    try:
        logger.info(f"📥 收到特征提取请求 | threatId: {request.threatId}")
        logger.info(f"📊 图数据 | 节点数: {len(request.graphData.nodes)} | 边数: {len(request.graphData.edges)}")
        
        # 转换为特征提取器需要的格式
        graph_data = {
            "nodes": [node.dict() for node in request.graphData.nodes],
            "edges": [edge.dict() for edge in request.graphData.edges]
        }
        
        logger.info(f"📊 开始提取特征 | 节点数: {len(graph_data['nodes'])} | 边数: {len(graph_data['edges'])}")
        
        # 提取特征
        features = extractor.extract(graph_data)
        grouped = extractor.extract_grouped(graph_data)
        feature_names = extractor.get_feature_names()
        
        # 生成threatId
        threat_id = request.threatId or request.graphData.threatId or f"threat_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # 构建130维特征详情
        feature_dimensions = build_feature_dimensions(features.tolist(), feature_names)
        
        # 构建增强版分组详情
        groups_detail = build_groups_detail(grouped, features.tolist(), feature_names)
        
        # 构建响应
        response = FeatureResponse(
            success=True,
            threatId=threat_id,
            # 增强: 130维原始向量
            rawVector=features.tolist(),
            featureVector=features.tolist(),
            featureGroups={
                "graphStructure": grouped["graph_structure"].tolist(),
                "node": grouped["node"].tolist(),
                "edge": grouped["edge"].tolist(),
                "sequence": grouped["sequence"].tolist(),
                "semantic": grouped["semantic"].tolist()
            },
            # 增强: 分组详情含基线对比
            groups=groups_detail,
            featureNames=feature_names,
            # 增强: 130维特征详情
            featureDimensions=feature_dimensions,
            extractTime=datetime.now().isoformat(),
            message="特征提取成功"
        )
        
        # 缓存特征
        if request.saveToDb:
            feature_cache[threat_id] = {
                "threatId": threat_id,
                "rawVector": features.tolist(),
                "featureVector": features.tolist(),
                "featureGroups": response.featureGroups,
                "extractTime": response.extractTime,
                "attackType": request.graphData.attackType
            }
            logger.info(f"💾 特征已缓存 | threatId: {threat_id}")
        
        logger.info(f"✅ 特征提取完成 | threatId: {threat_id} | 维度: {len(features)}")
        return response
        
    except Exception as e:
        logger.error(f"❌ 特征提取失败: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"特征提取失败: {str(e)}")

@app.get("/api/pids/features/{threat_id}")
async def get_features(threat_id: str):
    """获取已存储的特征"""
    if threat_id not in feature_cache:
        raise HTTPException(status_code=404, detail=f"未找到特征: {threat_id}")
    
    return {
        "success": True,
        **feature_cache[threat_id]
    }

@app.get("/api/pids/features")
async def list_features():
    """列出所有已存储的特征"""
    return {
        "success": True,
        "count": len(feature_cache),
        "features": [
            {
                "threatId": tid,
                "attackType": data.get("attackType"),
                "extractTime": data.get("extractTime")
            }
            for tid, data in feature_cache.items()
        ]
    }

@app.delete("/api/pids/features/{threat_id}")
async def delete_features(threat_id: str):
    """删除已存储的特征"""
    if threat_id in feature_cache:
        del feature_cache[threat_id]
        return {"success": True, "message": f"已删除特征: {threat_id}"}
    raise HTTPException(status_code=404, detail=f"未找到特征: {threat_id}")

@app.get("/api/pids/feature-names")
async def get_feature_names():
    """获取特征名称列表"""
    return {
        "success": True,
        "count": len(extractor.get_feature_names()),
        "names": extractor.get_feature_names(),
        "groups": {
            "graphStructure": {"start": 0, "end": 15, "count": 15},
            "node": {"start": 15, "end": 55, "count": 40},
            "edge": {"start": 55, "end": 80, "count": 25},
            "sequence": {"start": 80, "end": 110, "count": 30},
            "semantic": {"start": 110, "end": 130, "count": 20}
        }
    }

# ============ 双层检测 API (L1+L2) ============

class DetectV2Request(BaseModel):
    """双层检测请求"""
    graphData: Optional[GraphData] = None
    featureVector: Optional[List[float]] = None
    threatId: Optional[str] = None
    useL2: bool = True

class DetectV2Response(BaseModel):
    """双层检测响应"""
    success: bool
    threatId: str
    prediction: str
    anomalyScore: float
    l1Score: Optional[float] = None
    l2Score: Optional[float] = None
    confidence: float
    detectionLayer: str
    detectionTimeMs: int
    message: Optional[str] = None

@app.post("/api/pids/detect", response_model=DetectV2Response)
async def detect_v2(request: DetectV2Request):
    """
    双层检测端点 (L1快速筛选 + L2深度确认)
    
    接收溯源图数据或特征向量，返回检测结果
    """
    import time as _time
    t0 = _time.time()
    
    threat_id = request.threatId or f"threat_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    # Step 1: 获取特征向量
    if request.featureVector:
        features = np.array(request.featureVector).reshape(1, -1)
    elif request.graphData:
        graph_data = {
            "nodes": [node.dict() for node in request.graphData.nodes],
            "edges": [edge.dict() for edge in request.graphData.edges]
        }
        feat_vec = extractor.extract(graph_data)
        features = feat_vec.reshape(1, -1)
    else:
        raise HTTPException(status_code=400, detail="需要提供 graphData 或 featureVector")
    
    l1_score = None
    l2_score = None
    detection_layer = "none"
    
    # Step 2: L1 快速筛选
    if l1_detector and l1_detector.is_fitted:
        l1_scores = l1_detector.predict_scores(features)
        l1_score = float(l1_scores[0])
        l1_pred = l1_detector.predict(features)[0]
        detection_layer = "L1"
        
        # L1 判定为正常 → 直接放行
        if l1_pred == 0 and not request.useL2:
            elapsed = int((_time.time() - t0) * 1000)
            return DetectV2Response(
                success=True, threatId=threat_id,
                prediction="normal", anomalyScore=l1_score,
                l1Score=l1_score, confidence=1 - l1_score,
                detectionLayer="L1", detectionTimeMs=elapsed,
                message="L1判定正常"
            )
    
    # Step 3: L2 深度确认
    if request.useL2 and l2_detector and l2_detector.is_fitted:
        l2_scores = l2_detector.predict_scores(features)
        l2_score = float(l2_scores[0])
        l2_pred = l2_detector.predict(features)[0]
        detection_layer = "L2"
        
        final_score = l2_score
        final_pred = "anomaly" if l2_pred == 1 else "normal"
    elif l1_score is not None:
        final_score = l1_score
        final_pred = "anomaly" if l1_score >= (l1_detector.threshold if l1_detector else 0.5) else "normal"
    else:
        final_score = 0.0
        final_pred = "unknown"
        detection_layer = "none"
    
    elapsed = int((_time.time() - t0) * 1000)
    confidence = abs(final_score - 0.5) * 2
    
    logger.info(f"🔍 检测完成 | {threat_id} | {final_pred} | "
                f"L1={f'{l1_score:.3f}' if l1_score is not None else 'N/A'} | "
                f"L2={f'{l2_score:.3f}' if l2_score is not None else 'N/A'} | {elapsed}ms")
    
    return DetectV2Response(
        success=True, threatId=threat_id,
        prediction=final_pred, anomalyScore=final_score,
        l1Score=l1_score, l2Score=l2_score,
        confidence=confidence, detectionLayer=detection_layer,
        detectionTimeMs=elapsed,
        message=f"{detection_layer}检测完成"
    )

@app.get("/api/pids/detect/status")
async def detect_status():
    """获取检测模型状态"""
    return {
        "success": True,
        "l1": {"loaded": l1_detector is not None and l1_detector.is_fitted,
               "type": "EnsembleDetector (IF+LOF+OCSVM+XGBoost)"},
        "l2": {"loaded": l2_detector is not None and l2_detector.is_fitted,
               "type": "VAEClassifier (VAE+MLP)"},
    }

# ============ 行为建模 API (旧版兼容) ============

class TrainRequest(BaseModel):
    """训练请求"""
    modelType: str = "isolation_forest"
    modelName: str = "pids_anomaly_detector"
    version: str = "1.0"
    contamination: float = 0.1
    features: Optional[List[List[float]]] = None

class DetectRequest(BaseModel):
    """检测请求"""
    featureVector: List[float]
    threatId: Optional[str] = None
    threshold: float = 0.5

@app.get("/api/pids/model/info")
async def get_model_info():
    """获取当前模型信息"""
    return {
        "success": True,
        **modeler.get_model_info()
    }

@app.post("/api/pids/model/train")
async def train_model(request: TrainRequest):
    """训练异常检测模型"""
    try:
        # 如果没有提供特征，使用缓存的特征
        if request.features:
            features = np.array(request.features)
        elif feature_cache:
            features = np.array([f["featureVector"] for f in feature_cache.values()])
        else:
            raise HTTPException(status_code=400, detail="没有可用的训练数据")
        
        config = ModelConfig(
            model_type=request.modelType,
            model_name=request.modelName,
            version=request.version,
            contamination=request.contamination
        )
        
        result = modeler.train(features, config)
        modeler.save_model()
        
        return {
            "success": True,
            "message": "模型训练完成",
            **result
        }
    except Exception as e:
        logger.error(f"模型训练失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"训练失败: {str(e)}")

@app.post("/api/pids/model/detect")
async def detect_anomaly(request: DetectRequest):
    """执行异常检测"""
    try:
        if not modeler.is_fitted:
            raise HTTPException(status_code=400, detail="模型未训练")
        
        result = modeler.predict(
            np.array(request.featureVector),
            request.threatId,
            request.threshold
        )
        
        return {
            "success": True,
            "threatId": result.threat_id,
            "prediction": result.prediction,
            "anomalyScore": result.anomaly_score,
            "confidence": result.confidence,
            "featureHighlights": result.feature_highlights,
            "detectionTimeMs": result.detection_time_ms,
            "modelName": result.model_name
        }
    except Exception as e:
        logger.error(f"异常检测失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"检测失败: {str(e)}")

@app.get("/api/pids/model/list")
async def list_models():
    """列出所有保存的模型"""
    import glob
    model_files = glob.glob(os.path.join(modeler.model_dir, "*.pkl"))
    return {
        "success": True,
        "count": len(model_files),
        "models": [os.path.basename(f) for f in model_files]
    }

@app.post("/api/pids/model/load/{filename}")
async def load_model(filename: str):
    """加载指定模型"""
    success = modeler.load_model(filename)
    if success:
        return {"success": True, "message": f"模型已加载: {filename}"}
    raise HTTPException(status_code=404, detail=f"模型文件不存在: {filename}")

# ============ 性能评估 API ============

class EvaluateRequest(BaseModel):
    """评估请求"""
    yTrue: List[int]
    yPred: List[int]
    yScores: Optional[List[float]] = None
    detectionTimes: Optional[List[float]] = None
    attackTypes: Optional[List[str]] = None

@app.post("/api/pids/evaluate")
async def evaluate_performance(request: EvaluateRequest):
    """评估模型性能"""
    try:
        metrics = evaluator.evaluate(
            y_true=np.array(request.yTrue),
            y_pred=np.array(request.yPred),
            y_scores=np.array(request.yScores) if request.yScores else None,
            detection_times=request.detectionTimes,
            attack_types=request.attackTypes
        )
        
        return {
            "success": True,
            "metrics": {
                "accuracy": metrics.accuracy,
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1Score": metrics.f1_score,
                "aucRoc": metrics.auc_roc,
                "confusionMatrix": metrics.confusion_matrix,
                "truePositives": metrics.true_positives,
                "trueNegatives": metrics.true_negatives,
                "falsePositives": metrics.false_positives,
                "falseNegatives": metrics.false_negatives,
                "totalSamples": metrics.total_samples,
                "detectionTimeMeanMs": metrics.detection_time_mean_ms
            }
        }
    except Exception as e:
        logger.error(f"评估失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"评估失败: {str(e)}")

@app.get("/api/pids/evaluate/summary")
async def get_evaluation_summary():
    """获取评估摘要"""
    return {
        "success": True,
        **evaluator.get_summary()
    }

@app.get("/api/pids/evaluate/report")
async def get_evaluation_report():
    """获取评估报告"""
    return {
        "success": True,
        "report": evaluator.generate_report()
    }

# ============ 启动服务 ============
def main():
    """启动API服务"""
    print("=" * 60)
    print("🚀 PIDS 特征提取 API 服务")
    print("=" * 60)
    print(f"📡 服务地址: http://{API_HOST}:{API_PORT}")
    print(f"📖 API文档: http://localhost:{API_PORT}/docs")
    print("=" * 60)
    
    uvicorn.run(
        "PIDS.pids_feature_api:app",
        host=API_HOST,
        port=API_PORT,
        reload=True,
        log_level=LOG_LEVEL.lower()
    )

if __name__ == "__main__":
    main()
