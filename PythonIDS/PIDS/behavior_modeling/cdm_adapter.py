# -*- coding: utf-8 -*-
"""
DARPA TC CDM18 → PIDS 溯源图适配器
====================================

将 DARPA Transparent Computing E3 数据集 (CDM18 JSON格式)
转换为 PIDS FeatureExtractor 所需的 {nodes, edges} 格式。

数据集路径: /home/test/YuLianTianJian_Core/data/DARPATC E3数据集/
文件格式: 每行一个JSON对象 (JSONL)
CDM版本: 18
数据源: SOURCE_LINUX_THEIA

用法:
    python -m PIDS.behavior_modeling.cdm_adapter \
        --data_dir "/home/test/YuLianTianJian_Core/data/DARPATC E3数据集" \
        --output_dir "./PIDS/data" \
        --window_minutes 5
"""

import os
import sys
import json
import glob
import time
import logging
import argparse
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# CDM18 实体类型前缀
CDM_PREFIX = "com.bbn.tc.schema.avro.cdm18."

# CDM Event 类型 → 我们的边标签映射
EVENT_TYPE_MAP = {
    "EVENT_READ": "读取",
    "EVENT_WRITE": "写入",
    "EVENT_EXECUTE": "执行",
    "EVENT_FORK": "创建进程",
    "EVENT_CLONE": "创建进程",
    "EVENT_OPEN": "打开",
    "EVENT_CLOSE": "关闭",
    "EVENT_CONNECT": "连接",
    "EVENT_ACCEPT": "接受连接",
    "EVENT_SENDTO": "发送数据",
    "EVENT_RECVFROM": "接收数据",
    "EVENT_SENDMSG": "发送消息",
    "EVENT_RECVMSG": "接收消息",
    "EVENT_MMAP": "内存映射",
    "EVENT_RENAME": "重命名",
    "EVENT_UNLINK": "删除",
    "EVENT_LINK": "链接",
    "EVENT_CHMOD": "修改权限",
    "EVENT_TRUNCATE": "截断",
    "EVENT_MODIFY_FILE_ATTRIBUTES": "修改属性",
    "EVENT_SIGNAL": "信号",
    "EVENT_CHANGE_PRINCIPAL": "切换用户",
    "EVENT_LOGIN": "登录",
    "EVENT_LOGOUT": "登出",
    "EVENT_BOOT": "启动",
    "EVENT_MOUNT": "挂载",
    "EVENT_LOADLIBRARY": "加载库",
    "EVENT_CREATE_OBJECT": "创建对象",
    "EVENT_OTHER": "其他",
}

# 攻击相关的高危事件类型
ATTACK_RELEVANT_EVENTS = {
    "EVENT_EXECUTE", "EVENT_WRITE", "EVENT_READ", "EVENT_CONNECT",
    "EVENT_SENDTO", "EVENT_RECVFROM", "EVENT_SENDMSG", "EVENT_RECVMSG",
    "EVENT_FORK", "EVENT_CLONE", "EVENT_CHMOD", "EVENT_CHANGE_PRINCIPAL",
    "EVENT_RENAME", "EVENT_UNLINK", "EVENT_LINK",
}

# 空UUID（忽略）
NULL_UUID = "00000000-0000-0000-0000-000000000000"


class CDMAdapter:
    """
    将 CDM18 JSON 数据转换为 PIDS 溯源图格式
    """

    def __init__(self, window_minutes: int = 5, max_nodes_per_graph: int = 200):
        """
        Args:
            window_minutes: 时间窗口大小（分钟），用于切割子图
            max_nodes_per_graph: 每个子图最大节点数
        """
        self.window_ns = window_minutes * 60 * 1_000_000_000  # 转为纳秒
        self.max_nodes = max_nodes_per_graph

        # 全局实体注册表
        self.subjects: Dict[str, Dict] = {}      # UUID → Subject(进程)信息
        self.file_objects: Dict[str, Dict] = {}   # UUID → FileObject信息
        self.net_objects: Dict[str, Dict] = {}    # UUID → NetFlowObject信息
        self.principals: Dict[str, Dict] = {}     # UUID → Principal(用户)信息
        self.hosts: Dict[str, Dict] = {}          # UUID → Host信息

        # 事件缓冲区
        self.events: List[Dict] = []

        # 统计
        self.stats = defaultdict(int)

    def parse_file(self, filepath: str, max_lines: int = 0):
        """
        解析单个CDM JSON文件，提取实体和事件

        Args:
            filepath: JSON文件路径
            max_lines: 最大读取行数（0=全部）
        """
        logger.info(f"解析文件: {filepath}")
        line_count = 0

        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                    self._process_record(record)
                    line_count += 1

                    if line_count % 500000 == 0:
                        logger.info(f"  已处理 {line_count:,} 行 | "
                                    f"进程={len(self.subjects):,} 文件={len(self.file_objects):,} "
                                    f"网络={len(self.net_objects):,} 事件={len(self.events):,}")

                    if max_lines > 0 and line_count >= max_lines:
                        break

                except json.JSONDecodeError:
                    self.stats['json_errors'] += 1
                except Exception as e:
                    self.stats['parse_errors'] += 1
                    if self.stats['parse_errors'] <= 5:
                        logger.warning(f"  解析错误: {e}")

        logger.info(f"文件解析完成: {line_count:,} 行 | "
                    f"进程={len(self.subjects):,} 文件={len(self.file_objects):,} "
                    f"网络={len(self.net_objects):,} 事件={len(self.events):,}")

    def _process_record(self, record: Dict):
        """处理单条CDM记录"""
        datum = record.get("datum", {})

        for key, value in datum.items():
            entity_type = key.replace(CDM_PREFIX, "")

            if entity_type == "Subject":
                self._register_subject(value)
            elif entity_type == "FileObject":
                self._register_file_object(value)
            elif entity_type == "NetFlowObject":
                self._register_net_object(value)
            elif entity_type == "Event":
                self._register_event(value)
            elif entity_type == "Principal":
                self._register_principal(value)
            elif entity_type == "Host":
                self._register_host(value)
            else:
                self.stats[f'skip_{entity_type}'] += 1

    def _register_subject(self, data: Dict):
        """注册进程实体"""
        uuid = data.get("uuid", "")
        if not uuid or uuid == NULL_UUID:
            return

        props = data.get("properties", {})
        prop_map = props.get("map", {}) if isinstance(props, dict) else {}

        path = prop_map.get("path", "")
        cmdline = data.get("cmdLine", {})
        if isinstance(cmdline, dict):
            cmdline = cmdline.get("string", "N/A")

        self.subjects[uuid] = {
            "uuid": uuid,
            "type": data.get("type", "SUBJECT_PROCESS"),
            "pid": data.get("cid", 0),
            "path": path,
            "cmdline": cmdline if cmdline != "N/A" else path,
            "parent_uuid": self._extract_uuid(data.get("parentSubject")),
            "start_time": data.get("startTimestampNanos", 0),
            "ppid": prop_map.get("ppid", ""),
            "tgid": prop_map.get("tgid", ""),
        }
        self.stats['subjects'] += 1

    def _register_file_object(self, data: Dict):
        """注册文件实体"""
        uuid = data.get("uuid", "")
        if not uuid or uuid == NULL_UUID:
            return

        props = data.get("properties", {})
        prop_map = props.get("map", {}) if isinstance(props, dict) else {}

        # 文件路径可能在 baseObject.properties.map.path 或直接在 properties
        base_obj = data.get("baseObject", {})
        base_props = base_obj.get("properties", {}) if isinstance(base_obj, dict) else {}
        base_map = base_props.get("map", {}) if isinstance(base_props, dict) else {}

        file_path = base_map.get("path", "") or prop_map.get("filename", "") or prop_map.get("path", "")

        self.file_objects[uuid] = {
            "uuid": uuid,
            "path": file_path,
            "type": data.get("type", "FILE_OBJECT_FILE"),
        }
        self.stats['file_objects'] += 1

    def _register_net_object(self, data: Dict):
        """注册网络连接实体"""
        uuid = data.get("uuid", "")
        if not uuid or uuid == NULL_UUID:
            return

        self.net_objects[uuid] = {
            "uuid": uuid,
            "src_addr": data.get("srcAddress", ""),
            "src_port": data.get("srcPort", 0),
            "dst_addr": data.get("dstAddress", ""),
            "dst_port": data.get("dstPort", 0),
        }
        self.stats['net_objects'] += 1

    def _register_principal(self, data: Dict):
        """注册用户实体"""
        uuid = data.get("uuid", "")
        if not uuid:
            return
        self.principals[uuid] = {
            "uuid": uuid,
            "type": data.get("type", ""),
            "userId": data.get("userId", ""),
            "username": data.get("username", ""),
        }
        self.stats['principals'] += 1

    def _register_host(self, data: Dict):
        """注册主机实体"""
        uuid = data.get("uuid", "")
        if not uuid:
            return
        interfaces = data.get("interfaces", [])
        ips = []
        for iface in interfaces:
            ips.extend(iface.get("ipAddresses", []))
        self.hosts[uuid] = {
            "uuid": uuid,
            "hostname": data.get("hostName", ""),
            "ips": ips,
        }
        self.stats['hosts'] += 1

    def _register_event(self, data: Dict):
        """注册事件（边）"""
        event_type = data.get("type", "")

        # 只保留攻击相关事件，过滤掉噪声
        if event_type not in ATTACK_RELEVANT_EVENTS:
            self.stats['events_filtered'] += 1
            return

        subject_uuid = self._extract_uuid(data.get("subject"))
        object_uuid = self._extract_uuid(data.get("predicateObject"))
        timestamp = data.get("timestampNanos", 0)

        # 过滤无效事件
        if not subject_uuid or subject_uuid == NULL_UUID:
            return
        if not object_uuid or object_uuid == NULL_UUID:
            return

        self.events.append({
            "uuid": data.get("uuid", ""),
            "type": event_type,
            "subject": subject_uuid,
            "object": object_uuid,
            "object2": self._extract_uuid(data.get("predicateObject2")),
            "timestamp": timestamp,
            "name": data.get("name"),
            "size": data.get("size"),
        })
        self.stats['events'] += 1

    def _extract_uuid(self, field) -> str:
        """从CDM UUID字段中提取UUID字符串"""
        if field is None:
            return ""
        if isinstance(field, str):
            return field
        if isinstance(field, dict):
            return field.get(f"{CDM_PREFIX}UUID", "")
        return ""

    def build_subgraphs(self) -> List[Dict[str, Any]]:
        """
        按时间窗口切割事件流，构建溯源子图列表

        Returns:
            子图列表，每个子图格式: {"nodes": [...], "edges": [...], "metadata": {...}}
        """
        if not self.events:
            logger.warning("没有事件数据，无法构建子图")
            return []

        # 按时间排序
        self.events.sort(key=lambda e: e["timestamp"])

        min_ts = self.events[0]["timestamp"]
        max_ts = self.events[-1]["timestamp"]
        total_windows = (max_ts - min_ts) // self.window_ns + 1

        logger.info(f"时间范围: {self._ns_to_datetime(min_ts)} ~ {self._ns_to_datetime(max_ts)}")
        logger.info(f"预计窗口数: {total_windows}")

        subgraphs = []
        window_start = min_ts
        event_idx = 0

        while window_start <= max_ts:
            window_end = window_start + self.window_ns
            window_events = []

            # 收集当前窗口内的事件
            while event_idx < len(self.events) and self.events[event_idx]["timestamp"] < window_end:
                if self.events[event_idx]["timestamp"] >= window_start:
                    window_events.append(self.events[event_idx])
                event_idx += 1

            if len(window_events) >= 3:  # 至少3个事件才构建子图
                subgraph = self._events_to_graph(window_events, window_start, window_end)
                if subgraph and len(subgraph["nodes"]) >= 3:
                    subgraphs.append(subgraph)

            window_start = window_end

        logger.info(f"构建了 {len(subgraphs)} 个子图")
        return subgraphs

    def _events_to_graph(self, events: List[Dict], window_start: int, window_end: int) -> Optional[Dict]:
        """
        将一组事件转换为 PIDS 溯源图格式

        Returns:
            {"nodes": [...], "edges": [...], "metadata": {...}}
        """
        node_set = set()
        nodes = []
        edges = []

        for event in events:
            src_uuid = event["subject"]
            dst_uuid = event["object"]
            event_type = event["type"]

            # 添加源节点（进程）
            if src_uuid not in node_set:
                node_set.add(src_uuid)
                node_info = self._resolve_node(src_uuid)
                if node_info:
                    nodes.append(node_info)

            # 添加目标节点（进程/文件/网络）
            if dst_uuid not in node_set:
                node_set.add(dst_uuid)
                node_info = self._resolve_node(dst_uuid)
                if node_info:
                    nodes.append(node_info)

            # 添加边
            label = EVENT_TYPE_MAP.get(event_type, event_type)
            edges.append({
                "source": src_uuid,
                "target": dst_uuid,
                "label": label,
                "timestamp": event["timestamp"],
            })

            # 限制子图大小
            if len(nodes) >= self.max_nodes:
                break

        if not nodes or not edges:
            return None

        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "window_start": window_start,
                "window_end": window_end,
                "start_time": self._ns_to_datetime(window_start),
                "end_time": self._ns_to_datetime(window_end),
                "num_events": len(events),
                "num_nodes": len(nodes),
                "num_edges": len(edges),
            }
        }

    def _resolve_node(self, uuid: str) -> Optional[Dict]:
        """
        根据UUID解析节点信息，映射为PIDS节点格式

        Returns:
            {"id": uuid, "label": "...", "type": "process/file/socket"}
        """
        # 优先查进程
        if uuid in self.subjects:
            subj = self.subjects[uuid]
            label = subj["path"] or subj["cmdline"] or f"pid_{subj['pid']}"
            # 截取进程名（去掉路径前缀）
            if "/" in label:
                label = label.split("/")[-1] or label
            return {
                "id": uuid,
                "label": label,
                "type": "process",
                "cmdline": subj.get("cmdline", ""),
                "timestamp": subj.get("start_time"),
            }

        # 查文件
        if uuid in self.file_objects:
            fobj = self.file_objects[uuid]
            label = fobj["path"] or f"file_{uuid[:8]}"
            return {
                "id": uuid,
                "label": label,
                "type": "file",
            }

        # 查网络连接
        if uuid in self.net_objects:
            nobj = self.net_objects[uuid]
            src = f"{nobj['src_addr']}:{nobj['src_port']}" if nobj['src_addr'] else ""
            dst = f"{nobj['dst_addr']}:{nobj['dst_port']}" if nobj['dst_addr'] else ""
            label = f"{src}->{dst}" if src and dst else (src or dst or f"net_{uuid[:8]}")
            return {
                "id": uuid,
                "label": label,
                "type": "socket",
            }

        # 未知实体
        return {
            "id": uuid,
            "label": f"unknown_{uuid[:8]}",
            "type": "other",
        }

    def _ns_to_datetime(self, ns: int) -> str:
        """纳秒时间戳转可读时间"""
        try:
            return datetime.fromtimestamp(ns / 1_000_000_000).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError):
            return f"ns={ns}"

    def get_stats(self) -> Dict:
        """返回解析统计信息"""
        return dict(self.stats)


def extract_features_from_subgraphs(subgraphs: List[Dict], feature_extractor) -> Tuple[np.ndarray, List[Dict]]:
    """
    对子图列表批量提取特征向量

    Args:
        subgraphs: 子图列表
        feature_extractor: FeatureExtractor实例

    Returns:
        (features_array, metadata_list)
    """
    features_list = []
    metadata_list = []

    for i, sg in enumerate(subgraphs):
        try:
            feature_vec = feature_extractor.extract(sg)
            features_list.append(feature_vec)
            metadata_list.append(sg["metadata"])

            if (i + 1) % 100 == 0:
                logger.info(f"  特征提取进度: {i+1}/{len(subgraphs)}")

        except Exception as e:
            logger.warning(f"  子图 {i} 特征提取失败: {e}")

    if features_list:
        return np.array(features_list, dtype=np.float32), metadata_list
    return np.empty((0, 130), dtype=np.float32), []


def main():
    parser = argparse.ArgumentParser(description="DARPA TC CDM18 → PIDS 数据转换")
    parser.add_argument("--data_dir", type=str, required=True,
                        help="DARPA TC E3 数据集目录")
    parser.add_argument("--output_dir", type=str, default="./PIDS/data",
                        help="输出目录")
    parser.add_argument("--window_minutes", type=int, default=5,
                        help="时间窗口大小（分钟）")
    parser.add_argument("--max_files", type=int, default=0,
                        help="最大处理文件数（0=全部）")
    parser.add_argument("--max_lines_per_file", type=int, default=0,
                        help="每个文件最大读取行数（0=全部）")
    parser.add_argument("--train_ratio", type=float, default=0.7,
                        help="训练集比例")
    parser.add_argument("--val_ratio", type=float, default=0.15,
                        help="验证集比例")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # ===== Step 1: 解析CDM数据 =====
    logger.info("=" * 60)
    logger.info("Step 1: 解析 DARPA TC CDM18 数据")
    logger.info("=" * 60)

    adapter = CDMAdapter(window_minutes=args.window_minutes)

    # 查找所有JSON文件
    json_files = sorted(glob.glob(os.path.join(args.data_dir, "*.json*")))
    if not json_files:
        logger.error(f"未找到JSON文件: {args.data_dir}")
        sys.exit(1)

    logger.info(f"找到 {len(json_files)} 个数据文件")

    if args.max_files > 0:
        json_files = json_files[:args.max_files]
        logger.info(f"限制处理前 {args.max_files} 个文件")

    for filepath in json_files:
        adapter.parse_file(filepath, max_lines=args.max_lines_per_file)

    logger.info(f"\n解析统计: {adapter.get_stats()}")

    # ===== Step 2: 构建子图 =====
    logger.info("=" * 60)
    logger.info("Step 2: 按时间窗口构建溯源子图")
    logger.info("=" * 60)

    subgraphs = adapter.build_subgraphs()

    if not subgraphs:
        logger.error("未能构建任何子图，请检查数据")
        sys.exit(1)

    # 保存子图（用于调试）
    subgraph_path = os.path.join(args.output_dir, "subgraphs_sample.json")
    with open(subgraph_path, 'w', encoding='utf-8') as f:
        json.dump(subgraphs[:10], f, ensure_ascii=False, indent=2, default=str)
    logger.info(f"样本子图已保存: {subgraph_path}")

    # ===== Step 3: 特征提取 =====
    logger.info("=" * 60)
    logger.info("Step 3: 批量特征提取 (130维)")
    logger.info("=" * 60)

    # 导入特征提取器（优先从同目录导入，兼容多种部署方式）
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    if _script_dir not in sys.path:
        sys.path.insert(0, _script_dir)
    try:
        from feature_extractor import FeatureExtractor
        logger.info(f"FeatureExtractor 从同目录导入: {_script_dir}")
    except ImportError:
        # 回退：尝试从 PIDS 包结构导入
        for _candidate in [
            os.path.join(_script_dir, '..', '..'),
            '/home/test/YuLianTianJian_Core/PythonIDS',
        ]:
            _candidate = os.path.abspath(_candidate)
            if os.path.isdir(os.path.join(_candidate, 'PIDS', 'feature_extraction')):
                sys.path.insert(0, _candidate)
                break
        from PIDS.feature_extraction.feature_extractor import FeatureExtractor
        logger.info("FeatureExtractor 从 PIDS 包导入")

    extractor = FeatureExtractor()
    features, metadata = extract_features_from_subgraphs(subgraphs, extractor)

    logger.info(f"特征矩阵: {features.shape}")

    if features.shape[0] == 0:
        logger.error("特征提取失败，无有效样本")
        sys.exit(1)

    # ===== Step 4: 生成标签 =====
    logger.info("=" * 60)
    logger.info("Step 4: 生成标签（基于启发式规则）")
    logger.info("=" * 60)

    # 由于没有精确的ground truth时间戳对齐，使用启发式标注：
    # 特征向量中的语义特征（攻击模式得分）可以作为弱标签
    # overall_threat_score (第128维) > 阈值 → 异常
    labels = generate_heuristic_labels(features, subgraphs)

    normal_count = np.sum(labels == 0)
    anomaly_count = np.sum(labels == 1)
    logger.info(f"标签分布: 正常={normal_count}, 异常={anomaly_count}")

    # ===== Step 5: 数据集划分 =====
    logger.info("=" * 60)
    logger.info("Step 5: 数据集划分")
    logger.info("=" * 60)

    n = features.shape[0]
    indices = np.random.permutation(n)

    train_end = int(n * args.train_ratio)
    val_end = int(n * (args.train_ratio + args.val_ratio))

    train_idx = indices[:train_end]
    val_idx = indices[train_end:val_end]
    test_idx = indices[val_end:]

    # 保存数据集
    for name, idx in [("train", train_idx), ("val", val_idx), ("test", test_idx)]:
        path = os.path.join(args.output_dir, f"{name}_dataset.npz")
        np.savez_compressed(path,
                            features=features[idx],
                            labels=labels[idx])
        logger.info(f"  {name}: {len(idx)} 样本 → {path}")

    # 保存完整数据集
    full_path = os.path.join(args.output_dir, "full_dataset.npz")
    np.savez_compressed(full_path, features=features, labels=labels)
    logger.info(f"  完整数据集: {n} 样本 → {full_path}")

    # 保存特征名称
    names_path = os.path.join(args.output_dir, "feature_names.json")
    with open(names_path, 'w', encoding='utf-8') as f:
        json.dump(extractor.get_feature_names(), f, ensure_ascii=False)

    logger.info("=" * 60)
    logger.info("数据准备完成！")
    logger.info(f"  总样本数: {n}")
    logger.info(f"  训练集: {len(train_idx)}")
    logger.info(f"  验证集: {len(val_idx)}")
    logger.info(f"  测试集: {len(test_idx)}")
    logger.info(f"  输出目录: {args.output_dir}")
    logger.info("=" * 60)


def generate_heuristic_labels(features: np.ndarray, subgraphs: List[Dict]) -> np.ndarray:
    """
    基于启发式规则生成标签

    策略：
    1. 特征向量中的语义特征（攻击模式得分）作为主要依据
    2. 图结构异常（异常高的边数/节点数比）作为辅助
    3. 结合多个信号综合判定

    Returns:
        标签数组: 0=正常, 1=异常
    """
    n = features.shape[0]
    labels = np.zeros(n, dtype=np.int32)

    # 130维特征中，语义特征在最后20维 (110-129)
    # 具体索引：
    # 110: sql_injection_score
    # 111: xss_score
    # 112: webshell_score
    # 113: traversal_score
    # 114: rce_score
    # 115: privilege_escalation_score
    # 116: data_exfiltration_score
    # 117: persistence_score
    # 118: sensitive_file_access_count
    # 119: sensitive_file_access_ratio
    # 120: critical_process_count
    # 121: critical_process_ratio
    # 122: lateral_movement_score
    # 123: reconnaissance_score
    # 127: overall_threat_score
    # 128: confidence_score
    # 129: anomaly_score

    for i in range(n):
        f = features[i]

        # 攻击模式得分
        attack_scores = f[110:118]  # 8个攻击模式得分
        max_attack_score = np.max(attack_scores) if len(attack_scores) > 0 else 0
        sum_attack_score = np.sum(attack_scores)

        # 敏感文件访问
        sensitive_access = f[118] if len(f) > 118 else 0
        sensitive_ratio = f[119] if len(f) > 119 else 0

        # 关键进程
        critical_count = f[120] if len(f) > 120 else 0
        critical_ratio = f[121] if len(f) > 121 else 0

        # 综合威胁得分
        threat_score = f[127] if len(f) > 127 else 0

        # 图结构特征
        node_count = f[0] if len(f) > 0 else 0
        edge_count = f[1] if len(f) > 1 else 0
        density = f[2] if len(f) > 2 else 0

        # 判定规则（多信号融合）
        anomaly_signals = 0

        if max_attack_score > 0.3:
            anomaly_signals += 2
        elif max_attack_score > 0.1:
            anomaly_signals += 1

        if sum_attack_score > 0.5:
            anomaly_signals += 1

        if sensitive_ratio > 0.3:
            anomaly_signals += 1

        if critical_ratio > 0.5:
            anomaly_signals += 1

        if threat_score > 0.3:
            anomaly_signals += 2

        if edge_count > 0 and node_count > 0 and edge_count / max(node_count, 1) > 5:
            anomaly_signals += 1

        # 阈值：累计信号 >= 2 判定为异常
        if anomaly_signals >= 2:
            labels[i] = 1

    return labels


if __name__ == "__main__":
    main()
