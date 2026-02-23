# -*- coding: utf-8 -*-
"""
PIDS 特征提取引擎 v2.0
=======================

从因果溯源图中提取130维结构化特征向量。
使用 NetworkX 进行真实图属性计算。

特征维度分布：
- 图结构特征: 15维 (NetworkX真实计算)
- 节点特征: 40维
- 边特征: 25维
- 序列特征: 30维 (时间熵计算)
- 语义特征: 20维 (关键词热度映射)

总计: 130维
"""

import json
import math
import numpy as np
import networkx as nx
from typing import Dict, List, Any, Tuple, Optional
from collections import Counter
from datetime import datetime
from scipy import stats


class FeatureExtractor:
    """
    PIDS 因果溯源图特征提取器
    
    将溯源图谱转化为130维特征向量，用于后续的机器学习分析。
    """
    
    # 关键进程列表（用于节点特征提取）
    KEY_PROCESSES = [
        'bash', 'sh', 'zsh', 'python', 'python3', 'perl', 'ruby',
        'wget', 'curl', 'nc', 'netcat', 'ncat',
        'ssh', 'scp', 'sftp', 'ftp',
        'cat', 'less', 'more', 'head', 'tail', 'grep',
        'chmod', 'chown', 'chgrp',
        'sudo', 'su', 'passwd',
        'nginx', 'apache', 'httpd', 'php-fpm', 'mysql', 'postgres',
        'whoami', 'id', 'uname', 'hostname', 'ifconfig', 'ip',
        'ps', 'top', 'netstat', 'ss', 'lsof',
        'rm', 'mv', 'cp', 'mkdir', 'touch',
        'crontab', 'at', 'systemctl', 'service'
    ]
    
    # 敏感文件路径模式
    SENSITIVE_FILES = [
        '/etc/passwd', '/etc/shadow', '/etc/sudoers',
        '/etc/ssh/', '/root/.ssh/',
        '/var/log/', '/var/www/',
        '/tmp/', '/dev/shm/',
        '.php', '.jsp', '.asp', '.sh', '.py',
        'shell', 'backdoor', 'webshell', 'exploit'
    ]
    
    # 攻击模式关键词
    ATTACK_PATTERNS = {
        'sql_injection': ['select', 'union', 'insert', 'update', 'delete', 'drop', 'mysql'],
        'xss': ['script', 'javascript', 'onerror', 'onload', 'alert'],
        'webshell': ['eval', 'base64', 'system', 'exec', 'shell', 'cmd'],
        'traversal': ['../', '..\\', 'passwd', 'shadow'],
        'rce': ['bash', 'sh', 'cmd', 'exec', 'system', 'whoami'],
        'privilege_escalation': ['sudo', 'su', 'chmod', 'chown', 'setuid'],
        'data_exfiltration': ['curl', 'wget', 'nc', 'ftp', 'scp'],
        'persistence': ['crontab', 'rc.local', 'init.d', 'systemd', '.bashrc']
    }
    
    def __init__(self):
        """初始化特征提取器"""
        self.feature_names = self._generate_feature_names()
    
    def _generate_feature_names(self) -> List[str]:
        """生成特征名称列表"""
        names = []
        
        # 图结构特征名称 (15维)
        names.extend([
            'node_count', 'edge_count', 'graph_density',
            'avg_degree', 'max_degree', 'min_degree',
            'max_path_length', 'avg_path_length',
            'connected_components', 'clustering_coefficient',
            'graph_diameter', 'graph_radius',
            'node_edge_ratio', 'leaf_node_ratio', 'hub_node_ratio'
        ])
        
        # 节点特征名称 (40维)
        names.extend([
            'process_node_count', 'file_node_count', 'socket_node_count',
            'attacker_node_count', 'other_node_count'
        ])
        # 关键进程出现频率 (35个)
        for proc in self.KEY_PROCESSES[:35]:
            names.append(f'proc_{proc}_freq')
        
        # 边特征名称 (25维)
        names.extend([
            'exec_edge_count', 'read_edge_count', 'write_edge_count',
            'connect_edge_count', 'fork_edge_count', 'other_edge_count',
            'process_to_process', 'process_to_file', 'file_to_process',
            'process_to_socket', 'socket_to_process',
            'attacker_to_process', 'attacker_to_file',
            'cross_type_ratio', 'self_loop_count',
            'bidirectional_edge_count', 'chain_length_avg', 'chain_length_max',
            'branch_factor_avg', 'branch_factor_max',
            'edge_weight_sum', 'edge_weight_avg', 'edge_weight_max',
            'critical_path_length', 'attack_chain_depth'
        ])
        
        # 序列特征名称 (30维)
        names.extend([
            'time_span_seconds', 'time_span_minutes', 'time_span_hours',
            'interval_mean', 'interval_std', 'interval_min', 'interval_max',
            'interval_median', 'interval_q25', 'interval_q75',
            'burst_count', 'burst_intensity',
            'operation_entropy', 'node_type_entropy', 'edge_type_entropy',
            'sequence_length', 'unique_operations',
            'repeat_pattern_count', 'periodic_pattern_score',
            'acceleration_score', 'deceleration_score',
            'morning_activity', 'afternoon_activity', 'evening_activity', 'night_activity',
            'weekday_activity', 'weekend_activity',
            'first_to_critical', 'critical_to_last', 'attack_phase_duration'
        ])
        
        # 语义特征名称 (20维)
        names.extend([
            'sql_injection_score', 'xss_score', 'webshell_score',
            'traversal_score', 'rce_score',
            'privilege_escalation_score', 'data_exfiltration_score', 'persistence_score',
            'sensitive_file_access_count', 'sensitive_file_access_ratio',
            'critical_process_count', 'critical_process_ratio',
            'lateral_movement_score', 'reconnaissance_score',
            'attack_stage_initial', 'attack_stage_exploit', 'attack_stage_post',
            'overall_threat_score', 'confidence_score', 'anomaly_score'
        ])
        
        return names[:130]  # 确保恰好130维
    
    def extract(self, graph_data: Dict[str, Any]) -> np.ndarray:
        """
        从溯源图中提取130维特征向量
        
        Args:
            graph_data: 溯源图数据，格式: {"nodes": [...], "edges": [...]}
        
        Returns:
            130维特征向量 (numpy array)
        """
        nodes = graph_data.get('nodes', [])
        edges = graph_data.get('edges', [])
        
        features = []
        
        # 1. 图结构特征 (15维)
        features.extend(self._extract_graph_structure_features(nodes, edges))
        
        # 2. 节点特征 (40维)
        features.extend(self._extract_node_features(nodes))
        
        # 3. 边特征 (25维)
        features.extend(self._extract_edge_features(nodes, edges))
        
        # 4. 序列特征 (30维)
        features.extend(self._extract_sequence_features(nodes, edges))
        
        # 5. 语义特征 (20维)
        features.extend(self._extract_semantic_features(nodes, edges))
        
        # 确保恰好130维
        features = features[:130]
        while len(features) < 130:
            features.append(0.0)
        
        return np.array(features, dtype=np.float32)
    
    def _build_networkx_graph(self, nodes: List, edges: List) -> nx.DiGraph:
        """
        构建 NetworkX 有向图
        
        Args:
            nodes: 节点列表
            edges: 边列表
            
        Returns:
            NetworkX 有向图对象
        """
        G = nx.DiGraph()
        
        # 添加节点及其属性
        for i, node in enumerate(nodes):
            node_id = node.get('id', f'node_{i}')
            G.add_node(node_id, 
                       label=node.get('label', ''),
                       type=node.get('type', 'other'),
                       cmdline=node.get('cmdline', ''),
                       timestamp=node.get('timestamp') or node.get('time'))
        
        # 添加边及其属性
        for edge in edges:
            src = edge.get('source', '')
            tgt = edge.get('target', '')
            if src and tgt and G.has_node(src) and G.has_node(tgt):
                G.add_edge(src, tgt, 
                           label=edge.get('label', ''),
                           weight=edge.get('weight', 1.0))
        
        return G

    def _extract_graph_structure_features(self, nodes: List, edges: List) -> List[float]:
        """
        使用 NetworkX 提取真实图结构特征 (15维)
        
        特征列表:
        0. node_count - 节点数量
        1. edge_count - 边数量
        2. graph_density - 图密度
        3. avg_degree - 平均度数
        4. max_degree - 最大度数
        5. min_degree - 最小度数
        6. max_path_length - 最长路径长度
        7. avg_path_length - 平均路径长度
        8. connected_components - 弱连通分量数
        9. clustering_coefficient - 聚类系数
        10. graph_diameter - 图直径
        11. graph_radius - 图半径
        12. node_edge_ratio - 节点边比率
        13. leaf_node_ratio - 叶子节点比例
        14. hub_node_ratio - 枢纽节点比例
        """
        n = len(nodes)
        e = len(edges)
        
        if n == 0:
            return [0.0] * 15
        
        # 构建 NetworkX 图
        G = self._build_networkx_graph(nodes, edges)
        
        # ===== 真实图属性计算 =====
        
        # 1. 基本统计
        node_count = float(G.number_of_nodes())
        edge_count = float(G.number_of_edges())
        
        # 2. 图密度 (使用NetworkX计算)
        density = nx.density(G)
        
        # 3. 度数统计
        degrees = [d for n, d in G.degree()]
        avg_degree = np.mean(degrees) if degrees else 0.0
        max_degree = float(max(degrees)) if degrees else 0.0
        min_degree = float(min(degrees)) if degrees else 0.0
        
        # 4. 路径长度 (使用最大弱连通分量)
        max_path_length = 0.0
        avg_path_length = 0.0
        diameter = 0.0
        radius = 0.0
        
        try:
            # 转换为无向图计算连通性
            G_undirected = G.to_undirected()
            if nx.is_connected(G_undirected):
                # 计算所有节点对之间的最短路径长度
                path_lengths = dict(nx.all_pairs_shortest_path_length(G_undirected))
                all_lengths = []
                for source in path_lengths:
                    for target, length in path_lengths[source].items():
                        if source != target:
                            all_lengths.append(length)
                
                if all_lengths:
                    max_path_length = float(max(all_lengths))
                    avg_path_length = float(np.mean(all_lengths))
                    diameter = max_path_length
                    # 计算偏心率和半径
                    eccentricities = nx.eccentricity(G_undirected)
                    radius = float(min(eccentricities.values()))
            else:
                # 对于非连通图，使用最大连通分量
                largest_cc = max(nx.connected_components(G_undirected), key=len)
                subgraph = G_undirected.subgraph(largest_cc)
                if len(subgraph) > 1:
                    diameter = float(nx.diameter(subgraph))
                    radius = float(nx.radius(subgraph))
                    avg_path_length = float(nx.average_shortest_path_length(subgraph))
                    max_path_length = diameter
        except Exception:
            # 如果计算失败，使用估计值
            max_path_length = float(n) if n > 1 else 0.0
            avg_path_length = float(n) / 2.0 if n > 1 else 0.0
        
        # 5. 连通分量数 (弱连通)
        connected_components = float(nx.number_weakly_connected_components(G))
        
        # 6. 聚类系数 (转换为无向图计算)
        try:
            clustering_coefficient = nx.average_clustering(G.to_undirected())
        except Exception:
            clustering_coefficient = 0.0
        
        # 7. 节点边比率
        node_edge_ratio = node_count / edge_count if edge_count > 0 else 0.0
        
        # 8. 叶子节点比例 (出度为0的节点)
        out_degrees = [d for n, d in G.out_degree()]
        leaf_count = sum(1 for d in out_degrees if d == 0)
        leaf_ratio = leaf_count / node_count if node_count > 0 else 0.0
        
        # 9. 枢纽节点比例 (度数大于平均值2倍的节点)
        hub_count = sum(1 for d in degrees if d > avg_degree * 2)
        hub_ratio = hub_count / node_count if node_count > 0 else 0.0
        
        return [
            node_count,              # 0: node_count
            edge_count,              # 1: edge_count
            density,                 # 2: graph_density
            avg_degree,              # 3: avg_degree
            max_degree,              # 4: max_degree
            min_degree,              # 5: min_degree
            max_path_length,         # 6: max_path_length
            avg_path_length,         # 7: avg_path_length
            connected_components,    # 8: connected_components
            clustering_coefficient,  # 9: clustering_coefficient
            diameter,                # 10: graph_diameter
            radius,                  # 11: graph_radius
            node_edge_ratio,         # 12: node_edge_ratio
            leaf_ratio,              # 13: leaf_node_ratio
            hub_ratio                # 14: hub_node_ratio
        ]
    
    def _extract_node_features(self, nodes: List) -> List[float]:
        """提取节点特征 (40维)"""
        features = []
        
        # 节点类型统计
        type_counts = Counter(node.get('type', 'other') for node in nodes)
        n = len(nodes) if nodes else 1
        
        features.extend([
            float(type_counts.get('process', 0)),
            float(type_counts.get('file', 0)),
            float(type_counts.get('socket', 0)),
            float(type_counts.get('attacker', 0)),
            float(sum(v for k, v in type_counts.items() if k not in ['process', 'file', 'socket', 'attacker']))
        ])
        
        # 关键进程出现频率 (35维)
        labels = [node.get('label', '').lower() for node in nodes]
        for proc in self.KEY_PROCESSES[:35]:
            count = sum(1 for label in labels if proc in label)
            features.append(count / n if n > 0 else 0)
        
        return features
    
    def _extract_edge_features(self, nodes: List, edges: List) -> List[float]:
        """提取边特征 (25维)"""
        e = len(edges) if edges else 1
        n = len(nodes) if nodes else 1
        
        # 边类型统计
        edge_labels = [edge.get('label', 'other').lower() for edge in edges]
        label_counts = Counter(edge_labels)
        
        # 节点类型映射
        node_types = {node.get('id', ''): node.get('type', 'other') for node in nodes}
        
        # 类型间边统计（真实计算）
        cross_type_count = 0
        type_pair_counts = Counter()
        self_loop_count = 0
        edge_set = set()
        bidirectional_count = 0
        
        for edge in edges:
            src = edge.get('source', '')
            tgt = edge.get('target', '')
            src_type = node_types.get(src, 'other')
            tgt_type = node_types.get(tgt, 'other')
            
            if src_type != tgt_type:
                cross_type_count += 1
            
            type_pair_counts[(src_type, tgt_type)] += 1
            
            if src == tgt:
                self_loop_count += 1
            
            if (tgt, src) in edge_set:
                bidirectional_count += 1
            edge_set.add((src, tgt))
        
        process_to_process = float(type_pair_counts.get(('process', 'process'), 0))
        process_to_file = float(type_pair_counts.get(('process', 'file'), 0))
        file_to_process = float(type_pair_counts.get(('file', 'process'), 0))
        process_to_socket = float(type_pair_counts.get(('process', 'socket'), 0))
        socket_to_process = float(type_pair_counts.get(('socket', 'process'), 0))
        attacker_to_process = float(type_pair_counts.get(('attacker', 'process'), 0))
        attacker_to_file = float(type_pair_counts.get(('attacker', 'file'), 0))
        
        # 链长和分支因子（基于出度统计）
        out_degree_counts = Counter(edge.get('source', '') for edge in edges)
        out_degrees = list(out_degree_counts.values()) if out_degree_counts else [0]
        branch_factor_avg = float(np.mean(out_degrees))
        branch_factor_max = float(max(out_degrees))
        
        # 边权重统计
        weights = [edge.get('weight', 1.0) for edge in edges]
        edge_weight_sum = float(sum(weights)) if weights else 0.0
        edge_weight_avg = float(np.mean(weights)) if weights else 0.0
        edge_weight_max = float(max(weights)) if weights else 0.0
        
        # 使用 NetworkX 计算关键路径和攻击链深度
        G = self._build_networkx_graph(nodes, edges)
        try:
            critical_path_length = float(nx.dag_longest_path_length(G)) if nx.is_directed_acyclic_graph(G) else float(n)
        except Exception:
            critical_path_length = float(n)
        
        # 攻击链深度：从 attacker 类型节点出发的最长路径
        attack_chain_depth = 0.0
        attacker_nodes = [nid for nid, data in G.nodes(data=True) if data.get('type') == 'attacker']
        for att in attacker_nodes:
            try:
                lengths = nx.single_source_shortest_path_length(G, att)
                if lengths:
                    attack_chain_depth = max(attack_chain_depth, float(max(lengths.values())))
            except Exception:
                pass
        if attack_chain_depth == 0.0:
            attack_chain_depth = float(n) / 2
        
        return [
            float(sum(1 for l in edge_labels if '执行' in l or 'exec' in l)),
            float(sum(1 for l in edge_labels if '读' in l or 'read' in l)),
            float(sum(1 for l in edge_labels if '写' in l or 'write' in l)),
            float(sum(1 for l in edge_labels if '连接' in l or 'connect' in l)),
            float(sum(1 for l in edge_labels if 'fork' in l)),
            float(label_counts.get('other', 0)),
            process_to_process,
            process_to_file,
            file_to_process,
            process_to_socket,
            socket_to_process,
            attacker_to_process,
            attacker_to_file,
            cross_type_count / e if e > 0 else 0,
            float(self_loop_count),
            float(bidirectional_count),
            float(e) / n if n > 0 else 0,  # chain_length_avg
            critical_path_length,  # chain_length_max
            branch_factor_avg,
            branch_factor_max,
            edge_weight_sum,
            edge_weight_avg,
            edge_weight_max,
            critical_path_length,
            attack_chain_depth
        ]
    
    def _calculate_entropy(self, values: List) -> float:
        """
        计算香农熵
        
        Args:
            values: 值列表
            
        Returns:
            熵值 (归一化到0-1)
        """
        if not values:
            return 0.0
        
        counter = Counter(values)
        total = len(values)
        probabilities = [count / total for count in counter.values()]
        
        # 香农熵计算
        entropy = -sum(p * math.log2(p) for p in probabilities if p > 0)
        
        # 归一化 (除以最大可能熵)
        max_entropy = math.log2(len(counter)) if len(counter) > 1 else 1.0
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
        
        return min(normalized_entropy, 1.0)

    def _detect_bursts(self, timestamps: List[float], threshold_factor: float = 2.0) -> Tuple[int, float]:
        """
        检测时间序列中的爆发事件
        自动化攻击的时间间隔方差极小（节奏整齐），人工操作方差大
        
        Args:
            timestamps: 排序后的时间戳列表
            threshold_factor: 爆发检测阈值因子
            
        Returns:
            (爆发次数, 爆发强度)
        """
        if len(timestamps) < 3:
            return 0, 0.0
        
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        # 检测爆发：间隔小于 (均值 - threshold_factor * 标准差)
        threshold = max(mean_interval - threshold_factor * std_interval, 0.001)
        
        burst_count = 0
        burst_intensity = 0.0
        in_burst = False
        current_burst_length = 0
        
        for interval in intervals:
            if interval < threshold:
                if not in_burst:
                    burst_count += 1
                    in_burst = True
                current_burst_length += 1
            else:
                if in_burst:
                    burst_intensity = max(burst_intensity, current_burst_length)
                    current_burst_length = 0
                in_burst = False
        
        # 处理最后一个爆发
        if in_burst:
            burst_intensity = max(burst_intensity, current_burst_length)
        
        # 归一化爆发强度
        normalized_intensity = burst_intensity / len(intervals) if intervals else 0.0
        
        return burst_count, normalized_intensity

    def _extract_sequence_features(self, nodes: List, edges: List) -> List[float]:
        """
        提取序列特征 (30维) - 使用时间熵和方差分析
        
        自动化脚本的攻击序列方差极小（节奏整齐），人工操作方差大。
        通过时间戳方差和熵来区分自动化攻击和人工操作。
        """
        # 提取时间戳
        timestamps = []
        datetimes = []
        for node in nodes:
            ts = node.get('timestamp') or node.get('time')
            if ts:
                try:
                    if isinstance(ts, str):
                        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                        timestamps.append(dt.timestamp())
                        datetimes.append(dt)
                    elif isinstance(ts, (int, float)):
                        timestamps.append(float(ts))
                        datetimes.append(datetime.fromtimestamp(float(ts)))
                except Exception:
                    pass
        
        if len(timestamps) < 2:
            # 返回默认值，但保持结构
            return [0.0] * 30
        
        timestamps.sort()
        
        # ===== 时间跨度 =====
        time_span = timestamps[-1] - timestamps[0]
        time_span_seconds = time_span
        time_span_minutes = time_span / 60.0
        time_span_hours = time_span / 3600.0
        
        # ===== 时间间隔统计 =====
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        interval_mean = float(np.mean(intervals)) if intervals else 0.0
        interval_std = float(np.std(intervals)) if intervals else 0.0  # 关键：方差小=自动化
        interval_min = float(min(intervals)) if intervals else 0.0
        interval_max = float(max(intervals)) if intervals else 0.0
        interval_median = float(np.median(intervals)) if intervals else 0.0
        interval_q25 = float(np.percentile(intervals, 25)) if intervals else 0.0
        interval_q75 = float(np.percentile(intervals, 75)) if intervals else 0.0
        
        # ===== 爆发检测 =====
        burst_count, burst_intensity = self._detect_bursts(timestamps)
        
        # ===== 熵计算 =====
        # 操作熵：不同操作类型的分布
        operations = [node.get('label', '') for node in nodes]
        operation_entropy = self._calculate_entropy(operations)
        
        # 节点类型熵
        node_types = [node.get('type', 'other') for node in nodes]
        node_type_entropy = self._calculate_entropy(node_types)
        
        # 边类型熵
        edge_labels = [edge.get('label', 'other') for edge in edges]
        edge_type_entropy = self._calculate_entropy(edge_labels)
        
        # ===== 序列统计 =====
        sequence_length = float(len(nodes))
        unique_operations = float(len(set(operations)))
        
        # ===== 重复模式检测 =====
        # 检测是否存在重复的操作序列模式
        repeat_pattern_count = 0.0
        if len(operations) >= 4:
            # 检查连续重复模式
            for window_size in [2, 3, 4]:
                patterns = [''.join(operations[i:i+window_size]) for i in range(len(operations)-window_size+1)]
                pattern_counter = Counter(patterns)
                repeat_pattern_count += sum(1 for count in pattern_counter.values() if count > 1)
        
        # ===== 周期性模式评分 =====
        # 使用间隔的变异系数来评估周期性（CV小=周期性强=可能是自动化）
        cv = interval_std / interval_mean if interval_mean > 0 else 1.0
        periodic_pattern_score = max(0.0, 1.0 - cv)  # CV越小，周期性越强
        
        # ===== 加速/减速检测 =====
        acceleration_score = 0.0
        deceleration_score = 0.0
        if len(intervals) >= 3:
            # 计算间隔变化率
            interval_changes = [intervals[i+1] - intervals[i] for i in range(len(intervals)-1)]
            negative_changes = sum(1 for c in interval_changes if c < 0)  # 间隔变小=加速
            positive_changes = sum(1 for c in interval_changes if c > 0)  # 间隔变大=减速
            total_changes = len(interval_changes)
            acceleration_score = negative_changes / total_changes if total_changes > 0 else 0.0
            deceleration_score = positive_changes / total_changes if total_changes > 0 else 0.0
        
        # ===== 时间段活动分布 =====
        morning_activity = 0.0   # 6-12点
        afternoon_activity = 0.0 # 12-18点
        evening_activity = 0.0   # 18-24点
        night_activity = 0.0     # 0-6点
        weekday_activity = 0.0
        weekend_activity = 0.0
        
        if datetimes:
            for dt in datetimes:
                hour = dt.hour
                if 6 <= hour < 12:
                    morning_activity += 1
                elif 12 <= hour < 18:
                    afternoon_activity += 1
                elif 18 <= hour < 24:
                    evening_activity += 1
                else:
                    night_activity += 1
                
                # 周内/周末
                if dt.weekday() < 5:
                    weekday_activity += 1
                else:
                    weekend_activity += 1
            
            # 归一化
            total = len(datetimes)
            morning_activity /= total
            afternoon_activity /= total
            evening_activity /= total
            night_activity /= total
            weekday_activity /= total
            weekend_activity /= total
        
        # ===== 攻击阶段时间 =====
        # 基于关键事件（攻击者节点、敏感操作）的时间戳定位关键时刻
        critical_keywords = ['exec', '执行', 'shell', 'sudo', 'chmod', 'passwd', 'attack', '攻击',
                             'inject', 'exploit', 'webshell', 'reverse']
        critical_timestamp = None
        for node in nodes:
            label = (node.get('label', '') or '').lower()
            cmdline = (node.get('cmdline', '') or '').lower()
            node_type = (node.get('type', '') or '').lower()
            text = f"{label} {cmdline}"
            is_critical = node_type == 'attacker' or any(kw in text for kw in critical_keywords)
            if is_critical:
                ts = node.get('timestamp') or node.get('time')
                if ts:
                    try:
                        if isinstance(ts, str):
                            dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                            critical_timestamp = dt.timestamp()
                        elif isinstance(ts, (int, float)):
                            critical_timestamp = float(ts)
                        break
                    except Exception:
                        pass
        
        if critical_timestamp is not None and time_span > 0:
            first_to_critical = max(0.0, critical_timestamp - timestamps[0])
            critical_to_last = max(0.0, timestamps[-1] - critical_timestamp)
        else:
            first_to_critical = time_span * 0.3 if time_span > 0 else 0.0
            critical_to_last = time_span * 0.7 if time_span > 0 else 0.0
        attack_phase_duration = time_span
        
        return [
            time_span_seconds,       # 0: time_span_seconds
            time_span_minutes,       # 1: time_span_minutes
            time_span_hours,         # 2: time_span_hours
            interval_mean,           # 3: interval_mean
            interval_std,            # 4: interval_std (关键：自动化攻击方差小)
            interval_min,            # 5: interval_min
            interval_max,            # 6: interval_max
            interval_median,         # 7: interval_median
            interval_q25,            # 8: interval_q25
            interval_q75,            # 9: interval_q75
            float(burst_count),      # 10: burst_count
            burst_intensity,         # 11: burst_intensity
            operation_entropy,       # 12: operation_entropy
            node_type_entropy,       # 13: node_type_entropy
            edge_type_entropy,       # 14: edge_type_entropy
            sequence_length,         # 15: sequence_length
            unique_operations,       # 16: unique_operations
            repeat_pattern_count,    # 17: repeat_pattern_count
            periodic_pattern_score,  # 18: periodic_pattern_score (高=自动化)
            acceleration_score,      # 19: acceleration_score
            deceleration_score,      # 20: deceleration_score
            morning_activity,        # 21: morning_activity
            afternoon_activity,      # 22: afternoon_activity
            evening_activity,        # 23: evening_activity
            night_activity,          # 24: night_activity
            weekday_activity,        # 25: weekday_activity
            weekend_activity,        # 26: weekend_activity
            first_to_critical,       # 27: first_to_critical
            critical_to_last,        # 28: critical_to_last
            attack_phase_duration    # 29: attack_phase_duration
        ]
    
    def _calculate_pattern_score(self, text: str, keywords: List[str]) -> float:
        """
        计算关键词热度映射分数
        
        严禁直接返回固定分值。必须扫描 cmdline 中的敏感词。
        例如：若发现 'union select'，SQL注入分值应计算为 关键词匹配数 / 关键词总数
        
        Args:
            text: 待扫描的文本
            keywords: 关键词列表
            
        Returns:
            匹配得分 (0.0 - 1.0)
        """
        if not text or not keywords:
            return 0.0
        
        text_lower = text.lower()
        matched_count = 0
        weighted_score = 0.0
        
        for i, kw in enumerate(keywords):
            if kw.lower() in text_lower:
                matched_count += 1
                # 关键词权重：前面的关键词更重要
                weight = 1.0 + (len(keywords) - i) / len(keywords) * 0.5
                weighted_score += weight
                
                # 检查组合模式（如 'union select'）
                if i < len(keywords) - 1:
                    combo = f"{kw} {keywords[i+1]}"
                    if combo.lower() in text_lower:
                        weighted_score += 0.5  # 组合模式加分
        
        # 基础分数：匹配数/总数
        base_score = matched_count / len(keywords)
        
        # 加权分数归一化
        max_weighted = sum(1.0 + (len(keywords) - i) / len(keywords) * 0.5 for i in range(len(keywords)))
        weighted_normalized = weighted_score / max_weighted if max_weighted > 0 else 0.0
        
        # 综合得分
        final_score = (base_score + weighted_normalized) / 2.0
        
        return min(final_score, 1.0)

    def _extract_semantic_features(self, nodes: List, edges: List) -> List[float]:
        """
        提取语义特征 (20维) - 使用关键词热度映射
        
        严禁直接返回固定分值。必须扫描 cmdline 中的敏感词。
        """
        # 收集所有文本信息
        all_texts = []
        cmdlines = []
        labels = []
        
        for node in nodes:
            label = node.get('label', '') or ''
            cmdline = node.get('cmdline', '') or ''
            labels.append(label.lower())
            cmdlines.append(cmdline.lower())
            all_texts.append(f"{label} {cmdline}".lower())
        
        combined_text = ' '.join(all_texts)
        combined_cmdline = ' '.join(cmdlines)
        
        # ===== 攻击模式热度映射 =====
        # 使用真实的关键词匹配计算分数
        
        sql_injection_score = self._calculate_pattern_score(
            combined_text, self.ATTACK_PATTERNS['sql_injection'])
        
        xss_score = self._calculate_pattern_score(
            combined_text, self.ATTACK_PATTERNS['xss'])
        
        webshell_score = self._calculate_pattern_score(
            combined_text, self.ATTACK_PATTERNS['webshell'])
        
        traversal_score = self._calculate_pattern_score(
            combined_text, self.ATTACK_PATTERNS['traversal'])
        
        rce_score = self._calculate_pattern_score(
            combined_text, self.ATTACK_PATTERNS['rce'])
        
        privilege_escalation_score = self._calculate_pattern_score(
            combined_text, self.ATTACK_PATTERNS['privilege_escalation'])
        
        data_exfiltration_score = self._calculate_pattern_score(
            combined_text, self.ATTACK_PATTERNS['data_exfiltration'])
        
        persistence_score = self._calculate_pattern_score(
            combined_text, self.ATTACK_PATTERNS['persistence'])
        
        # ===== 敏感文件访问统计 =====
        sensitive_count = 0
        for label in labels:
            for sf in self.SENSITIVE_FILES:
                if sf.lower() in label:
                    sensitive_count += 1
                    break
        
        n = len(nodes) if nodes else 1
        sensitive_file_access_count = float(sensitive_count)
        sensitive_file_access_ratio = sensitive_count / n
        
        # ===== 关键进程统计 =====
        critical_count = 0
        for label in labels:
            for kp in self.KEY_PROCESSES[:15]:  # 前15个是最关键的
                if kp.lower() in label:
                    critical_count += 1
                    break
        
        critical_process_count = float(critical_count)
        critical_process_ratio = critical_count / n
        
        # ===== 横向移动评分 =====
        # 检测SSH/RDP/WMI等横向移动特征
        lateral_keywords = ['ssh', 'rdp', 'wmi', 'psexec', 'winrm', 'lateral', 'pivot']
        lateral_movement_score = self._calculate_pattern_score(combined_text, lateral_keywords)
        
        # ===== 侦察评分 =====
        # 检测信息收集行为
        recon_keywords = ['whoami', 'id', 'uname', 'hostname', 'ifconfig', 'ip addr', 
                          'netstat', 'ss', 'ps aux', 'cat /etc', 'systeminfo', 'ipconfig']
        reconnaissance_score = self._calculate_pattern_score(combined_text, recon_keywords)
        
        # ===== 攻击阶段评估 =====
        # 基于特征组合判断攻击处于哪个阶段
        all_scores = [sql_injection_score, xss_score, webshell_score, traversal_score,
                      rce_score, privilege_escalation_score, data_exfiltration_score, persistence_score]
        
        # 初始阶段：扫描、探测
        attack_stage_initial = (reconnaissance_score + traversal_score) / 2.0
        
        # 利用阶段：注入、RCE、WebShell
        attack_stage_exploit = (sql_injection_score + xss_score + webshell_score + rce_score) / 4.0
        
        # 后渗透阶段：提权、持久化、数据窃取
        attack_stage_post = (privilege_escalation_score + persistence_score + data_exfiltration_score) / 3.0
        
        # 归一化阶段分数
        stage_sum = attack_stage_initial + attack_stage_exploit + attack_stage_post
        if stage_sum > 0:
            attack_stage_initial /= stage_sum
            attack_stage_exploit /= stage_sum
            attack_stage_post /= stage_sum
        else:
            attack_stage_initial = 0.33
            attack_stage_exploit = 0.34
            attack_stage_post = 0.33
        
        # ===== 综合威胁评分 =====
        overall_threat_score = np.mean(all_scores) if all_scores else 0.0
        
        # ===== 置信度评分 =====
        # 基于匹配到的特征数量
        non_zero_count = sum(1 for s in all_scores if s > 0.1)
        confidence_score = min(0.5 + non_zero_count * 0.1, 1.0)
        
        # ===== 异常评分 =====
        # 综合考虑所有因素
        anomaly_factors = [
            overall_threat_score,
            sensitive_file_access_ratio,
            critical_process_ratio,
            lateral_movement_score,
            reconnaissance_score
        ]
        anomaly_score = np.mean(anomaly_factors) * confidence_score
        
        return [
            sql_injection_score,           # 0: sql_injection_score
            xss_score,                     # 1: xss_score
            webshell_score,                # 2: webshell_score
            traversal_score,               # 3: traversal_score
            rce_score,                     # 4: rce_score
            privilege_escalation_score,    # 5: privilege_escalation_score
            data_exfiltration_score,       # 6: data_exfiltration_score
            persistence_score,             # 7: persistence_score
            sensitive_file_access_count,   # 8: sensitive_file_access_count
            sensitive_file_access_ratio,   # 9: sensitive_file_access_ratio
            critical_process_count,        # 10: critical_process_count
            critical_process_ratio,        # 11: critical_process_ratio
            lateral_movement_score,        # 12: lateral_movement_score
            reconnaissance_score,          # 13: reconnaissance_score
            attack_stage_initial,          # 14: attack_stage_initial
            attack_stage_exploit,          # 15: attack_stage_exploit
            attack_stage_post,             # 16: attack_stage_post
            overall_threat_score,          # 17: overall_threat_score
            confidence_score,              # 18: confidence_score
            anomaly_score                  # 19: anomaly_score
        ]
    
    def get_feature_names(self) -> List[str]:
        """获取特征名称列表"""
        return self.feature_names
    
    def extract_with_names(self, graph_data: Dict[str, Any]) -> Dict[str, float]:
        """
        提取特征并返回带名称的字典
        
        Args:
            graph_data: 溯源图数据
        
        Returns:
            特征名称到特征值的映射字典
        """
        features = self.extract(graph_data)
        return dict(zip(self.feature_names, features.tolist()))
    
    def extract_grouped(self, graph_data: Dict[str, Any]) -> Dict[str, np.ndarray]:
        """
        按类别分组提取特征
        
        Returns:
            {
                'graph_structure': 15维,
                'node': 40维,
                'edge': 25维,
                'sequence': 30维,
                'semantic': 20维
            }
        """
        features = self.extract(graph_data)
        return {
            'graph_structure': features[0:15],
            'node': features[15:55],
            'edge': features[55:80],
            'sequence': features[80:110],
            'semantic': features[110:130]
        }


# ============ 测试代码 ============
if __name__ == "__main__":
    # 测试数据
    test_graph = {
        "nodes": [
            {"id": "attacker_1", "label": "10.138.50.151", "type": "attacker"},
            {"id": "process_nginx", "label": "nginx", "type": "process"},
            {"id": "process_php", "label": "php-fpm", "type": "process"},
            {"id": "process_mysql", "label": "mysql", "type": "process"},
            {"id": "file_users", "label": "/var/lib/mysql/users.ibd", "type": "file"}
        ],
        "edges": [
            {"source": "attacker_1", "target": "process_nginx", "label": "攻击"},
            {"source": "process_nginx", "target": "process_php", "label": "执行"},
            {"source": "process_php", "target": "process_mysql", "label": "调用"},
            {"source": "process_mysql", "target": "file_users", "label": "访问"}
        ]
    }
    
    # 提取特征
    extractor = FeatureExtractor()
    features = extractor.extract(test_graph)
    
    print("=" * 60)
    print("PIDS 特征提取测试")
    print("=" * 60)
    print(f"特征维度: {len(features)}")
    print(f"特征向量: {features[:10]}... (前10维)")
    print()
    
    # 分组提取
    grouped = extractor.extract_grouped(test_graph)
    print("分组特征:")
    for name, vec in grouped.items():
        print(f"  {name}: {len(vec)}维, 均值={np.mean(vec):.4f}")
    print()
    
    # 带名称提取
    named_features = extractor.extract_with_names(test_graph)
    print("前10个特征:")
    for name, value in list(named_features.items())[:10]:
        print(f"  {name}: {value:.4f}")
