/**
 * PIDS 特征下钻详情弹窗
 * 
 * 毛玻璃质感的详情表，展示特征组所有子维度的对比：
 * | 特征项 | 正常基线 | 当前攻击值 | 偏离率 | 状态 |
 * 
 * 御链天鉴开发团队
 */

import React, { useMemo } from 'react';
import { X, AlertCircle, CheckCircle, TrendingUp, TrendingDown, Minus } from 'lucide-react';

// 特征组基线配置
const GROUP_BASELINES: Record<string, { baseline: number; features: Array<{ name: string; label: string; baseline: number }> }> = {
  graphStructure: {
    baseline: 0.15,
    features: [
      { name: 'node_count', label: '节点数量', baseline: 5 },
      { name: 'edge_count', label: '边数量', baseline: 4 },
      { name: 'graph_density', label: '图密度', baseline: 0.3 },
      { name: 'avg_degree', label: '平均度数', baseline: 1.6 },
      { name: 'max_degree', label: '最大度数', baseline: 3 },
      { name: 'min_degree', label: '最小度数', baseline: 1 },
      { name: 'max_path_length', label: '最长路径', baseline: 3 },
      { name: 'avg_path_length', label: '平均路径', baseline: 1.5 },
      { name: 'connected_components', label: '连通分量数', baseline: 1 },
      { name: 'clustering_coefficient', label: '聚类系数', baseline: 0.2 },
      { name: 'graph_diameter', label: '图直径', baseline: 3 },
      { name: 'graph_radius', label: '图半径', baseline: 1.5 },
      { name: 'node_edge_ratio', label: '节点边比率', baseline: 1.25 },
      { name: 'leaf_node_ratio', label: '叶子节点比例', baseline: 0.4 },
      { name: 'hub_node_ratio', label: '枢纽节点比例', baseline: 0.1 }
    ]
  },
  node: {
    baseline: 0.12,
    features: [
      { name: 'process_node_count', label: '进程节点数', baseline: 3 },
      { name: 'file_node_count', label: '文件节点数', baseline: 1 },
      { name: 'socket_node_count', label: '套接字节点数', baseline: 0 },
      { name: 'attacker_node_count', label: '攻击者节点数', baseline: 1 },
      { name: 'other_node_count', label: '其他节点数', baseline: 0 }
    ]
  },
  edge: {
    baseline: 0.18,
    features: [
      { name: 'exec_edge_count', label: '执行边数', baseline: 1 },
      { name: 'read_edge_count', label: '读取边数', baseline: 1 },
      { name: 'write_edge_count', label: '写入边数', baseline: 0.5 },
      { name: 'connect_edge_count', label: '连接边数', baseline: 0.5 },
      { name: 'fork_edge_count', label: 'Fork边数', baseline: 0 },
      { name: 'cross_type_ratio', label: '跨层调用频率', baseline: 0.05 }
    ]
  },
  sequence: {
    baseline: 0.14,
    features: [
      { name: 'time_span_seconds', label: '时间跨度(秒)', baseline: 60 },
      { name: 'interval_mean', label: '平均间隔', baseline: 10 },
      { name: 'interval_std', label: '间隔方差', baseline: 5 },
      { name: 'burst_count', label: '爆发次数', baseline: 0 },
      { name: 'burst_intensity', label: '爆发强度', baseline: 0 },
      { name: 'operation_entropy', label: '操作熵', baseline: 0.5 },
      { name: 'periodic_pattern_score', label: '周期性评分', baseline: 0.2 }
    ]
  },
  semantic: {
    baseline: 0.10,
    features: [
      { name: 'sql_injection_score', label: 'SQL注入得分', baseline: 0 },
      { name: 'xss_score', label: 'XSS得分', baseline: 0 },
      { name: 'webshell_score', label: 'WebShell得分', baseline: 0 },
      { name: 'traversal_score', label: '目录遍历得分', baseline: 0 },
      { name: 'rce_score', label: 'RCE得分', baseline: 0 },
      { name: 'privilege_escalation_score', label: '提权得分', baseline: 0 },
      { name: 'data_exfiltration_score', label: '数据窃取得分', baseline: 0 },
      { name: 'persistence_score', label: '持久化得分', baseline: 0 },
      { name: 'overall_threat_score', label: '综合威胁得分', baseline: 0.1 },
      { name: 'anomaly_score', label: '异常得分', baseline: 0.1 }
    ]
  }
};

const GROUP_NAMES: Record<string, string> = {
  graphStructure: '图结构特征',
  node: '节点特征',
  edge: '边特征',
  sequence: '序列特征',
  semantic: '语义特征'
};

const GROUP_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  graphStructure: { bg: 'from-blue-500/20 to-blue-600/10', border: 'border-blue-500/30', text: 'text-blue-400' },
  node: { bg: 'from-purple-500/20 to-purple-600/10', border: 'border-purple-500/30', text: 'text-purple-400' },
  edge: { bg: 'from-green-500/20 to-green-600/10', border: 'border-green-500/30', text: 'text-green-400' },
  sequence: { bg: 'from-yellow-500/20 to-yellow-600/10', border: 'border-yellow-500/30', text: 'text-yellow-400' },
  semantic: { bg: 'from-red-500/20 to-red-600/10', border: 'border-red-500/30', text: 'text-red-400' }
};

interface FeatureDetailModalProps {
  groupKey: string;
  groupValues: number[];
  featureNames?: string[];
  onClose: () => void;
  onFeatureClick?: (featureName: string, nodeIds?: string[]) => void;  // 反向定位联动
}

const FeatureDetailModal: React.FC<FeatureDetailModalProps> = ({
  groupKey,
  groupValues,
  featureNames = [],
  onClose,
  onFeatureClick
}) => {
  const groupConfig = GROUP_BASELINES[groupKey];
  const colors = GROUP_COLORS[groupKey] || GROUP_COLORS.graphStructure;
  const groupName = GROUP_NAMES[groupKey] || groupKey;

  // 计算每个特征的偏离率和状态
  const featureRows = useMemo(() => {
    if (!groupConfig) return [];
    
    return groupConfig.features.map((feature, idx) => {
      const currentValue = groupValues[idx] || 0;
      const baseline = feature.baseline;
      
      // 计算偏离率
      let deviation = 0;
      if (baseline > 0) {
        deviation = ((currentValue - baseline) / baseline) * 100;
      } else if (currentValue > 0) {
        deviation = currentValue * 100; // 基线为0时，直接使用当前值作为偏离
      }
      
      // 确定状态
      let status: 'normal' | 'warning' | 'danger' = 'normal';
      let statusLabel = '正常';
      let statusIcon = <CheckCircle size={14} className="text-green-400" />;
      
      if (Math.abs(deviation) > 500 || (baseline === 0 && currentValue > 0.5)) {
        status = 'danger';
        statusLabel = '🔴 极高';
        statusIcon = <AlertCircle size={14} className="text-red-400 animate-pulse" />;
      } else if (Math.abs(deviation) > 100 || (baseline === 0 && currentValue > 0.2)) {
        status = 'warning';
        statusLabel = '🟡 偏高';
        statusIcon = <AlertCircle size={14} className="text-yellow-400" />;
      }
      
      return {
        name: feature.name,
        label: feature.label,
        baseline,
        current: currentValue,
        deviation,
        status,
        statusLabel,
        statusIcon
      };
    });
  }, [groupConfig, groupValues]);

  // 统计异常数量
  const anomalyCount = featureRows.filter(r => r.status !== 'normal').length;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* 背景遮罩 - 毛玻璃效果 */}
      <div 
        className="absolute inset-0 bg-slate-900/60 backdrop-blur-md"
        onClick={onClose}
      />
      
      {/* 弹窗主体 */}
      <div className={`
        relative max-w-3xl w-full max-h-[80vh] overflow-hidden
        bg-gradient-to-br ${colors.bg} backdrop-blur-xl
        rounded-2xl border ${colors.border} shadow-2xl
      `}>
        {/* 头部 */}
        <div className="flex items-center justify-between p-4 border-b border-slate-700/50">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${colors.bg} flex items-center justify-center border ${colors.border}`}>
              <TrendingUp className={`w-5 h-5 ${colors.text}`} />
            </div>
            <div>
              <h2 className={`text-lg font-bold ${colors.text}`}>{groupName} 详情分析</h2>
              <p className="text-xs text-slate-400">
                共 {featureRows.length} 个子维度 · {anomalyCount > 0 ? (
                  <span className="text-red-400">{anomalyCount} 个异常</span>
                ) : (
                  <span className="text-green-400">全部正常</span>
                )}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-700/50 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-slate-400" />
          </button>
        </div>
        
        {/* 表格内容 - 可滚动 */}
        <div className="overflow-y-auto max-h-[60vh] p-4" style={{ scrollbarWidth: 'thin', scrollbarColor: '#475569 transparent' }}>
          <table className="w-full">
            <thead className="sticky top-0 bg-slate-900/90 backdrop-blur">
              <tr className="text-left text-xs text-slate-400 border-b border-slate-700/50">
                <th className="pb-3 font-medium">特征项</th>
                <th className="pb-3 font-medium text-center">正常基线</th>
                <th className="pb-3 font-medium text-center">当前攻击值</th>
                <th className="pb-3 font-medium text-center">偏离率</th>
                <th className="pb-3 font-medium text-center">状态</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/30">
              {featureRows.map((row, idx) => (
                <tr 
                  key={row.name}
                  className={`
                    group cursor-pointer transition-colors
                    ${row.status === 'danger' ? 'bg-red-500/5 hover:bg-red-500/10' : 
                      row.status === 'warning' ? 'bg-yellow-500/5 hover:bg-yellow-500/10' : 
                      'hover:bg-slate-700/30'}
                  `}
                  onClick={() => onFeatureClick?.(row.name)}
                >
                  <td className="py-3">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-300 font-medium">{row.label}</span>
                      <span className="text-slate-600 text-xs font-mono">({row.name})</span>
                    </div>
                  </td>
                  <td className="py-3 text-center">
                    <span className="text-slate-400 font-mono">
                      {row.baseline.toFixed(row.baseline < 1 ? 2 : 0)}
                    </span>
                  </td>
                  <td className="py-3 text-center">
                    <span className={`font-mono font-bold ${
                      row.status === 'danger' ? 'text-red-400' :
                      row.status === 'warning' ? 'text-yellow-400' :
                      'text-green-400'
                    }`}>
                      {row.current.toFixed(row.current < 1 ? 4 : 2)}
                    </span>
                  </td>
                  <td className="py-3 text-center">
                    <div className="flex items-center justify-center gap-1">
                      {row.deviation > 0 ? (
                        <TrendingUp size={12} className="text-red-400" />
                      ) : row.deviation < 0 ? (
                        <TrendingDown size={12} className="text-green-400" />
                      ) : (
                        <Minus size={12} className="text-slate-500" />
                      )}
                      <span className={`font-mono text-sm ${
                        row.deviation > 100 ? 'text-red-400' :
                        row.deviation > 0 ? 'text-yellow-400' :
                        'text-green-400'
                      }`}>
                        {row.deviation > 0 ? '+' : ''}{row.deviation.toFixed(0)}%
                      </span>
                    </div>
                  </td>
                  <td className="py-3 text-center">
                    <div className="flex items-center justify-center gap-1">
                      {row.statusIcon}
                      <span className={`text-xs font-medium ${
                        row.status === 'danger' ? 'text-red-400' :
                        row.status === 'warning' ? 'text-yellow-400' :
                        'text-green-400'
                      }`}>
                        {row.statusLabel}
                      </span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        {/* 底部提示 */}
        <div className="p-4 border-t border-slate-700/50 bg-slate-900/50">
          <p className="text-xs text-slate-500 text-center">
            💡 点击异常项可在左侧拓扑图中高亮显示对应的异常节点/边
          </p>
        </div>
      </div>
    </div>
  );
};

export default FeatureDetailModal;
