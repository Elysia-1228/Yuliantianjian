/**
 * PIDS 特征全景图组件 (Feature Panoramic View)
 * 
 * 13x10 的大型发光点阵，展示130维特征向量
 * 支持悬浮显示维度含义和实时数值
 * 
 * 御链天鉴开发团队
 */

import React, { useState, useMemo, useCallback } from 'react';
import { Info, Zap, Activity, AlertTriangle, X } from 'lucide-react';

// 特征组配置
const FEATURE_GROUP_CONFIG = {
  graphStructure: { 
    name: '图结构', 
    range: [0, 15], 
    color: '#3b82f6', // 蓝色
    glowColor: 'rgba(59, 130, 246, 0.6)'
  },
  node: { 
    name: '节点', 
    range: [15, 55], 
    color: '#8b5cf6', // 紫色
    glowColor: 'rgba(139, 92, 246, 0.6)'
  },
  edge: { 
    name: '边', 
    range: [55, 80], 
    color: '#10b981', // 绿色
    glowColor: 'rgba(16, 185, 129, 0.6)'
  },
  sequence: { 
    name: '序列', 
    range: [80, 110], 
    color: '#f59e0b', // 黄色
    glowColor: 'rgba(245, 158, 11, 0.6)'
  },
  semantic: { 
    name: '语义', 
    range: [110, 130], 
    color: '#ef4444', // 红色
    glowColor: 'rgba(239, 68, 68, 0.6)'
  }
};

// 特征维度详细信息
const DIMENSION_LABELS: Record<number, string> = {
  0: '节点数量', 1: '边数量', 2: '图密度', 3: '平均度数', 4: '最大度数',
  5: '最小度数', 6: '最长路径', 7: '平均路径', 8: '连通分量数', 9: '聚类系数',
  10: '图直径', 11: '图半径', 12: '节点边比率', 13: '叶子节点比例', 14: '枢纽节点比例',
  15: '进程节点数', 16: '文件节点数', 17: '套接字节点数', 18: '攻击者节点数', 19: '其他节点数',
  55: '执行边数', 56: '读取边数', 57: '写入边数', 58: '连接边数', 59: 'Fork边数',
  68: '跨层调用频率',
  80: '时间跨度(秒)', 81: '时间跨度(分)', 82: '时间跨度(时)',
  83: '平均间隔', 84: '间隔方差', 85: '最小间隔', 86: '最大间隔',
  90: '爆发次数', 91: '爆发强度', 92: '操作熵', 93: '节点类型熵', 94: '边类型熵',
  98: '周期性评分', 99: '加速评分', 100: '减速评分',
  110: 'SQL注入得分', 111: 'XSS得分', 112: 'WebShell得分', 113: '目录遍历得分',
  114: 'RCE得分', 115: '提权得分', 116: '数据窃取得分', 117: '持久化得分',
  118: '敏感文件访问数', 119: '敏感文件访问率', 120: '关键进程数', 121: '关键进程比例',
  122: '横向移动得分', 123: '侦察得分', 124: '初始阶段', 125: '利用阶段', 126: '后渗透阶段',
  127: '综合威胁得分', 128: '置信度', 129: '异常得分'
};

interface FeaturePanoramicViewProps {
  rawVector: number[];  // 130维原始向量
  featureNames?: string[];
  activeGroup?: string | null;  // 当前激活的特征组
  onDimensionClick?: (dimIndex: number, dimInfo: any) => void;
  onGroupClick?: (groupKey: string) => void;
  compact?: boolean;  // 紧凑模式
}

interface TooltipState {
  visible: boolean;
  x: number;
  y: number;
  dimIndex: number;
  value: number;
  group: string;
  label: string;
}

const FeaturePanoramicView: React.FC<FeaturePanoramicViewProps> = ({
  rawVector = [],
  featureNames = [],
  activeGroup = null,
  onDimensionClick,
  onGroupClick,
  compact = false
}) => {
  const [tooltip, setTooltip] = useState<TooltipState>({
    visible: false, x: 0, y: 0, dimIndex: 0, value: 0, group: '', label: ''
  });
  const [highlightedDims, setHighlightedDims] = useState<Set<number>>(new Set());

  // 获取维度所属组
  const getGroupForDim = useCallback((dimIndex: number): string => {
    for (const [key, config] of Object.entries(FEATURE_GROUP_CONFIG)) {
      if (dimIndex >= config.range[0] && dimIndex < config.range[1]) {
        return key;
      }
    }
    return 'semantic';
  }, []);

  // 获取维度颜色
  const getDimColor = useCallback((dimIndex: number, value: number): string => {
    const group = getGroupForDim(dimIndex);
    const config = FEATURE_GROUP_CONFIG[group as keyof typeof FEATURE_GROUP_CONFIG];
    
    // 根据值的强度调整颜色亮度
    const intensity = Math.min(value, 1);
    if (intensity > 0.7) return '#ef4444'; // 高值 - 红色
    if (intensity > 0.4) return '#f59e0b'; // 中值 - 橙色
    return config.color; // 正常值 - 组颜色
  }, [getGroupForDim]);

  // 获取发光颜色
  const getGlowColor = useCallback((dimIndex: number, value: number): string => {
    const intensity = Math.min(value, 1);
    if (intensity > 0.7) return 'rgba(239, 68, 68, 0.8)';
    if (intensity > 0.4) return 'rgba(245, 158, 11, 0.6)';
    
    const group = getGroupForDim(dimIndex);
    const config = FEATURE_GROUP_CONFIG[group as keyof typeof FEATURE_GROUP_CONFIG];
    return config.glowColor;
  }, [getGroupForDim]);

  // 处理鼠标悬浮
  const handleMouseEnter = useCallback((e: React.MouseEvent, dimIndex: number) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const value = rawVector[dimIndex] || 0;
    const group = getGroupForDim(dimIndex);
    const label = DIMENSION_LABELS[dimIndex] || featureNames[dimIndex] || `维度 ${dimIndex}`;
    
    setTooltip({
      visible: true,
      x: rect.left + rect.width / 2,
      y: rect.top - 10,
      dimIndex,
      value,
      group,
      label
    });
  }, [rawVector, featureNames, getGroupForDim]);

  const handleMouseLeave = useCallback(() => {
    setTooltip(prev => ({ ...prev, visible: false }));
  }, []);

  // 处理点击
  const handleDimClick = useCallback((dimIndex: number) => {
    const value = rawVector[dimIndex] || 0;
    const group = getGroupForDim(dimIndex);
    const label = DIMENSION_LABELS[dimIndex] || featureNames[dimIndex] || `维度 ${dimIndex}`;
    
    if (onDimensionClick) {
      onDimensionClick(dimIndex, { value, group, label });
    }
    
    // 高亮点击的维度
    setHighlightedDims(prev => {
      const newSet = new Set(prev);
      if (newSet.has(dimIndex)) {
        newSet.delete(dimIndex);
      } else {
        newSet.add(dimIndex);
      }
      return newSet;
    });
  }, [rawVector, featureNames, getGroupForDim, onDimensionClick]);

  // 渲染13x10点阵
  const gridCells = useMemo(() => {
    const cells = [];
    const cols = 13;
    const rows = 10;
    
    for (let row = 0; row < rows; row++) {
      for (let col = 0; col < cols; col++) {
        const dimIndex = row * cols + col;
        if (dimIndex >= 130) break;
        
        const value = rawVector[dimIndex] || 0;
        const group = getGroupForDim(dimIndex);
        const isActive = activeGroup === null || activeGroup === group;
        const isHighlighted = highlightedDims.has(dimIndex);
        const color = getDimColor(dimIndex, value);
        const glowColor = getGlowColor(dimIndex, value);
        const intensity = Math.min(value, 1);
        
        cells.push(
          <div
            key={dimIndex}
            className={`
              relative cursor-pointer transition-all duration-300 rounded-sm
              ${isActive ? 'opacity-100' : 'opacity-30'}
              ${isHighlighted ? 'ring-2 ring-white ring-offset-1 ring-offset-slate-900 z-10' : ''}
            `}
            style={{
              width: compact ? '16px' : '24px',
              height: compact ? '16px' : '24px',
              backgroundColor: color,
              opacity: isActive ? 0.3 + intensity * 0.7 : 0.2,
              boxShadow: isActive && intensity > 0.3 
                ? `0 0 ${compact ? 6 : 10}px ${glowColor}, inset 0 0 ${compact ? 3 : 5}px rgba(255,255,255,0.3)` 
                : 'none',
              transform: isHighlighted ? 'scale(1.2)' : 'scale(1)'
            }}
            onMouseEnter={(e) => handleMouseEnter(e, dimIndex)}
            onMouseLeave={handleMouseLeave}
            onClick={() => handleDimClick(dimIndex)}
          >
            {/* 高亮脉冲动画 */}
            {isHighlighted && (
              <div 
                className="absolute inset-0 rounded-sm animate-ping"
                style={{ backgroundColor: color, opacity: 0.5 }}
              />
            )}
          </div>
        );
      }
    }
    return cells;
  }, [rawVector, activeGroup, highlightedDims, compact, getGroupForDim, getDimColor, getGlowColor, handleMouseEnter, handleMouseLeave, handleDimClick]);

  // 图例
  const legend = useMemo(() => (
    <div className={`flex flex-wrap gap-2 ${compact ? 'text-[10px]' : 'text-xs'}`}>
      {Object.entries(FEATURE_GROUP_CONFIG).map(([key, config]) => (
        <div
          key={key}
          className={`
            flex items-center gap-1 px-2 py-1 rounded cursor-pointer transition-all
            ${activeGroup === key ? 'ring-1 ring-white/50 bg-white/10' : 'hover:bg-white/5'}
          `}
          onClick={() => onGroupClick?.(key)}
        >
          <div 
            className="w-3 h-3 rounded-sm"
            style={{ backgroundColor: config.color }}
          />
          <span className="text-slate-300">{config.name}</span>
          <span className="text-slate-500">
            ({config.range[1] - config.range[0]}维)
          </span>
        </div>
      ))}
    </div>
  ), [activeGroup, compact, onGroupClick]);

  return (
    <div className={`relative ${compact ? 'p-2' : 'p-4'} bg-slate-900/80 rounded-xl border border-slate-700/50`}>
      {/* 标题 */}
      <div className={`flex items-center justify-between ${compact ? 'mb-2' : 'mb-4'}`}>
        <div className="flex items-center gap-2">
          <Activity className={`${compact ? 'w-4 h-4' : 'w-5 h-5'} text-cyan-400`} />
          <span className={`font-bold text-white ${compact ? 'text-sm' : 'text-base'}`}>
            特征全景图
          </span>
          <span className="text-slate-500 text-xs">(130维)</span>
        </div>
        {!compact && (
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Info size={12} />
            <span>悬浮查看详情，点击高亮</span>
          </div>
        )}
      </div>

      {/* 13x10 点阵 */}
      <div 
        className="grid gap-1 mx-auto"
        style={{ 
          gridTemplateColumns: `repeat(13, ${compact ? '16px' : '24px'})`,
          width: 'fit-content'
        }}
      >
        {gridCells}
      </div>

      {/* 图例 */}
      <div className={`${compact ? 'mt-2' : 'mt-4'}`}>
        {legend}
      </div>

      {/* 悬浮提示框 */}
      {tooltip.visible && (
        <div
          className="fixed z-50 pointer-events-none"
          style={{
            left: tooltip.x,
            top: tooltip.y,
            transform: 'translate(-50%, -100%)'
          }}
        >
          <div className="bg-slate-950 border border-cyan-500/50 rounded-lg p-3 shadow-xl min-w-[180px]">
            <div className="flex items-center gap-2 mb-2 pb-2 border-b border-slate-700">
              <Zap size={14} className="text-cyan-400" />
              <span className="text-cyan-400 font-bold text-sm">
                dim_{tooltip.dimIndex}
              </span>
            </div>
            <div className="space-y-1 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-400">名称:</span>
                <span className="text-white font-medium">{tooltip.label}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">数值:</span>
                <span className={`font-mono font-bold ${
                  tooltip.value > 0.7 ? 'text-red-400' : 
                  tooltip.value > 0.4 ? 'text-yellow-400' : 'text-green-400'
                }`}>
                  {tooltip.value.toFixed(4)}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">分组:</span>
                <span className="text-purple-400">
                  {FEATURE_GROUP_CONFIG[tooltip.group as keyof typeof FEATURE_GROUP_CONFIG]?.name || tooltip.group}
                </span>
              </div>
            </div>
            {/* 提示箭头 */}
            <div className="absolute left-1/2 bottom-0 transform -translate-x-1/2 translate-y-full">
              <div className="border-8 border-transparent border-t-slate-950" />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default FeaturePanoramicView;
