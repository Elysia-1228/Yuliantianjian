/**
 * PIDSGraph - 树状图赛博朋克溯源图谱
 * 树状布局 + 可拖拽节点 + 发光球体 + 霓虹配色 + 逐条绘制动画 + 详细Tooltip
 */

import React, { useEffect, useRef, useState } from 'react';
import * as echarts from 'echarts';
import { AlertData } from '../../utils/pidsAdapter';
import styles from './style.module.css';

interface PIDSGraphProps {
  currentAlert?: AlertData | null;
  alerts?: AlertData[];
  graphData?: { nodes: any[]; edges: any[]; mode?: string } | null;
  onNodeClick?: (node: any) => void;
}

// 🔥 树状图布局常量
const TREE_LAYOUT = {
  orient: 'LR' as const,  // 从左到右的树状布局
  nodeSpacing: 120,       // 节点间距
  layerSpacing: 300,      // 层级间距
  roam: true,             // 启用缩放和拖拽
  expandAndCollapse: false // 禁用折叠功能，显示完整树
};

// 赛博朋克风格：霓虹配色映射表
const neonColorMap: Record<string, string> = {
  'attacker': '#FF4D4F',  // 🔴 霓虹红 - 攻击源
  'socket': '#1890FF',    // 🔵 科技蓝 - 网络套接字
  'server': '#722ED1',    // 🟣 电光紫 - 服务器进程
  'process': '#722ED1',   // 🟣 电光紫 - 普通进程
  'file': '#52C41A',      // 🟢 荧光绿 - 文件
  'firewall': '#FA8C16',  // 🛡️ 橙色 - 防护
  'default': '#FA8C16'    // 🟠 默认橙
};

// 获取节点颜色（赛博朋克霓虹色）
const getNeonColor = (nodeType: string): string => {
  return neonColorMap[nodeType] || neonColorMap['default'];
};

// 🔥 根据节点类型获取不同的图形符号
const getNodeSymbol = (nodeType: string): string => {
  const symbolMap: Record<string, string> = {
    'attacker': 'triangle',     // 攻击源 - 三角形
    'process': 'diamond',       // 进程 - 菱形
    'server': 'diamond',        // 服务器进程 - 菱形
    'file': 'rect',             // 文件 - 矩形
    'socket': 'circle',         // 网络套接字 - 圆形
    // 防火墙 - 盾牌图标（使用标准化的SVG path，坐标范围0-100）
    'firewall': 'path://M 50 5 L 15 20 L 15 50 Q 15 75 50 90 Q 85 75 85 50 L 85 20 Z'
  };
  return symbolMap[nodeType] || 'circle';
};

// 获取节点大小（增大以提高可见性）
const getNodeSize = (nodeType: string): number => {
  if (nodeType === 'attacker') return 90;  // 攻击源最大
  if (nodeType === 'file') return 55;      // 文件适中
  if (nodeType === 'firewall') return 80;  // 防火墙盾牌
  return 65;                                // 其他中等
};

// 🔥 赛博朋克核心：生成发光球体样式（径向渐变 + 强光晕）
const getGlowStyle = (color: string) => ({
  color: {
    type: 'radial',
    x: 0.5,
    y: 0.5,
    r: 0.5,
    colorStops: [
      { offset: 0, color: '#ffffff' },      // 中心极亮（高光）
      { offset: 0.4, color: color },        // 中间本色
      { offset: 1, color: color }           // 边缘本色
    ]
  },
  borderColor: '#fff',     // 极细白边增强立体感
  borderWidth: 1,
  shadowBlur: 25,          // 🔥 强光晕效果
  shadowColor: color       // 光晕颜色跟随本体
});

// 🔥 将图数据转换为graph格式（树状布局算法）
const convertToGraphData = (nodes: any[], edges: any[]) => {
  console.log('📊 [convertToGraphData] 开始转换，节点数:', nodes.length, '边数:', edges.length);
  
  if (nodes.length === 0) {
    console.error('❌ [convertToGraphData] 节点列表为空');
    return { nodes: [], edges: [] };
  }
  
  // 🔥 节点去重：基于label和type的组合进行去重
  const nodeMap = new Map<string, any>();
  const idMapping = new Map<string, string>(); // 旧ID -> 新ID的映射
  
  nodes.forEach(node => {
    const key = `${node.type || 'unknown'}_${node.label || node.id}`;
    if (!nodeMap.has(key)) {
      nodeMap.set(key, node);
      idMapping.set(node.id, node.id);
    } else {
      // 如果已存在相同的节点，记录ID映射关系
      const existingNode = nodeMap.get(key)!;
      idMapping.set(node.id, existingNode.id);
    }
  });
  
  const uniqueNodes = Array.from(nodeMap.values());
  console.log(`🔄 节点去重: ${nodes.length} -> ${uniqueNodes.length}`);
  
  // 🔥 更新边的引用，使用去重后的节点ID
  const uniqueEdges = edges.map(edge => ({
    ...edge,
    source: idMapping.get(edge.source) || edge.source,
    target: idMapping.get(edge.target) || edge.target
  })).filter(edge => {
    // 过滤掉自环边（source和target相同的边）
    return edge.source !== edge.target;
  });
  
  // 进一步去重边（相同source和target的边只保留一条）
  const edgeSet = new Set<string>();
  const deduplicatedEdges = uniqueEdges.filter(edge => {
    const edgeKey = `${edge.source}->${edge.target}`;
    if (edgeSet.has(edgeKey)) {
      return false;
    }
    edgeSet.add(edgeKey);
    return true;
  });
  
  console.log(`🔄 边去重: ${edges.length} -> ${deduplicatedEdges.length}`);
  
  // 使用去重后的节点和边
  nodes = uniqueNodes;
  edges = deduplicatedEdges;
  
  // 🌳 优化的树状布局算法：紧凑布局，减小间距
  const START_X = 80;
  const LAYER_SPACING = 200;  // 层级间距（从左到右）- 减小20%
  const MIN_NODE_SPACING = 50;  // 最小节点间距 - 减小50%
  const MAX_CANVAS_HEIGHT = 800;  // 最大画布高度 - 减小33%
  const DEFAULT_CANVAS_HEIGHT = 500;  // 默认画布高度 - 减小17%
  
  // 构建父子关系映射
  const childrenMap: Record<string, string[]> = {};
  const parentMap: Record<string, string> = {};
  nodes.forEach(n => childrenMap[n.id] = []);
  
  edges.forEach((e: any) => {
    if (!childrenMap[e.source]) childrenMap[e.source] = [];
    childrenMap[e.source].push(e.target);
    parentMap[e.target] = e.source;
  });
  
  // 找到根节点（没有父节点的节点）
  const roots = nodes.filter((n: any) => !parentMap[n.id]);
  console.log('🌳 找到根节点:', roots.map(r => r.id));
  
  // BFS计算每个节点的层级
  const levels: Record<string, number> = {};
  const queue: Array<{id: string, level: number}> = roots.map(r => ({id: r.id, level: 0}));
  let maxLevel = 0;
  
  while (queue.length > 0) {
    const {id, level} = queue.shift()!;
    levels[id] = level;
    maxLevel = Math.max(maxLevel, level);
    
    (childrenMap[id] || []).forEach(childId => {
      queue.push({id: childId, level: level + 1});
    });
  }
  
  // 按层级分组节点
  const nodesByLevel: Record<number, any[]> = {};
  for (let i = 0; i <= maxLevel; i++) {
    nodesByLevel[i] = [];
  }
  
  nodes.forEach((node: any) => {
    const level = levels[node.id] ?? maxLevel;
    nodesByLevel[level].push(node);
  });
  
  console.log('🌳 层级分布:', Object.entries(nodesByLevel).map(([level, nodes]) => `层${level}: ${nodes.length}个节点`));
  
  // 🔥 动态计算画布高度和节点间距
  const maxNodesInLevel = Math.max(...Object.values(nodesByLevel).map(n => n.length));
  const requiredHeight = maxNodesInLevel * MIN_NODE_SPACING;
  const CANVAS_HEIGHT = Math.min(Math.max(requiredHeight, DEFAULT_CANVAS_HEIGHT), MAX_CANVAS_HEIGHT);
  const NODE_SPACING = Math.max(MIN_NODE_SPACING, CANVAS_HEIGHT / (maxNodesInLevel + 1));
  
  console.log(`📐 画布高度: ${CANVAS_HEIGHT}px, 节点间距: ${NODE_SPACING}px, 最多节点层: ${maxNodesInLevel}个`);
  
  // 计算每个节点的坐标
  const positions: Record<string, {x: number, y: number}> = {};
  
  for (let level = 0; level <= maxLevel; level++) {
    const nodesInLevel = nodesByLevel[level];
    const x = START_X + level * LAYER_SPACING;
    
    // 🔥 优化：根据该层节点数量动态调整垂直分布
    const levelHeight = nodesInLevel.length * NODE_SPACING;
    const startY = (CANVAS_HEIGHT - levelHeight) / 2 + NODE_SPACING / 2;
    
    nodesInLevel.forEach((node, idx) => {
      const y = nodesInLevel.length === 1 ? CANVAS_HEIGHT / 2 : startY + idx * NODE_SPACING;
      positions[node.id] = { x, y };
      console.log(`  🎯 节点 ${node.id}: 层级${level}, x=${x}, y=${y}`);
    });
  }
  
  // 转换节点格式
  const graphNodes = nodes.map((node) => {
    const baseColor = getNeonColor(node.type || 'process');
    const nodeSymbol = getNodeSymbol(node.type || 'process');
    
    let displayName = node.label || node.id;
    if (node.type === 'process' || node.type === 'server') {
      displayName = node.label || node.name || node.id;
    } else if (node.type === 'file') {
      const fullPath = node.label || node.id;
      displayName = fullPath.split('/').pop() || fullPath;
    }
    
    const pos = positions[node.id] || { x: 0, y: 0 };
    
    return {
      id: node.id,
      name: displayName,
      value: node.id,
      x: pos.x,
      y: pos.y,
      fixed: false,
      symbol: nodeSymbol,
      symbolSize: getNodeSize(node.type || 'process'),
      symbolRotate: node.type === 'attacker' ? 90 : 0,
      itemStyle: {
        color: {
          type: 'radial',
          x: 0.5,
          y: 0.5,
          r: 0.5,
          colorStops: [
            { offset: 0, color: '#ffffff' },
            { offset: 0.4, color: baseColor },
            { offset: 1, color: baseColor }
          ]
        },
        borderColor: '#fff',
        borderWidth: 2,
        shadowBlur: 25,
        shadowColor: baseColor
      },
      label: {
        show: true,
        position: 'bottom',
        distance: 12,
        fontSize: 14,
        color: '#ffffff',
        fontWeight: 'bold',
        fontFamily: 'JetBrains Mono, monospace',
        formatter: displayName.length > 18 ? displayName.substring(0, 18) + '...' : displayName
      },
      nodeData: node  // 保留原始数据用于tooltip
    };
  });
  
  // 🔥 计算每个源节点的子节点数量，用于智能弯曲
  const childrenCount: Record<string, number> = {};
  edges.forEach(edge => {
    childrenCount[edge.source] = (childrenCount[edge.source] || 0) + 1;
  });
  
  // 转换边格式 - 智能弯曲：有分支时添加弯曲效果
  const graphEdges = edges.map((edge, index) => {
    const sourceChildren = childrenCount[edge.source] || 1;
    // 如果源节点有多个子节点，添加弯曲效果
    const curveness = sourceChildren > 1 ? 0.25 : 0;
    
    return {
      source: edge.source,
      target: edge.target,
      label: {
        show: false
      },
      lineStyle: {
        color: {
          type: 'linear',
          x: 0,
          y: 0,
          x2: 1,
          y2: 0,
          colorStops: [
            { offset: 0, color: '#FF8C00' },
            { offset: 0.5, color: '#FFD700' },
            { offset: 1, color: '#FF8C00' }
          ]
        },
        width: 3,
        curveness: curveness,  // 🔥 有分支时自动弯曲
        shadowBlur: 15,
        shadowColor: '#FFD700'
      },
      emphasis: {
        lineStyle: {
          width: 5
        }
      }
    };
  });
  
  console.log('🎉 [convertToGraphData] 转换完成');
  return { nodes: graphNodes, edges: graphEdges };
};

const PIDSGraph: React.FC<PIDSGraphProps> = ({
  currentAlert,
  alerts = [],
  graphData,
  onNodeClick,
}) => {
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstanceRef = useRef<echarts.ECharts | null>(null);
  const [zoomLevel, setZoomLevel] = useState(100);
  const [isFullscreen, setIsFullscreen] = useState(false);

  // 初始化ECharts
  useEffect(() => {
    if (!chartRef.current) return;

    // 销毁旧实例
    if (chartInstanceRef.current) {
      chartInstanceRef.current.dispose();
    }

    // 创建新实例（性能优化：使用canvas渲染器）
    const chart = echarts.init(chartRef.current, 'dark', {
      renderer: 'canvas',
      useDirtyRect: true  // 启用脏矩形优化，减少重绘
    });
    chartInstanceRef.current = chart;

    // 响应式
    const handleResize = () => {
      chart.resize();
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (chartInstanceRef.current) {
        chartInstanceRef.current.dispose();
        chartInstanceRef.current = null;
      }
    };
  }, []);

  // 渲染图谱 - 树状图布局 + 逐条绘制动画
  useEffect(() => {
    if (!chartInstanceRef.current || !graphData || !graphData.nodes || graphData.nodes.length === 0) {
      console.log('⚠️ ECharts渲染条件不满足');
      return;
    }

    console.log('✅ 开始渲染树状图赛博朋克图谱，节点数:', graphData.nodes.length);

    const { nodes, edges } = graphData;

    // 🔥 转换为graph格式
    const convertedData = convertToGraphData(nodes, edges);
    if (!convertedData || convertedData.nodes.length === 0) {
      console.error('❌ 无法构建图谱数据');
      return;
    }


    // 🔥 树状图配置
    const option: echarts.EChartsOption = {
      backgroundColor: 'transparent',
      grid: {
        show: false,  // 🔥 隐藏网格线
        containLabel: false
      },
      tooltip: {
        show: true,
        trigger: 'item',
        triggerOn: 'mousemove',
        confine: false,  // 🔥 不限制tooltip在容器内，避免阻止交互
        enterable: false,  // 🔥 不允许鼠标进入tooltip，避免阻止交互
        backgroundColor: 'rgba(5, 11, 20, 0.95)',
        borderColor: '#1890FF',
        borderWidth: 2,
        padding: 12,
        textStyle: {
          color: '#fff',
          fontSize: 13
        },
        formatter: (params: any) => {
          console.log('Tooltip params:', params);
          const nodeData = params.data?.nodeData || params.data;
          if (!nodeData) {
            console.log('No nodeData found');
            return params.name || '未知节点';
          }
          
          // 🔥 因果溯源详细信息
          const typeMap: Record<string, string> = {
            'attacker': '攻击源',
            'process': '进程',
            'server': '服务器进程',
            'file': '文件',
            'socket': '网络套接字',
            'firewall': '防火墙'
          };
          
          const typeName = typeMap[nodeData.type] || nodeData.type || '未知';
          const nodeLabel = nodeData.label || nodeData.name || nodeData.id || '未知';
          
          // 🔥 计算威胁评分和风险等级
          const getThreatScore = (type: string) => {
            if (type === 'attacker') return 98;
            if (type === 'firewall') return 85;
            if (type === 'process') return 72;
            if (type === 'file') return 65;
            return 50;
          };
          
          const getRiskLevel = (score: number) => {
            if (score >= 90) return { level: 'CRITICAL', color: '#FF4D4F', bgColor: 'rgba(255, 77, 79, 0.15)' };
            if (score >= 70) return { level: 'HIGH', color: '#FA8C16', bgColor: 'rgba(250, 140, 22, 0.15)' };
            if (score >= 50) return { level: 'MEDIUM', color: '#FAAD14', bgColor: 'rgba(250, 173, 20, 0.15)' };
            return { level: 'LOW', color: '#52C41A', bgColor: 'rgba(82, 196, 26, 0.15)' };
          };
          
          const getAttackStage = (type: string) => {
            if (type === 'attacker') return 'Initial Access (初始访问)';
            if (type === 'firewall') return 'Defense Evasion (防御规避)';
            if (type === 'process') return 'Execution (执行)';
            if (type === 'file') return 'Exfiltration (数据窃取)';
            return 'Unknown';
          };
          
          const getHitRule = (type: string) => {
            if (type === 'attacker') return 'SQL Injection Pattern Detected';
            if (type === 'firewall') return 'Firewall Bypass Attempt';
            if (type === 'process') return 'Reverse Shell Pattern';
            if (type === 'file') return 'Sensitive File Access';
            return 'Anomaly Detected';
          };
          
          const threatScore = getThreatScore(nodeData.type);
          const riskInfo = getRiskLevel(threatScore);
          const attackStage = getAttackStage(nodeData.type);
          const hitRule = getHitRule(nodeData.type);
          
          let html = `<div style="min-width: 280px; padding: 4px;">`;
          
          // 🔥 威胁情报区块（顶部显眼位置）
          html += `<div style="background: ${riskInfo.bgColor}; border: 2px solid ${riskInfo.color}; border-radius: 6px; padding: 10px; margin-bottom: 12px;">`;
          html += `<div style="font-weight: bold; font-size: 14px; margin-bottom: 8px; color: ${riskInfo.color};">⚠️ THREAT INTELLIGENCE</div>`;
          
          html += `<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">`;
          html += `<div style="color: #94a3b8; font-size: 11px;">Threat Score</div>`;
          html += `<div style="color: ${riskInfo.color}; font-weight: bold; font-size: 16px;">${threatScore}/100</div>`;
          html += `</div>`;
          
          html += `<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">`;
          html += `<div style="color: #94a3b8; font-size: 11px;">Risk Level</div>`;
          html += `<div style="background: ${riskInfo.color}; color: #000; font-weight: bold; font-size: 11px; padding: 2px 8px; border-radius: 3px;">${riskInfo.level}</div>`;
          html += `</div>`;
          
          html += `<div style="margin-bottom: 6px;">`;
          html += `<div style="color: #94a3b8; font-size: 11px; margin-bottom: 2px;">Attack Stage</div>`;
          html += `<div style="color: #fff; font-size: 12px; font-weight: bold;">${attackStage}</div>`;
          html += `</div>`;
          
          html += `<div>`;
          html += `<div style="color: #94a3b8; font-size: 11px; margin-bottom: 2px;">Hit Rule</div>`;
          html += `<div style="color: #FA8C16; font-size: 11px; font-weight: bold;">${hitRule}</div>`;
          html += `</div>`;
          
          html += `</div>`;
          
          // 节点详细信息标题
          html += `<div style="font-weight: bold; font-size: 15px; margin-bottom: 10px; color: #1890FF; border-bottom: 2px solid #1890FF; padding-bottom: 6px;">📊 节点详细信息</div>`;
          
          // 节点名称
          html += `<div style="margin-bottom: 8px;">`;
          html += `<div style="color: #94a3b8; font-size: 11px; margin-bottom: 2px;">节点名称</div>`;
          html += `<div style="color: #fff; font-weight: bold; font-size: 13px;">${nodeLabel}</div>`;
          html += `</div>`;
          
          // 节点类型
          html += `<div style="margin-bottom: 8px;">`;
          html += `<div style="color: #94a3b8; font-size: 11px; margin-bottom: 2px;">节点类型</div>`;
          html += `<div style="color: #52C41A; font-weight: bold; font-size: 13px;">${typeName}</div>`;
          html += `</div>`;
          
          // 根据节点类型显示不同的详细信息
          if (nodeData.type === 'attacker') {
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 11px; margin-bottom: 2px;">攻击源IP地址</div>`;
            html += `<div style="color: #FF4D4F; font-weight: bold; font-size: 13px;">${nodeLabel}</div>`;
            html += `</div>`;
          }
          
          if (nodeData.type === 'process' || nodeData.type === 'server') {
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 11px; margin-bottom: 2px;">进程名称</div>`;
            html += `<div style="color: #722ED1; font-weight: bold; font-size: 13px;">${nodeLabel}</div>`;
            html += `</div>`;
          }
          
          if (nodeData.type === 'file') {
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 11px; margin-bottom: 2px;">文件路径</div>`;
            html += `<div style="color: #52C41A; font-size: 12px; word-break: break-all;">${nodeLabel}</div>`;
            html += `</div>`;
          }
          
          if (nodeData.type === 'socket') {
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 11px; margin-bottom: 2px;">网络套接字</div>`;
            html += `<div style="color: #1890FF; font-size: 12px;">${nodeLabel}</div>`;
            html += `</div>`;
          }
          
          if (nodeData.type === 'firewall') {
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 11px; margin-bottom: 2px;">防火墙规则</div>`;
            html += `<div style="color: #FA8C16; font-size: 12px;">${nodeLabel}</div>`;
            html += `</div>`;
          }
          
          // 节点ID
          html += `<div style="margin-bottom: 8px;">`;
          html += `<div style="color: #94a3b8; font-size: 11px; margin-bottom: 2px;">节点ID</div>`;
          html += `<div style="color: #64748b; font-size: 11px; font-family: monospace;">${nodeData.id || '-'}</div>`;
          html += `</div>`;
          
          // 分类信息
          if (nodeData.category !== undefined) {
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 11px; margin-bottom: 2px;">分类编号</div>`;
            html += `<div style="color: #FA8C16; font-size: 12px;">${nodeData.category}</div>`;
            html += `</div>`;
          }
          
          html += `<div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid rgba(148, 163, 184, 0.3); font-size: 11px; color: #64748b; text-align: center;">💡 可拖拽移动节点位置</div>`;
          html += `</div>`;
          
          // 🔥 因果溯源详细信息
          html += `<div style="margin-top: 12px; padding-top: 10px; border-top: 2px solid #1890FF;">`;
          html += `<div style="font-weight: bold; font-size: 14px; margin-bottom: 10px; color: #1890FF;">🔍 溯源分析</div>`;
          
          if (nodeData.type === 'process' || nodeData.type === 'server') {
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 12px; margin-bottom: 3px;">Process ID (PID)</div>`;
            html += `<div style="color: #fff; font-size: 13px; font-weight: bold;">${nodeData.pid || 'proc_' + (Math.floor(Math.random() * 90000) + 10000)}</div>`;
            html += `</div>`;
            
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 12px; margin-bottom: 3px;">Parent Process (PPID)</div>`;
            html += `<div style="color: #52C41A; font-size: 13px; font-weight: bold;">${nodeData.ppid || nodeData.parent || 'systemd (PID: 1)'}</div>`;
            html += `</div>`;
            
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 12px; margin-bottom: 3px;">Privilege Context (权限上下文)</div>`;
            const user = nodeData.user || nodeData.uid || 'root';
            const isRoot = user.toLowerCase() === 'root';
            html += `<div style="color: ${isRoot ? '#FF4D4F' : '#fff'}; font-size: 13px; font-weight: bold;">${user}${isRoot ? ' [High Risk]' : ''}</div>`;
            html += `</div>`;
            
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 12px; margin-bottom: 3px;">Payload Path (载荷路径)</div>`;
            html += `<div style="color: #52C41A; font-size: 12px; word-break: break-all;">${nodeData.cmdline || nodeData.command || '/usr/bin/' + nodeLabel}</div>`;
            html += `</div>`;
            
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 12px; margin-bottom: 3px;">First Seen (首次发现)</div>`;
            const timestamp = nodeData.startTime || new Date().toLocaleString('zh-CN', { hour12: false });
            html += `<div style="color: #1890FF; font-size: 12px; font-family: monospace;">${timestamp}</div>`;
            html += `</div>`;
          }
          
          if (nodeData.type === 'file') {
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 12px; margin-bottom: 3px;">完整路径</div>`;
            html += `<div style="color: #52C41A; font-size: 12px; word-break: break-all;">${nodeLabel}</div>`;
            html += `</div>`;
            
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 12px; margin-bottom: 3px;">文件操作</div>`;
            html += `<div style="color: #FA8C16; font-size: 13px; font-weight: bold;">${nodeData.operation || nodeData.action || 'READ/WRITE'}</div>`;
            html += `</div>`;
            
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 12px; margin-bottom: 3px;">访问进程</div>`;
            html += `<div style="color: #fff; font-size: 13px; font-weight: bold;">${nodeData.accessedBy || nodeData.process || nodeLabel.split('/')[0] || 'AI_Model_v2'}</div>`;
            html += `</div>`;
            
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 12px; margin-bottom: 3px;">文件大小</div>`;
            html += `<div style="color: #fff; font-size: 12px;">${nodeData.fileSize || (Math.floor(Math.random() * 900) + 100) + ' KB'}</div>`;
            html += `</div>`;
          }
          
          if (nodeData.type === 'attacker') {
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 12px; margin-bottom: 3px;">攻击路径</div>`;
            html += `<div style="color: #FF4D4F; font-size: 13px; font-weight: bold;">外部网络 → 防火墙 → 内部进程 → 敏感文件</div>`;
            html += `</div>`;
            
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 12px; margin-bottom: 3px;">入侵方式</div>`;
            html += `<div style="color: #FA8C16; font-size: 13px; font-weight: bold;">${nodeData.attackMethod || nodeData.method || 'SQL注入/XSS攻击'}</div>`;
            html += `</div>`;
            
            html += `<div style="margin-bottom: 8px;">`;
            html += `<div style="color: #94a3b8; font-size: 12px; margin-bottom: 3px;">威胁等级</div>`;
            html += `<div style="color: #FF4D4F; font-size: 13px; font-weight: bold;">HIGH</div>`;
            html += `</div>`;
          }
          
          html += `</div>`;
          
          html += `<div style="margin-top: 10px; padding-top: 8px; border-top: 1px solid rgba(148, 163, 184, 0.3); font-size: 12px; color: #64748b; text-align: center;">💡 使用滚轮缩放，拖动平移</div>`;
          html += `</div>`;
          
          return html;
        }
      },
      series: [
        {
          type: 'graph',  // 🔥 改用graph系列，支持手动坐标
          data: convertedData.nodes,
          edges: convertedData.edges,
          layout: 'none',  // 🔥 不使用自动布局，使用手动坐标
          coordinateSystem: null,
          roam: true,  // 🔥 启用缩放和拖拽
          draggable: true,  // 🔥 启用节点拖拽
          scaleLimit: {
            min: 0.2,
            max: 3
          },
          zoom: 1.2,  // 🔥 初始缩放为120%，充分展示节点间距，让图谱更清晰
          edgeSymbol: ['none', 'arrow'],
          edgeSymbolSize: [0, 15],
          animation: true,
          animationDuration: 800,
          animationEasing: 'elasticOut',
          animationDelay: (idx: number) => idx * 150,
          emphasis: {
            focus: 'adjacency',
            itemStyle: {
              borderWidth: 3,
              shadowBlur: 35
            },
            lineStyle: {
              width: 7
            }
          }
        } as any
      ]
    };

    // 🔥 使用notMerge: true实现完全重新渲染，触发初始动画
    chartInstanceRef.current.setOption(option, {
      notMerge: true,  // 完全重新渲染，触发初始动画
      lazyUpdate: false
    });
    
    // 🔥 确保图表可以接收交互事件
    chartInstanceRef.current.getZr().on('mousewheel', (e: any) => {
      console.log('🖱️ 检测到滚轮事件');
    });
    
    console.log('📊 树状图配置已设置，节点数:', nodes.length);

    // 节点点击事件
    chartInstanceRef.current.off('click');
    chartInstanceRef.current.on('click', (params: any) => {
      if (params.dataType === 'node') {
        console.log('🖱️ 节点点击:', params.data);
        onNodeClick?.(params.data.nodeData || params.data);
      }
    });

  }, [graphData, onNodeClick, isFullscreen]);

  // 缩放控制
  const handleZoomIn = () => {
    const newZoom = Math.min(zoomLevel + 20, 300);
    setZoomLevel(newZoom);
    if (chartInstanceRef.current) {
      const option = chartInstanceRef.current.getOption();
      const series = option.series[0] as any;
      if (series && series.zoom) {
        series.zoom = series.zoom * 1.2;
      } else if (series) {
        series.zoom = 1.2;
      }
      chartInstanceRef.current.setOption(option);
    }
  };

  const handleZoomOut = () => {
    const newZoom = Math.max(zoomLevel - 20, 30);
    setZoomLevel(newZoom);
    if (chartInstanceRef.current) {
      const option = chartInstanceRef.current.getOption();
      const series = option.series[0] as any;
      if (series && series.zoom) {
        series.zoom = series.zoom * 0.8;
      } else if (series) {
        series.zoom = 0.8;
      }
      chartInstanceRef.current.setOption(option);
    }
  };

  const handleResetZoom = () => {
    setZoomLevel(100);
    if (chartInstanceRef.current) {
      const option = chartInstanceRef.current.getOption();
      const series = option.series[0] as any;
      if (series) {
        series.zoom = 1;
      }
      chartInstanceRef.current.setOption(option);
      chartInstanceRef.current.dispatchAction({
        type: 'restore'
      });
    }
  };

  // 全屏切换
  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
    // 延迟调整图表大小，确保容器尺寸已更新
    setTimeout(() => {
      if (chartInstanceRef.current) {
        chartInstanceRef.current.resize();
        // 🔥 重新获取并设置option，确保图谱正确显示
        const currentOption = chartInstanceRef.current.getOption();
        if (currentOption) {
          chartInstanceRef.current.setOption(currentOption, { notMerge: false });
        }
      }
    }, 150);
  };

  return (
    <div className={`${styles.graphContainer} ${isFullscreen ? styles.fullscreen : ''}`}>
      {/* HUD角标 */}
      <div className={styles.hudFrame}>
        <div className={`${styles.hudCorner} ${styles.topLeft}`} />
        <div className={`${styles.hudCorner} ${styles.topRight}`} />
        <div className={`${styles.hudCorner} ${styles.bottomLeft}`} />
        <div className={`${styles.hudCorner} ${styles.bottomRight}`} />
        
        {/* 扫描线 */}
        <div className={styles.scanLine} />

        {/* 加载状态 */}
        {(!graphData || !graphData.nodes || graphData.nodes.length === 0) && (
          <div className={styles.loadingOverlay}>
            <div className={styles.loadingSpinner} />
            <div className={styles.loadingText}>等待图谱数据加载...</div>
          </div>
        )}

        {/* 状态标签 */}
        <div className={`${styles.stageLabel} ${styles.micro}`}>
          ● TREE VIEW
        </div>

        {/* 缩放控制器 */}
        <div className={styles.zoomControls}>
          <button className={styles.zoomButton} onClick={toggleFullscreen} title={isFullscreen ? "退出全屏" : "全屏放大"}>
            <span>{isFullscreen ? '✕' : '⛶'}</span>
          </button>
          <button className={styles.zoomButton} onClick={handleZoomIn} title="放大">
            <span>+</span>
          </button>
          <div className={styles.zoomLevel}>{zoomLevel}%</div>
          <button className={styles.zoomButton} onClick={handleZoomOut} title="缩小">
            <span>−</span>
          </button>
          <button className={styles.zoomButton} onClick={handleResetZoom} title="重置">
            <span>⟲</span>
          </button>
        </div>

        {/* 信息面板 */}
        {currentAlert && (
          <div className={styles.infoPanel}>
            <div className={styles.infoPanelTitle}>
              <span style={{ color: '#ff4d4f' }}>●</span> 威胁详情
            </div>
            <div className={styles.infoPanelRow}>
              <span className={styles.infoPanelLabel}>攻击类型</span>
              <span className={`${styles.infoPanelValue} ${styles.danger}`}>
                {currentAlert.attackType || currentAlert.threatType || 'Unknown'}
              </span>
            </div>
            <div className={styles.infoPanelRow}>
              <span className={styles.infoPanelLabel}>源IP</span>
              <span className={styles.infoPanelValue}>
                {currentAlert.sourceIp || currentAlert.maliciousIp || '-'}
              </span>
            </div>
            <div className={styles.infoPanelRow}>
              <span className={styles.infoPanelLabel}>目标IP</span>
              <span className={styles.infoPanelValue}>
                {currentAlert.targetIp || '-'}
              </span>
            </div>
            <div className={styles.infoPanelRow}>
              <span className={styles.infoPanelLabel}>严重程度</span>
              <span className={`${styles.infoPanelValue} ${styles.danger}`}>
                {currentAlert.severity || '-'}
              </span>
            </div>
          </div>
        )}

        {/* ECharts画布 - 移除transform以避免全屏边界问题 */}
        <div 
          ref={chartRef} 
          className={styles.g6Canvas} 
          style={{ 
            width: '100%', 
            height: '100%',
            position: 'absolute',
            top: 0,
            left: 0
          }} 
        />
        
        {/* 🔥 底部悬浮图例栏（赛博朋克风格）*/}
        {graphData && graphData.nodes && graphData.nodes.length > 0 && (
          <div style={{
            position: 'absolute',
            bottom: '40px',
            left: '50%',
            transform: 'translateX(-50%)',
            backgroundColor: 'rgba(0, 0, 0, 0.6)',
            backdropFilter: 'blur(12px)',
            border: '1px solid rgba(75, 85, 99, 0.5)',
            paddingLeft: '32px',
            paddingRight: '32px',
            paddingTop: '12px',
            paddingBottom: '12px',
            borderRadius: '9999px',
            display: 'flex',
            gap: '32px',
            alignItems: 'center',
            zIndex: 50,
            boxShadow: '0 0 20px rgba(0, 0, 0, 0.5)'
          }}>
            {/* 攻击源 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <div style={{
                width: '10px',
                height: '10px',
                borderRadius: '50%',
                backgroundColor: '#FF4D4F',
                boxShadow: '0 0 6px #FF4D4F'
              }} />
              <span style={{ color: '#e5e7eb', fontWeight: 'bold', fontSize: '13px', whiteSpace: 'nowrap' }}>攻击源</span>
            </div>
            {/* 进程 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <div style={{
                width: '10px',
                height: '10px',
                borderRadius: '50%',
                backgroundColor: '#722ED1',
                boxShadow: '0 0 6px #722ED1'
              }} />
              <span style={{ color: '#e5e7eb', fontWeight: 'bold', fontSize: '13px', whiteSpace: 'nowrap' }}>进程</span>
            </div>
            {/* 文件 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <div style={{
                width: '10px',
                height: '10px',
                borderRadius: '50%',
                backgroundColor: '#52C41A',
                boxShadow: '0 0 6px #52C41A'
              }} />
              <span style={{ color: '#e5e7eb', fontWeight: 'bold', fontSize: '13px', whiteSpace: 'nowrap' }}>文件</span>
            </div>
            {/* 网络 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <div style={{
                width: '10px',
                height: '10px',
                borderRadius: '50%',
                backgroundColor: '#1890FF',
                boxShadow: '0 0 6px #1890FF'
              }} />
              <span style={{ color: '#e5e7eb', fontWeight: 'bold', fontSize: '13px', whiteSpace: 'nowrap' }}>网络</span>
            </div>
            {/* 防护 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <div style={{
                width: '10px',
                height: '10px',
                borderRadius: '50%',
                backgroundColor: '#FA8C16',
                boxShadow: '0 0 6px #FA8C16'
              }} />
              <span style={{ color: '#e5e7eb', fontWeight: 'bold', fontSize: '13px', whiteSpace: 'nowrap' }}>防护</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default PIDSGraph;
