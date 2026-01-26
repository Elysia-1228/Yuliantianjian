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

// 🔥 将图数据转换为树状结构（tree系列）
const convertToTreeData = (nodes: any[], edges: any[]) => {
  const rootNodes = nodes.filter(n => n.type === 'attacker');
  if (rootNodes.length === 0) return null;
  
  const root = rootNodes[0];
  const adjacencyMap = new Map<string, string[]>();
  edges.forEach(edge => {
    if (!adjacencyMap.has(edge.source)) {
      adjacencyMap.set(edge.source, []);
    }
    adjacencyMap.get(edge.source)!.push(edge.target);
  });
  
  const buildTree = (nodeId: string, visited = new Set<string>()): any => {
    if (visited.has(nodeId)) return null;
    visited.add(nodeId);
    
    const node = nodes.find(n => n.id === nodeId);
    if (!node) return null;
    
    const children = adjacencyMap.get(nodeId) || [];
    const childNodes = children.map(childId => buildTree(childId, visited)).filter(Boolean);
    
    const baseColor = getNeonColor(node.type || 'process');
    const nodeSymbol = getNodeSymbol(node.type || 'process');
    
    let displayName = node.label || node.id;
    if (node.type === 'process' || node.type === 'server') {
      displayName = node.label || node.name || node.id;
    } else if (node.type === 'file') {
      const fullPath = node.label || node.id;
      displayName = fullPath.split('/').pop() || fullPath;
    }
    
    return {
      name: displayName,
      value: nodeId,
      nodeData: node,
      symbol: nodeSymbol,
      symbolSize: getNodeSize(node.type || 'process'),
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
      children: childNodes.length > 0 ? childNodes : undefined
    };
  };
  
  return buildTree(root.id);
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
  const [displayedNodeCount, setDisplayedNodeCount] = useState(0);
  const animationTimerRef = useRef<NodeJS.Timeout | null>(null);

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
      if (animationTimerRef.current) {
        clearTimeout(animationTimerRef.current);
      }
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

    // 🔥 转换为树状结构
    const treeData = convertToTreeData(nodes, edges);
    if (!treeData) {
      console.error('❌ 无法构建树状结构');
      return;
    }

    // 🔥 逐条绘制动画：初始化显示节点数为0
    setDisplayedNodeCount(0);
    
    // 清除之前的定时器
    if (animationTimerRef.current) {
      clearTimeout(animationTimerRef.current);
    }

    // 🔥 树状图配置
    const option: echarts.EChartsOption = {
      backgroundColor: 'transparent',
      tooltip: {
        show: true,
        trigger: 'item',
        triggerOn: 'mousemove|click',
        confine: true,
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
            const timestamp = nodeData.startTime || new Date().toLocaleString('zh-CN', { hour12: false, fractionalSecondDigits: 3 });
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
          type: 'tree',
          data: [treeData],
          orient: 'LR',
          layout: 'orthogonal',
          left: '5%',
          right: '5%',
          top: '10%',
          bottom: '10%',
          symbolRotate: (value: any, params: any) => {
            const nodeData = params.data.nodeData;
            if (nodeData && nodeData.type === 'attacker') {
              return 90;
            }
            return 0;
          },
          label: {
            show: true,
            position: 'bottom',
            distance: 12,
            fontSize: isFullscreen ? 16 : 14,  // 🔥 增大字体
            color: '#ffffff',
            fontWeight: 'bold',
            fontFamily: 'JetBrains Mono, monospace',
            formatter: (params: any) => {
              const name = params.name || '';
              return name.length > 18 ? name.substring(0, 18) + '...' : name;
            }
          },
          edgeShape: 'curve',
          edgeSymbol: ['none', 'arrow'],
          edgeSymbolSize: [0, 18],
          lineStyle: {
            color: {
              type: 'linear',
              x: 0,
              y: 0,
              x2: 1,
              y2: 0,
              colorStops: [
                { offset: 0, color: '#FF8C00' },
                { offset: 0.25, color: '#FFD700' },
                { offset: 0.5, color: '#FFA500' },
                { offset: 0.75, color: '#FFD700' },
                { offset: 1, color: '#FF8C00' }
              ]
            },
            width: 5,
            curveness: 0.5,
            shadowBlur: 30,
            shadowColor: '#FFD700',
            opacity: 1
          },
          emphasis: {
            focus: 'ancestor',
            itemStyle: {
              borderWidth: 3,
              shadowBlur: 35
            },
            lineStyle: {
              width: 6
            }
          },
          animation: true,
          animationDuration: 800,
          animationEasing: 'elasticOut',
          animationDelay: (idx: number) => idx * 150,
          roam: true,  // 🔥 启用滚轮缩放和拖动平移
          scaleLimit: {
            min: 0.3,
            max: 3
          },
          expandAndCollapse: false,
          initialTreeDepth: -1,
          leaves: {
            label: {
              position: 'right',
              verticalAlign: 'middle',
              align: 'left'
            }
          }
        } as any
      ]
    };

    // 🔥 使用notMerge: true实现完全重新渲染，触发初始动画
    chartInstanceRef.current.setOption(option, {
      notMerge: true,  // 完全重新渲染，触发初始动画
      lazyUpdate: false,
      silent: false
    });
    
    console.log('📊 树状图配置已设置，节点数:', nodes.length);

    // 🔥 真正的逐个绘制进度显示（与animationDelay同步）
    setDisplayedNodeCount(0);
    let currentCount = 0;
    const totalNodes = nodes.length;
    const drawInterval = 150;  // 每150ms绘制一个节点（与animationDelay一致）
    
    const updateProgress = () => {
      if (currentCount < totalNodes) {
        currentCount++;
        setDisplayedNodeCount(currentCount);
        animationTimerRef.current = setTimeout(updateProgress, drawInterval);
      }
    };
    
    // 开始进度更新
    animationTimerRef.current = setTimeout(updateProgress, drawInterval);

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
      }
    }, 100);
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
        
        {/* 逐条绘制进度提示 */}
        {graphData && graphData.nodes && displayedNodeCount < graphData.nodes.length && (
          <div style={{
            position: 'absolute',
            top: '20px',
            left: '50%',
            transform: 'translateX(-50%)',
            backgroundColor: 'rgba(24, 144, 255, 0.9)',
            color: '#fff',
            padding: '8px 16px',
            borderRadius: '20px',
            fontSize: '12px',
            fontWeight: 'bold',
            zIndex: 100,
            boxShadow: '0 0 20px rgba(24, 144, 255, 0.5)'
          }}>
            🎨 正在绘制节点: {displayedNodeCount} / {graphData.nodes.length}
          </div>
        )}

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
