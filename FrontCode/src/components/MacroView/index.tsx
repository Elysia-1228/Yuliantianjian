/**
 * MacroView - 威胁态势宏观视图
 * 包含威胁雷达图和星型攻击拓扑图
 */

import React, { useEffect, useRef } from 'react';
import G6, { Graph } from '@antv/g6';
import { AggregatedAlert, ThreatRadarData } from '../../utils/alertAggregator';

interface MacroViewProps {
  aggregatedAlerts: AggregatedAlert[];
  radarData: ThreatRadarData;
  topAttackers: AggregatedAlert[];
}

const MacroView: React.FC<MacroViewProps> = ({ aggregatedAlerts, radarData, topAttackers }) => {
  const radarRef = useRef<HTMLDivElement>(null);
  const topologyRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<Graph | null>(null);

  // 渲染威胁雷达图
  useEffect(() => {
    if (!radarRef.current) return;

    const canvas = radarRef.current;
    const ctx = document.createElement('canvas').getContext('2d');
    if (!ctx) return;

    // 使用Canvas绘制雷达图
    const drawRadar = () => {
      const container = radarRef.current;
      if (!container) return;

      // 清空容器
      container.innerHTML = '';

      const size = Math.min(container.clientWidth, container.clientHeight);
      const centerX = size / 2;
      const centerY = size / 2;
      const maxRadius = size * 0.4;

      const canvas = document.createElement('canvas');
      canvas.width = size;
      canvas.height = size;
      canvas.style.width = '100%';
      canvas.style.height = '100%';
      container.appendChild(canvas);

      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      // 雷达数据
      const metrics = [
        { label: '攻击频率', value: radarData.attackFrequency, angle: 0 },
        { label: '破坏力', value: radarData.destructiveness, angle: Math.PI * 2 / 5 },
        { label: '隐蔽性', value: radarData.stealth, angle: Math.PI * 4 / 5 },
        { label: '资产重要性', value: radarData.assetImportance, angle: Math.PI * 6 / 5 },
        { label: '置信度', value: radarData.confidence, angle: Math.PI * 8 / 5 },
      ];

      // 绘制背景网格
      ctx.strokeStyle = 'rgba(100, 200, 255, 0.15)';
      ctx.lineWidth = 1;
      for (let i = 1; i <= 5; i++) {
        ctx.beginPath();
        const radius = (maxRadius / 5) * i;
        metrics.forEach((metric, idx) => {
          const x = centerX + Math.cos(metric.angle - Math.PI / 2) * radius;
          const y = centerY + Math.sin(metric.angle - Math.PI / 2) * radius;
          if (idx === 0) {
            ctx.moveTo(x, y);
          } else {
            ctx.lineTo(x, y);
          }
        });
        ctx.closePath();
        ctx.stroke();
      }

      // 绘制轴线
      ctx.strokeStyle = 'rgba(100, 200, 255, 0.3)';
      metrics.forEach(metric => {
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        const x = centerX + Math.cos(metric.angle - Math.PI / 2) * maxRadius;
        const y = centerY + Math.sin(metric.angle - Math.PI / 2) * maxRadius;
        ctx.lineTo(x, y);
        ctx.stroke();
      });

      // 绘制数据区域
      ctx.fillStyle = 'rgba(231, 76, 60, 0.25)';
      ctx.strokeStyle = '#e74c3c';
      ctx.lineWidth = 3;
      ctx.beginPath();
      metrics.forEach((metric, idx) => {
        const radius = (metric.value / 100) * maxRadius;
        const x = centerX + Math.cos(metric.angle - Math.PI / 2) * radius;
        const y = centerY + Math.sin(metric.angle - Math.PI / 2) * radius;
        if (idx === 0) {
          ctx.moveTo(x, y);
        } else {
          ctx.lineTo(x, y);
        }
      });
      ctx.closePath();
      ctx.fill();
      ctx.stroke();

      // 绘制数据点
      ctx.fillStyle = '#e74c3c';
      metrics.forEach(metric => {
        const radius = (metric.value / 100) * maxRadius;
        const x = centerX + Math.cos(metric.angle - Math.PI / 2) * radius;
        const y = centerY + Math.sin(metric.angle - Math.PI / 2) * radius;
        ctx.beginPath();
        ctx.arc(x, y, 5, 0, Math.PI * 2);
        ctx.fill();
      });

      // 绘制标签
      ctx.fillStyle = '#e2e8f0';
      ctx.font = 'bold 14px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      metrics.forEach(metric => {
        const labelRadius = maxRadius + 30;
        const x = centerX + Math.cos(metric.angle - Math.PI / 2) * labelRadius;
        const y = centerY + Math.sin(metric.angle - Math.PI / 2) * labelRadius;
        ctx.fillText(metric.label, x, y);
        
        // 绘制数值
        ctx.font = 'bold 12px JetBrains Mono, monospace';
        ctx.fillStyle = '#06b6d4';
        ctx.fillText(Math.round(metric.value).toString(), x, y + 18);
      });
    };

    drawRadar();
    window.addEventListener('resize', drawRadar);
    return () => window.removeEventListener('resize', drawRadar);
  }, [radarData]);

  // 渲染星型攻击拓扑图
  useEffect(() => {
    if (!topologyRef.current || topAttackers.length === 0) return;

    const container = topologyRef.current;
    const width = container.clientWidth || 400;
    const height = container.clientHeight || 400;

    // 销毁旧图
    if (graphRef.current && !graphRef.current.destroyed) {
      graphRef.current.destroy();
    }
    container.innerHTML = '';

    // 构建星型拓扑数据
    const centerNode = {
      id: 'asset',
      label: 'Your Asset\n受保护资产',
      type: 'circle',
      size: 80,
      style: {
        fill: 'rgba(6, 182, 212, 0.2)',
        stroke: '#06b6d4',
        lineWidth: 4,
      },
    };

    const attackerNodes = topAttackers.slice(0, 5).map((attacker, idx) => ({
      id: `attacker_${idx}`,
      label: `${attacker.sourceIp}\n${attacker.count}次攻击`,
      type: 'circle',
      size: 50 + Math.min(attacker.count / 10, 30),
      style: {
        fill: attacker.severity === 'high' || attacker.severity === '高危' || attacker.severity === 'critical'
          ? 'rgba(231, 76, 60, 0.25)'
          : 'rgba(241, 196, 15, 0.25)',
        stroke: attacker.severity === 'high' || attacker.severity === '高危' || attacker.severity === 'critical'
          ? '#e74c3c'
          : '#f1c40f',
        lineWidth: 3,
      },
    }));

    const edges = attackerNodes.map((node, idx) => ({
      source: node.id,
      target: 'asset',
      type: 'line',
      style: {
        stroke: topAttackers[idx].severity === 'high' || topAttackers[idx].severity === '高危' || topAttackers[idx].severity === 'critical'
          ? '#e74c3c'
          : '#f1c40f',
        lineWidth: Math.min(topAttackers[idx].count / 20, 5),
        opacity: 0.6,
        endArrow: {
          path: G6.Arrow.triangle(10, 12, 0),
          fill: topAttackers[idx].severity === 'high' || topAttackers[idx].severity === '高危' || topAttackers[idx].severity === 'critical'
            ? '#e74c3c'
            : '#f1c40f',
        },
      },
      label: `${topAttackers[idx].primaryThreatType}`,
      labelCfg: {
        autoRotate: true,
        style: {
          fill: '#94a3b8',
          fontSize: 12,
          fontWeight: 'bold',
          background: {
            fill: 'rgba(5, 11, 20, 0.9)',
            padding: [3, 6, 3, 6],
            radius: 3,
          },
        },
      },
    }));

    const graph = new G6.Graph({
      container,
      width,
      height,
      fitView: true,
      fitViewPadding: 40,
      defaultNode: {
        labelCfg: {
          style: {
            fill: '#ffffff',
            fontSize: 14,
            fontWeight: 'bold',
            fontFamily: 'JetBrains Mono, monospace',
          },
        },
      },
      modes: {
        default: ['drag-canvas', 'zoom-canvas'],
      },
      layout: {
        type: 'radial',
        unitRadius: 150,
        linkDistance: 200,
        focusNode: 'asset',
      },
    });

    graph.data({
      id: 'macro-graph',
      nodes: [centerNode, ...attackerNodes],
      edges,
    } as any);

    graph.render();
    graphRef.current = graph;

    // 添加粒子动画效果
    edges.forEach((edge, idx) => {
      const edgeItem = graph.findById(edge.source + '-' + edge.target);
      if (edgeItem && (edgeItem as any).animate) {
        (edgeItem as any).animate(
          (ratio: number) => {
            const opacity = 0.3 + Math.sin(ratio * Math.PI * 2) * 0.3;
            return { opacity };
          },
          {
            duration: 2000 + idx * 200,
            repeat: true,
            easing: 'easeCubic',
          }
        );
      }
    });

    return () => {
      if (graph && !graph.destroyed) {
        graph.destroy();
      }
    };
  }, [topAttackers]);

  return (
    <div className="grid grid-cols-2 gap-6 h-full p-6">
      {/* 左侧：威胁雷达 */}
      <div className="bg-slate-950/50 rounded-lg border border-cyan-500/30 p-6">
        <h3 className="text-lg font-bold text-cyan-400 mb-4 font-mono">
          威胁画像 THREAT RADAR
        </h3>
        <div ref={radarRef} className="w-full h-[400px]" />
        
        {/* 统计信息 */}
        <div className="mt-6 grid grid-cols-3 gap-4">
          <div className="bg-slate-900/50 p-3 rounded text-center">
            <div className="text-3xl font-bold text-cyan-400 font-mono">{aggregatedAlerts.length}</div>
            <div className="text-xs text-slate-400 mt-1">攻击源数量</div>
          </div>
          <div className="bg-slate-900/50 p-3 rounded text-center">
            <div className="text-3xl font-bold text-red-400 font-mono">
              {aggregatedAlerts.reduce((sum, a) => sum + a.count, 0)}
            </div>
            <div className="text-xs text-slate-400 mt-1">总攻击次数</div>
          </div>
          <div className="bg-slate-900/50 p-3 rounded text-center">
            <div className="text-3xl font-bold text-yellow-400 font-mono">
              {aggregatedAlerts.filter(a => a.severity === 'high' || a.severity === '高危' || a.severity === 'critical').length}
            </div>
            <div className="text-xs text-slate-400 mt-1">高危源</div>
          </div>
        </div>
      </div>

      {/* 右侧：星型拓扑 */}
      <div className="bg-slate-950/50 rounded-lg border border-red-500/30 p-6">
        <h3 className="text-lg font-bold text-red-400 mb-4 font-mono">
          攻击拓扑 ATTACK TOPOLOGY
        </h3>
        <div ref={topologyRef} className="w-full h-[400px]" />
        
        {/* Top 5 攻击者列表 */}
        <div className="mt-6 space-y-2">
          <div className="text-xs text-slate-400 font-bold mb-2">TOP 5 攻击者</div>
          {topAttackers.slice(0, 5).map((attacker, idx) => (
            <div key={idx} className="flex items-center justify-between bg-slate-900/50 p-2 rounded">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${
                  attacker.severity === 'high' || attacker.severity === '高危' || attacker.severity === 'critical'
                    ? 'bg-red-500'
                    : 'bg-yellow-500'
                }`} />
                <span className="text-sm font-mono text-slate-300">{attacker.sourceIp}</span>
              </div>
              <span className="text-sm font-bold text-cyan-400 font-mono">{attacker.count}次</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default MacroView;
