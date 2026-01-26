/**
 * Galaxy Topology - 星系拓扑图
 * 中心：受害服务器（蓝光）
 * 卫星：Top 10 攻击源IP（环绕）
 * 连线：虚线，线宽代表攻击频率
 */

import React, { useEffect, useRef } from 'react';
import G6, { Graph } from '@antv/g6';
import { AggregatedAlert } from '../../utils/alertAggregator';

interface GalaxyTopologyProps {
  topAttackers: AggregatedAlert[];
  targetIp?: string;
}

const GalaxyTopology: React.FC<GalaxyTopologyProps> = ({ topAttackers, targetIp = 'Your Server' }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<Graph | null>(null);

  useEffect(() => {
    if (!containerRef.current || topAttackers.length === 0) return;

    const container = containerRef.current;
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 600;

    // 销毁旧图
    if (graphRef.current && !graphRef.current.destroyed) {
      graphRef.current.destroy();
    }
    container.innerHTML = '';

    // 中心节点：受害服务器
    const centerNode = {
      id: 'center_server',
      label: targetIp,
      type: 'circle',
      size: 100,
      style: {
        fill: 'rgba(6, 182, 212, 0.15)',
        stroke: '#06b6d4',
        lineWidth: 4,
        shadowColor: '#06b6d4',
        shadowBlur: 30,
      },
      labelCfg: {
        style: {
          fill: '#ffffff',
          fontSize: 16,
          fontWeight: 'bold',
          fontFamily: 'JetBrains Mono, monospace',
        },
      },
    };

    // 卫星节点：Top 10 攻击源
    const satelliteNodes = topAttackers.slice(0, 10).map((attacker, idx) => {
      const isCritical = attacker.severity === 'high' || attacker.severity === '高危' || attacker.severity === 'critical';
      const nodeSize = 50 + Math.min(attacker.count * 2, 40);
      
      return {
        id: `attacker_${idx}`,
        label: `${attacker.sourceIp}\n${attacker.count}次`,
        type: 'circle',
        size: nodeSize,
        style: {
          fill: isCritical ? 'rgba(231, 76, 60, 0.2)' : 'rgba(241, 196, 15, 0.2)',
          stroke: isCritical ? '#e74c3c' : '#f1c40f',
          lineWidth: 3,
          shadowColor: isCritical ? '#e74c3c' : '#f1c40f',
          shadowBlur: 15,
        },
        labelCfg: {
          style: {
            fill: '#ffffff',
            fontSize: 12,
            fontWeight: 'bold',
            fontFamily: 'JetBrains Mono, monospace',
          },
        },
      };
    });

    // 连线：虚线，线宽代表攻击频率
    const edges = satelliteNodes.map((node, idx) => {
      const attacker = topAttackers[idx];
      const isCritical = attacker.severity === 'high' || attacker.severity === '高危' || attacker.severity === 'critical';
      const lineWidth = Math.min(attacker.count / 5, 6);

      return {
        source: node.id,
        target: 'center_server',
        type: 'line',
        style: {
          stroke: isCritical ? '#e74c3c' : '#f1c40f',
          lineWidth: lineWidth,
          lineDash: [8, 4],
          opacity: 0.7,
          endArrow: {
            path: G6.Arrow.triangle(10, 12, 0),
            fill: isCritical ? '#e74c3c' : '#f1c40f',
          },
        },
        label: attacker.primaryThreatType,
        labelCfg: {
          autoRotate: true,
          style: {
            fill: '#94a3b8',
            fontSize: 11,
            fontWeight: 'bold',
            background: {
              fill: 'rgba(5, 11, 20, 0.9)',
              padding: [2, 5, 2, 5],
              radius: 3,
            },
          },
        },
      };
    });

    // 创建G6图
    const graph = new G6.Graph({
      container,
      width,
      height,
      fitView: true,
      fitViewPadding: 60,
      modes: {
        default: ['drag-canvas', 'zoom-canvas', 'drag-node'],
      },
      layout: {
        type: 'force',
        preventOverlap: true,
        nodeStrength: -300,
        edgeStrength: 0.2,
        linkDistance: 200,
        center: [width / 2, height / 2],
      },
      defaultNode: {
        labelCfg: {
          style: {
            fill: '#ffffff',
            fontSize: 14,
            fontWeight: 'bold',
          },
        },
      },
      defaultEdge: {
        labelCfg: {
          autoRotate: true,
        },
      },
    });

    graph.data({
      id: 'galaxy-graph',
      nodes: [centerNode, ...satelliteNodes],
      edges,
    } as any);

    graph.render();
    graphRef.current = graph;

    // 添加脉动动画效果
    const animateEdges = () => {
      edges.forEach((edge, idx) => {
        const edgeItem = graph.findById(`${edge.source}-${edge.target}`);
        if (edgeItem && (edgeItem as any).animate) {
          (edgeItem as any).animate(
            (ratio: number) => {
              const opacity = 0.4 + Math.sin(ratio * Math.PI * 2 + idx * 0.5) * 0.3;
              return { opacity };
            },
            {
              duration: 3000,
              repeat: true,
              easing: 'easeCubic',
            }
          );
        }
      });
    };

    // 延迟执行动画，等待布局稳定
    setTimeout(animateEdges, 500);

    return () => {
      if (graph && !graph.destroyed) {
        graph.destroy();
      }
    };
  }, [topAttackers, targetIp]);

  return (
    <div className="w-full h-full relative bg-slate-950/30">
      <div ref={containerRef} className="w-full h-full" />
      
      {/* 图例 */}
      <div className="absolute top-4 left-4 bg-slate-950/80 border border-cyan-500/30 rounded-lg p-3">
        <div className="text-xs font-bold text-cyan-400 mb-2 font-mono">GALAXY TOPOLOGY</div>
        <div className="space-y-1 text-xs text-slate-300">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-cyan-500/30 border-2 border-cyan-500"></div>
            <span>Protected Asset</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500/30 border-2 border-red-500"></div>
            <span>Critical Attacker</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-yellow-500/30 border-2 border-yellow-500"></div>
            <span>Warning Attacker</span>
          </div>
        </div>
      </div>

      {/* 统计信息 */}
      <div className="absolute bottom-4 left-4 bg-slate-950/80 border border-cyan-500/30 rounded-lg p-3">
        <div className="text-xs font-bold text-cyan-400 mb-2 font-mono">ATTACK STATISTICS</div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <div className="text-xl font-bold text-cyan-400 font-mono">{topAttackers.length}</div>
            <div className="text-xs text-slate-400">Total Sources</div>
          </div>
          <div>
            <div className="text-xl font-bold text-red-400 font-mono">
              {topAttackers.reduce((sum, a) => sum + a.count, 0)}
            </div>
            <div className="text-xs text-slate-400">Total Attacks</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default GalaxyTopology;
