/**
 * PIDS 特征雷达图组件
 * 
 * 展示130维特征向量的分组分布情况
 * 御链天鉴开发团队
 */

import React, { useEffect, useRef, useState } from 'react';
import * as echarts from 'echarts';

interface FeatureGroup {
  graphStructure: number[];
  node: number[];
  edge: number[];
  sequence: number[];
  semantic: number[];
}

interface FeatureRadarChartProps {
  featureGroups?: FeatureGroup;
  threatId?: string;
  attackType?: string;
  loading?: boolean;
  onRefresh?: () => void;
}

const FeatureRadarChart: React.FC<FeatureRadarChartProps> = ({
  featureGroups,
  threatId,
  attackType,
  loading = false,
  onRefresh
}) => {
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<echarts.ECharts | null>(null);

  // 计算每组特征的平均值
  const calculateGroupAverages = (groups: FeatureGroup) => {
    const avg = (arr: number[]) => {
      if (!arr || arr.length === 0) return 0;
      const sum = arr.reduce((a, b) => a + b, 0);
      return Math.min(sum / arr.length, 1); // 归一化到0-1
    };

    return [
      { name: '图结构', value: avg(groups.graphStructure), max: 1 },
      { name: '节点', value: avg(groups.node), max: 1 },
      { name: '边', value: avg(groups.edge), max: 1 },
      { name: '序列', value: avg(groups.sequence), max: 1 },
      { name: '语义', value: avg(groups.semantic), max: 1 }
    ];
  };

  // 初始化图表
  useEffect(() => {
    if (!chartRef.current) return;

    chartInstance.current = echarts.init(chartRef.current);

    const resizeObserver = new ResizeObserver(() => {
      chartInstance.current?.resize();
    });
    resizeObserver.observe(chartRef.current);

    return () => {
      resizeObserver.disconnect();
      chartInstance.current?.dispose();
    };
  }, []);

  // 更新图表数据
  useEffect(() => {
    if (!chartInstance.current) return;

    if (loading) {
      chartInstance.current.showLoading({
        text: '加载中...',
        color: '#3b82f6',
        textColor: '#fff',
        maskColor: 'rgba(0, 0, 0, 0.3)'
      });
      return;
    }

    chartInstance.current.hideLoading();

    if (!featureGroups) {
      chartInstance.current.setOption({
        title: {
          text: '暂无特征数据',
          left: 'center',
          top: 'center',
          textStyle: { color: '#6b7280', fontSize: 14 }
        }
      });
      return;
    }

    const data = calculateGroupAverages(featureGroups);

    const option: echarts.EChartsOption = {
      backgroundColor: 'transparent',
      title: {
        text: '特征分布雷达图',
        subtext: attackType ? `攻击类型: ${attackType}` : '',
        left: 'center',
        top: 10,
        textStyle: {
          color: '#e2e8f0',
          fontSize: 16,
          fontWeight: 'bold'
        },
        subtextStyle: {
          color: '#94a3b8',
          fontSize: 12
        }
      },
      tooltip: {
        trigger: 'item',
        backgroundColor: 'rgba(15, 23, 42, 0.9)',
        borderColor: '#334155',
        textStyle: { color: '#e2e8f0' },
        formatter: (params: any) => {
          if (params.data && params.data.value) {
            const values = params.data.value;
            return `
              <div style="padding: 8px;">
                <div style="font-weight: bold; margin-bottom: 8px;">特征分布</div>
                <div>图结构: ${(values[0] * 100).toFixed(1)}%</div>
                <div>节点: ${(values[1] * 100).toFixed(1)}%</div>
                <div>边: ${(values[2] * 100).toFixed(1)}%</div>
                <div>序列: ${(values[3] * 100).toFixed(1)}%</div>
                <div>语义: ${(values[4] * 100).toFixed(1)}%</div>
              </div>
            `;
          }
          return '';
        }
      },
      radar: {
        center: ['50%', '55%'],
        radius: '55%',
        indicator: data.map(d => ({ name: d.name, max: d.max })),
        axisName: {
          color: '#94a3b8',
          fontSize: 12,
          padding: [0, 4],
        },
        nameGap: 12,
        splitArea: {
          areaStyle: {
            color: ['rgba(59, 130, 246, 0.1)', 'rgba(59, 130, 246, 0.05)']
          }
        },
        axisLine: {
          lineStyle: { color: 'rgba(148, 163, 184, 0.3)' }
        },
        splitLine: {
          lineStyle: { color: 'rgba(148, 163, 184, 0.2)' }
        }
      },
      series: [
        {
          type: 'radar',
          data: [
            {
              value: data.map(d => d.value),
              name: '特征值',
              symbol: 'circle',
              symbolSize: 6,
              lineStyle: {
                color: '#3b82f6',
                width: 2
              },
              areaStyle: {
                color: new echarts.graphic.RadialGradient(0.5, 0.5, 1, [
                  { offset: 0, color: 'rgba(59, 130, 246, 0.4)' },
                  { offset: 1, color: 'rgba(59, 130, 246, 0.1)' }
                ])
              },
              itemStyle: {
                color: '#3b82f6',
                borderColor: '#fff',
                borderWidth: 1
              }
            }
          ]
        }
      ]
    };

    chartInstance.current.setOption(option, true);
  }, [featureGroups, attackType, loading]);

  // 计算威胁评分
  const calculateThreatScore = () => {
    if (!featureGroups) return 0;
    const semanticAvg = featureGroups.semantic.reduce((a, b) => a + b, 0) / featureGroups.semantic.length;
    return Math.min(semanticAvg * 100, 100);
  };

  const threatScore = calculateThreatScore();
  const getThreatLevel = (score: number) => {
    if (score >= 70) return { text: '高危', color: 'text-red-500', bg: 'bg-red-500/20' };
    if (score >= 40) return { text: '中危', color: 'text-yellow-500', bg: 'bg-yellow-500/20' };
    return { text: '低危', color: 'text-green-500', bg: 'bg-green-500/20' };
  };
  const level = getThreatLevel(threatScore);

  return (
    <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-4">
      {/* 头部信息 */}
      <div className="flex justify-between items-center mb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center">
            <svg className="w-5 h-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <div>
            <h3 className="text-white font-semibold">PIDS 特征分析</h3>
            {threatId && (
              <p className="text-slate-400 text-sm">ID: {threatId.slice(0, 16)}...</p>
            )}
          </div>
        </div>
        {onRefresh && (
          <button
            onClick={onRefresh}
            className="p-2 hover:bg-slate-700/50 rounded-lg transition-colors"
            title="刷新"
          >
            <svg className="w-4 h-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
        )}
      </div>

      {/* 雷达图 */}
      <div ref={chartRef} style={{ height: '280px' }} />

      {/* 威胁评分 */}
      {featureGroups && (
        <div className="mt-4 pt-4 border-t border-slate-700/50">
          <div className="flex justify-between items-center">
            <span className="text-slate-400 text-sm">威胁评分</span>
            <div className="flex items-center gap-2">
              <span className={`text-2xl font-bold ${level.color}`}>
                {threatScore.toFixed(1)}
              </span>
              <span className={`px-2 py-0.5 rounded text-xs font-medium ${level.bg} ${level.color}`}>
                {level.text}
              </span>
            </div>
          </div>
          {/* 进度条 */}
          <div className="mt-2 h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                threatScore >= 70 ? 'bg-red-500' : threatScore >= 40 ? 'bg-yellow-500' : 'bg-green-500'
              }`}
              style={{ width: `${threatScore}%` }}
            />
          </div>
          {/* 特征维度统计 */}
          <div className="mt-3 grid grid-cols-5 gap-2 text-center">
            <div className="text-xs">
              <div className="text-slate-400">图结构</div>
              <div className="text-blue-400 font-medium">15维</div>
            </div>
            <div className="text-xs">
              <div className="text-slate-400">节点</div>
              <div className="text-purple-400 font-medium">40维</div>
            </div>
            <div className="text-xs">
              <div className="text-slate-400">边</div>
              <div className="text-green-400 font-medium">25维</div>
            </div>
            <div className="text-xs">
              <div className="text-slate-400">序列</div>
              <div className="text-yellow-400 font-medium">30维</div>
            </div>
            <div className="text-xs">
              <div className="text-slate-400">语义</div>
              <div className="text-red-400 font-medium">20维</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default FeatureRadarChart;
