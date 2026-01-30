import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { 
  ZoomIn, ZoomOut, Crosshair, Globe, AlertTriangle, Network, Map, Search, Terminal, Zap, Activity, 
  Shield, Target, Clock, Server, Database, CheckCircle, ArrowRight, Cpu, AlertCircle, Wifi, Radio, 
  Skull, Bug, Eye, ChevronRight, TrendingUp, BarChart3, MapPin
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import PIDSGraph from '../components/PIDSGraph';
import { CHINA_GEO_NODES } from '../utils/constants';
import * as echarts from 'echarts';
import { TracingService, ThreatService } from '../services/connector';
import { 
  aggregateAlertsByIP, 
  filterAggregatedAlerts, 
  getTopAttackers, 
  calculateThreatRadar,
  AggregatedAlert 
} from '../utils/alertAggregator';

type ViewMode = 'geo' | 'pids';
type AnalysisPhase = 'idle' | 'sending' | 'processing' | 'receiving' | 'generating' | 'complete';

// 节点详细信息类型
interface NodeDetails {
  id: string;
  label: string;
  type: string;
  attackType?: string;
  sourceIp?: string;
  targetIp?: string;
  affectedProcess?: string;
  affectedFile?: string;
  timestamp?: string;
  [key: string]: any;
}

// ============ 科技感攻击源卡片组件 ============
interface CyberAttackCardProps {
  aggregation: AggregatedAlert;
  isSelected: boolean;
  onClick: () => void;
  index: number;
}

const CyberAttackCard: React.FC<CyberAttackCardProps> = ({ aggregation, isSelected, onClick, index }) => {
  const [isHovered, setIsHovered] = useState(false);
  const severityColors = {
    high: { bg: 'from-red-600/30 to-orange-600/20', border: 'border-red-500', glow: 'shadow-red-500/30', text: 'text-red-400' },
    critical: { bg: 'from-red-600/30 to-orange-600/20', border: 'border-red-500', glow: 'shadow-red-500/30', text: 'text-red-400' },
    '高危': { bg: 'from-red-600/30 to-orange-600/20', border: 'border-red-500', glow: 'shadow-red-500/30', text: 'text-red-400' },
    medium: { bg: 'from-yellow-600/30 to-amber-600/20', border: 'border-yellow-500', glow: 'shadow-yellow-500/30', text: 'text-yellow-400' },
    '中危': { bg: 'from-yellow-600/30 to-amber-600/20', border: 'border-yellow-500', glow: 'shadow-yellow-500/30', text: 'text-yellow-400' },
    low: { bg: 'from-blue-600/30 to-cyan-600/20', border: 'border-blue-500', glow: 'shadow-blue-500/30', text: 'text-blue-400' },
    '低危': { bg: 'from-blue-600/30 to-cyan-600/20', border: 'border-blue-500', glow: 'shadow-blue-500/30', text: 'text-blue-400' },
  };
  const colors = severityColors[aggregation.severity as keyof typeof severityColors] || severityColors.medium;

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={`relative p-4 rounded-xl cursor-pointer transition-all duration-300 transform group overflow-hidden
        ${isSelected 
          ? `bg-gradient-to-r ${colors.bg} ${colors.border} border-l-4 shadow-lg ${colors.glow} scale-[1.02]` 
          : 'bg-slate-900/40 border-l-4 border-transparent hover:border-cyan-500/50 hover:bg-slate-800/60'
        }
        ${isHovered && !isSelected ? 'translate-x-1' : ''}
      `}
      style={{ animationDelay: `${index * 50}ms` }}
    >
      {/* 扫描线动画 */}
      {(isSelected || isHovered) && (
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent animate-pulse" />
          <div className="absolute bottom-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent" />
          {isSelected && (
            <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 via-transparent to-purple-500/5 animate-pulse" />
          )}
        </div>
      )}

      {/* 顶部: IP和威胁等级 */}
      <div className="flex items-start justify-between mb-3 relative z-10">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${isSelected ? 'bg-cyan-400 animate-ping' : 'bg-slate-600'}`} />
          <div className={`text-base font-mono font-bold tracking-wide ${isSelected ? 'text-cyan-300' : 'text-slate-200'}`}>
            {aggregation.sourceIp}
          </div>
        </div>
        <div className={`flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-bold uppercase tracking-wider
          ${colors.text} bg-black/30 border ${colors.border}/50`}>
          <Skull size={12} />
          {aggregation.severity}
        </div>
      </div>

      {/* 攻击次数 - 大数字显示 */}
      <div className="flex items-center gap-3 mb-3">
        <div className={`text-3xl font-black font-mono ${isSelected ? 'text-cyan-400' : 'text-slate-400'} transition-colors`}>
          {aggregation.count}
        </div>
        <div className="flex flex-col">
          <span className="text-xs text-slate-500 uppercase tracking-wider">次攻击</span>
          <div className="flex items-center gap-1 text-xs text-red-400">
            <TrendingUp size={10} />
            <span>活跃威胁</span>
          </div>
        </div>
        {/* 迷你柱状图动画 */}
        <div className="ml-auto flex items-end gap-0.5 h-6">
          {[0.3, 0.6, 0.4, 0.8, 0.5, 0.9, 0.7].map((h, i) => (
            <div
              key={i}
              className={`w-1 rounded-t transition-all duration-300 ${isSelected ? 'bg-cyan-400' : 'bg-slate-600'}`}
              style={{ 
                height: `${h * 100}%`,
                animationDelay: `${i * 100}ms`,
                opacity: isSelected ? 1 : 0.5
              }}
            />
          ))}
        </div>
      </div>

      {/* 主要威胁类型 */}
      <div className={`text-sm font-bold mb-2 flex items-center gap-2 ${isSelected ? 'text-white' : 'text-slate-300'}`}>
        <Bug size={14} className={isSelected ? 'text-red-400' : 'text-slate-500'} />
        {aggregation.primaryThreatType}
      </div>

      {/* 威胁类型标签 */}
      {aggregation.threatTypes.length > 1 && (
        <div className="flex flex-wrap gap-1.5 mb-3">
          {aggregation.threatTypes.slice(0, 3).map((type, i) => (
            <span 
              key={i} 
              className={`text-[10px] px-2 py-0.5 rounded-full font-mono
                ${isSelected 
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' 
                  : 'bg-slate-800/80 text-slate-500 border border-slate-700/50'
                }`}
            >
              {type}
            </span>
          ))}
          {aggregation.threatTypes.length > 3 && (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800/80 text-slate-500 border border-slate-700/50">
              +{aggregation.threatTypes.length - 3}
            </span>
          )}
        </div>
      )}

      {/* 底部统计图标 - 真实数据 */}
      <div className="mt-3 pt-3 border-t border-slate-700/50">
        <div className="grid grid-cols-4 gap-2">
          {/* 攻击次数 */}
          <div className="flex flex-col items-center gap-1">
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center transition-all
              ${isSelected ? 'bg-red-500/20 border border-red-500/50' : 'bg-slate-800/50 border border-slate-700/30'}`}>
              <Target size={14} className={isSelected ? 'text-red-400' : 'text-slate-600'} />
            </div>
            <div className="text-[10px] font-mono font-bold text-cyan-400">{aggregation.count}</div>
          </div>
          
          {/* 威胁类型数 */}
          <div className="flex flex-col items-center gap-1">
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center transition-all
              ${isSelected ? 'bg-yellow-500/20 border border-yellow-500/50' : 'bg-slate-800/50 border border-slate-700/30'}`}>
              <Shield size={14} className={isSelected ? 'text-yellow-400' : 'text-slate-600'} />
            </div>
            <div className="text-[10px] font-mono font-bold text-yellow-400">{aggregation.threatTypes.length}</div>
          </div>
          
          {/* 受影响资产 */}
          <div className="flex flex-col items-center gap-1">
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center transition-all
              ${isSelected ? 'bg-purple-500/20 border border-purple-500/50' : 'bg-slate-800/50 border border-slate-700/30'}`}>
              <Server size={14} className={isSelected ? 'text-purple-400' : 'text-slate-600'} />
            </div>
            <div className="text-[10px] font-mono font-bold text-purple-400">{aggregation.targetIps.length}</div>
          </div>
          
          {/* 攻击持续时间 */}
          <div className="flex flex-col items-center gap-1">
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center transition-all
              ${isSelected ? 'bg-orange-500/20 border border-orange-500/50' : 'bg-slate-800/50 border border-slate-700/30'}`}>
              <Clock size={14} className={isSelected ? 'text-orange-400' : 'text-slate-600'} />
            </div>
            <div className="text-[10px] font-mono font-bold text-orange-400">
              {(() => {
                const duration = (new Date(aggregation.latestTime).getTime() - new Date(aggregation.earliestTime).getTime()) / (1000 * 60 * 60 * 24);
                return duration < 1 ? Math.round(duration * 24) + 'h' : Math.round(duration) + 'd';
              })()}
            </div>
          </div>
        </div>
      </div>

      {/* 选中时的脉冲边框 */}
      {isSelected && (
        <div className="absolute inset-0 rounded-xl border-2 border-cyan-400/50 animate-pulse pointer-events-none" />
      )}
    </div>
  );
};

// ============ 科技感聚合详情面板组件 ============
interface CyberDetailPanelProps {
  aggregation: AggregatedAlert;
  totalAlerts: number;
  totalSources: number;
}

const CyberDetailPanel: React.FC<CyberDetailPanelProps> = ({ aggregation, totalAlerts, totalSources }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'threats' | 'targets'>('overview');
  const [anomalyScore, setAnomalyScore] = useState(0);
  const [rawVector, setRawVector] = useState<number[]>([]);
  const [featureGroups, setFeatureGroups] = useState<any>({});
  const [scanPhase, setScanPhase] = useState(-1);
  const [visibleCards, setVisibleCards] = useState<string[]>([]);
  const [hoveredFeature, setHoveredFeature] = useState<string | null>(null);
  const [selectedFeature, setSelectedFeature] = useState<string | null>(null);
  const [detailModal, setDetailModal] = useState<{ visible: boolean; feature: any; top3: any[] }>({ visible: false, feature: null, top3: [] });
  
  const threatDistribution = useMemo(() => {
    const dist: Record<string, number> = {};
    aggregation.alerts.forEach(a => {
      const type = a.threatType || a.attackType || 'Unknown';
      dist[type] = (dist[type] || 0) + 1;
    });
    return Object.entries(dist).sort((a, b) => b[1] - a[1]);
  }, [aggregation]);

  const maxCount = Math.max(...threatDistribution.map(([, c]) => c), 1);

  const FEATURE_GROUPS = [
    { 
      name: '图结构特征', 
      key: 'graph_structure', 
      baseline: 0.12, 
      range: [0, 14], 
      weight: 0.35,
      subFeatures: ['节点数量', '边密度', '平均度数', '最大路径长度', '聚类系数']
    },
    { 
      name: '节点特征', 
      key: 'node', 
      baseline: 0.12, 
      range: [15, 54], 
      weight: 0.35,
      subFeatures: ['进程节点占比', '关键进程频率', '文件节点占比', '网络节点占比', '攻击源节点']
    },
    { 
      name: '边特征', 
      key: 'edge', 
      baseline: 0.12, 
      range: [55, 79], 
      weight: 0.35,
      subFeatures: ['执行边数量', '读写边数量', '连接边数量', '攻击链深度', '分支因子']
    },
    { 
      name: '序列特征', 
      key: 'sequence', 
      baseline: 0.10, 
      range: [80, 109], 
      weight: 0.20,
      subFeatures: ['时间跨度', '操作熵', '突发强度', '周期模式', '加速度评分']
    },
    { 
      name: '语义特征', 
      key: 'semantic', 
      baseline: 0.10, 
      range: [110, 129], 
      weight: 0.45,
      subFeatures: ['SQL注入评分', 'Webshell评分', '权限提升评分', '数据渗透评分', '持久化评分']
    },
  ];

  useEffect(() => {
    // 调用真实的后端特征提取API
    const fetchFeatures = async () => {
      try {
        // 构建符合后端API要求的溯源图数据
        const nodes = [];
        const edges = [];
        const nodeSet = new Set();
        
        aggregation.alerts.forEach((alert, idx) => {
          const attackerId = `attacker_${alert.sourceIp || 'unknown'}`;
          const targetId = `target_${alert.destIp || alert.sourceIp || 'unknown'}`;
          
          if (!nodeSet.has(attackerId)) {
            nodes.push({ 
              id: attackerId, 
              label: alert.sourceIp || 'unknown', 
              type: 'attacker',
              category: 0,
              timestamp: alert.occurTime || new Date().toISOString()
            });
            nodeSet.add(attackerId);
          }
          if (!nodeSet.has(targetId)) {
            nodes.push({ 
              id: targetId, 
              label: alert.destIp || alert.sourceIp || 'unknown', 
              type: 'process',
              category: 1,
              timestamp: alert.occurTime || new Date().toISOString(),
              cmdline: alert.attackType || ''
            });
            nodeSet.add(targetId);
          }
          
          edges.push({
            source: attackerId,
            target: targetId,
            label: alert.attackType || '连接'
          });
        });
        
        const graphData = { nodes, edges };
        
        // 调用后端API
        const response = await fetch('http://localhost:7890/api/pids/features/extract', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            graphData,
            threatId: `threat_${aggregation.sourceIp}`,
            saveToDb: false
          })
        });
        
        if (!response.ok) {
          throw new Error('特征提取API调用失败');
        }
        
        const data = await response.json();
        
        // 设置130维原始向量
        setRawVector(data.rawVector || []);
        
        // 设置分组特征数据
        const groupsData: any = {};
        FEATURE_GROUPS.forEach(g => {
          const groupDetail = data.groups?.[g.key === 'graph_structure' ? 'graphStructure' : g.key];
          if (groupDetail) {
            const current = groupDetail.current;
            const baseline = groupDetail.baseline;
            const deviation = ((current / baseline - 1) * 100).toFixed(0);
            
            groupsData[g.key] = {
              current,
              baseline,
              label: current > baseline ? `+${deviation}%` : `${deviation}%`,
              top3: groupDetail.topFeatures?.slice(0, 3).map((name: string) => ({
                name,
                score: (Math.random() * 0.5).toFixed(3) // 临时使用随机值，后续从dimensions获取
              })) || []
            };
          }
        });
        setFeatureGroups(groupsData);
        
        // 计算加权评分
        let weightedScore = 0;
        FEATURE_GROUPS.forEach(g => {
          const groupData = groupsData[g.key];
          if (groupData) {
            weightedScore += (groupData.current / groupData.baseline) * g.weight * 100;
          }
        });
        setAnomalyScore(Math.min(weightedScore, 100));
        
      } catch (error) {
        console.error('特征提取失败:', error);
        // 如果API调用失败，使用空数据
        setRawVector(Array.from({ length: 130 }, () => 0));
        setAnomalyScore(0);
      }
    };
    
    fetchFeatures();
    
    setScanPhase(0);
    let groupIdx = 0;
    const scanInterval = setInterval(() => {
      groupIdx++;
      setScanPhase(groupIdx);
      if (groupIdx > 4) {
        clearInterval(scanInterval);
        setScanPhase(-1);
        
        FEATURE_GROUPS.forEach((g, idx) => {
          setTimeout(() => {
            setVisibleCards(prev => [...prev, g.key]);
          }, idx * 300);
        });
      }
    }, 150);
    
    return () => clearInterval(scanInterval);
  }, [aggregation.sourceIp]);

  return (
    <div className="h-full flex flex-col bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950 overflow-hidden">
      {/* 标签页 */}
      <div className="px-4 pt-4 flex gap-1">
        {[
          { id: 'overview', label: '总览', icon: Eye },
          { id: 'threats', label: '威胁', icon: Bug },
          { id: 'targets', label: '目标', icon: Target },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex-1 flex items-center justify-center gap-1.5 py-2 px-3 rounded-t-lg text-xs font-bold transition-all
              ${activeTab === tab.id 
                ? 'bg-slate-800 text-cyan-400 border-t border-x border-cyan-500/30' 
                : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/50'
              }`}
          >
            <tab.icon size={12} />
            {tab.label}
          </button>
        ))}
      </div>

      {/* 内容区域 - 优化滚动 */}
      <div className="flex-1 overflow-y-overlay p-4 bg-slate-800/30 mx-4 mb-4 rounded-b-lg border border-t-0 border-slate-700/50 scrollbar-thin">
        {activeTab === 'overview' && (
          <div className="space-y-3 animate-fadeIn">
            {/* 130维特征热力图 - 分组展示 */}
            <div className="relative bg-gradient-to-br from-slate-900/90 via-slate-800/80 to-slate-900/90 rounded-xl p-5 border-2 border-cyan-500/30 shadow-2xl overflow-hidden">
              {/* 背景装饰 */}
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,rgba(6,182,212,0.15),transparent_50%)]" />
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_80%,rgba(168,85,247,0.1),transparent_50%)]" />
              
              {/* 超大标题 */}
              <div className="relative z-10 mb-5">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 bg-cyan-500/20 rounded-lg border border-cyan-500/50">
                    <Activity size={20} className="text-cyan-400" />
                  </div>
                  <div>
                    <div className="text-2xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-400 to-purple-400 tracking-tight">
                      多维异常提取引擎
                    </div>
                    <div className="text-xs text-slate-400 font-mono mt-0.5">130维原始行为特征全景图</div>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-xs">
                  <div className="flex items-center gap-2 px-3 py-1.5 bg-cyan-500/10 rounded-lg border border-cyan-500/30">
                    <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse" />
                    <span className="text-cyan-300 font-mono font-bold">{rawVector.length} 维特征</span>
                  </div>
                  <div className="flex items-center gap-2 px-3 py-1.5 bg-purple-500/10 rounded-lg border border-purple-500/30">
                    <Zap size={12} className="text-purple-400" />
                    <span className="text-purple-300 font-mono">图论算法引擎</span>
                  </div>
                  <div className="flex items-center gap-2 px-3 py-1.5 bg-green-500/10 rounded-lg border border-green-500/30">
                    <CheckCircle size={12} className="text-green-400" />
                    <span className="text-green-300 font-mono">实时提取</span>
                  </div>
                </div>
              </div>
              
              {/* 130维特征矩阵 - 带色卡图例 */}
              <div className="relative z-10 space-y-3">
                {/* 色卡图例 */}
                <div className="flex items-center gap-3 mb-2 p-3 bg-slate-900/50 rounded-lg border border-slate-700/30">
                  <span className="text-xs text-slate-400 font-bold">特征强度图例：</span>
                  <div className="flex items-center gap-2">
                    <div className="flex items-center gap-1.5">
                      <div className="w-4 h-3 rounded bg-gradient-to-r from-cyan-400/30 to-cyan-600/30 border border-cyan-500/50" />
                      <span className="text-[10px] text-cyan-300">正常 (0-0.3)</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className="w-4 h-3 rounded bg-gradient-to-r from-yellow-400/50 to-orange-500/50 border border-orange-500/50" />
                      <span className="text-[10px] text-orange-300">警告 (0.3-0.7)</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className="w-4 h-3 rounded bg-gradient-to-r from-red-500/70 to-red-600/70 border border-red-500/70 shadow-lg shadow-red-500/50" />
                      <span className="text-[10px] text-red-300">高危 (0.7-1.0)</span>
                    </div>
                  </div>
                </div>
                {FEATURE_GROUPS.map((group, groupIdx) => {
                  const isHovered = hoveredFeature === group.key;
                  const groupVector = rawVector.slice(group.range[0], group.range[1] + 1);
                  const groupAvg = groupVector.reduce((a, b) => a + b, 0) / groupVector.length;
                  const isScanning = scanPhase >= 0 && scanPhase <= 4 && scanPhase === groupIdx;
                  const isScanned = scanPhase < 0 || scanPhase > groupIdx;
                  
                  return (
                    <div 
                      key={group.key}
                      className={`transition-all duration-300 ${
                        isHovered ? 'scale-[1.02] shadow-lg shadow-cyan-500/20' : 'scale-100'
                      }`}
                    >
                      <div className="flex items-center gap-3 mb-1.5">
                        <div className={`text-xs font-bold w-24 transition-all ${
                          isHovered ? 'text-cyan-300 scale-105' : 'text-slate-400'
                        }`}>
                          {group.name}
                        </div>
                        <div className="flex-1 flex gap-1">
                          {groupVector.map((val, idx) => {
                            const intensity = isScanned ? Math.min(val, 1) : 0;
                            const hue = intensity > 0.7 ? 0 : intensity > 0.5 ? 30 : 180;
                            const opacity = isHovered ? 1 : 0.7;
                            
                            return (
                              <div
                                key={idx}
                                className={`h-4 flex-1 rounded transition-all duration-200 ${
                                  isScanning ? 'animate-pulse ring-1 ring-cyan-400' : ''
                                } ${
                                  isHovered ? 'scale-y-110' : ''
                                } ${
                                  intensity > 0.8 ? 'animate-[breathe_2s_ease-in-out_infinite]' : ''
                                }`}
                                style={{
                                  backgroundColor: isScanned
                                    ? `hsla(${hue}, 85%, 60%, ${Math.max(intensity * 0.95, 0.25) * opacity})`
                                    : 'rgba(30,41,59,0.4)',
                                  boxShadow: isScanning
                                    ? '0 0 8px rgba(6,182,212,1), 0 0 16px rgba(6,182,212,0.5)'
                                    : intensity > 0.8
                                    ? '0 0 10px rgba(239,68,68,1), 0 0 20px rgba(239,68,68,0.8), 0 0 30px rgba(239,68,68,0.4)'
                                    : intensity > 0.7
                                    ? '0 0 6px rgba(239,68,68,0.8), 0 0 12px rgba(239,68,68,0.4)'
                                    : intensity > 0.5
                                    ? '0 0 4px rgba(251,146,60,0.6)'
                                    : 'none'
                                }}
                                title={`${group.name}[${idx}]: ${val.toFixed(3)}`}
                              />
                            );
                          })}
                        </div>
                        <div className={`text-sm font-black font-mono w-16 text-right transition-all ${
                          groupAvg > 0.6 ? 'text-red-400 drop-shadow-[0_0_8px_rgba(239,68,68,0.8)]' : 
                          groupAvg > 0.4 ? 'text-orange-400 drop-shadow-[0_0_6px_rgba(251,146,60,0.6)]' : 
                          'text-cyan-400 drop-shadow-[0_0_6px_rgba(6,182,212,0.6)]'
                        } ${
                          isHovered ? 'scale-110' : ''
                        }`}>
                          {(groupAvg * 100).toFixed(0)}%
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
              
              {/* AI溯源判定报告面板 */}
              <div className="relative z-10 mt-4 pt-4 border-t border-cyan-500/20">
                <div className="bg-gradient-to-br from-slate-900/90 to-slate-800/80 rounded-xl p-4 border border-cyan-500/30 shadow-xl shadow-cyan-500/10">
                  <div className="flex items-center gap-2 mb-3">
                    <Terminal size={16} className="text-cyan-400" />
                    <span className="text-sm font-bold text-cyan-300">AI 溯源判定报告</span>
                    <div className="flex-1 h-px bg-gradient-to-r from-cyan-500/50 to-transparent" />
                  </div>
                  <div className="text-xs leading-relaxed text-slate-300 font-mono space-y-1">
                    <p className="animate-[typing_2s_steps(60)_1s_both]">
                      <span className="text-cyan-400">▶</span> AI 引擎已完成 <span className="text-cyan-400 font-bold">{rawVector.length} 维</span>特征提取
                    </p>
                    <p className="animate-[typing_2s_steps(60)_2s_both] opacity-0">
                      <span className="text-yellow-400">▶</span> 判定结论：该 IP <span className="text-cyan-400 font-bold">{aggregation.sourceIp}</span> 发起 <span className="text-red-400 font-bold">{aggregation.count} 次</span>攻击
                    </p>
                    <p className="animate-[typing_2s_steps(60)_3s_both] opacity-0">
                      <span className="text-purple-400">▶</span> 攻击路径：<span className="text-cyan-400 font-bold">{aggregation.sourceIp}</span> <span className="text-slate-400">→</span> <span className="text-slate-300">{aggregation.targetIps.join(' → ')}</span>
                    </p>
                    <p className="animate-[typing_2s_steps(60)_4s_both] opacity-0">
                      <span className="text-orange-400">▶</span> 主要手段：<span className="text-red-400 font-bold">{aggregation.threatTypes.slice(0, 2).join('、')}</span>
                    </p>
                    <p className="animate-[typing_2s_steps(60)_5s_both] opacity-0">
                      <span className="text-red-400">▶</span> 异常评分：<span className={`font-black ${
                        anomalyScore > 0.8 ? 'text-red-400' : 
                        anomalyScore > 0.5 ? 'text-orange-400' : 'text-yellow-400'
                      }`}>{anomalyScore.toFixed(3)}</span> | 威胁等级：<span className={`font-black ${
                        anomalyScore > 0.8 ? 'text-red-400' : 
                        anomalyScore > 0.5 ? 'text-orange-400' : 'text-yellow-400'
                      }`}>{anomalyScore > 0.8 ? '极高' : anomalyScore > 0.5 ? '高' : '中'}</span>
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* 5个特征维度卡片 */}
            {FEATURE_GROUPS.map(group => {
              const data = featureGroups[group.key] || { current: 0, baseline: group.baseline, label: '0%', top3: [] };
              const ratio = data.current / data.baseline;
              const isHigh = ratio > 2.5;
              const isCritical = ratio > 5; // 过载：超过500%
              const isVisible = visibleCards.includes(group.key);
              const barWidth = Math.min((data.current / 1) * 100, 100);
              const baselinePos = (data.baseline / 1) * 100;
              
              return (
                <div 
                  key={group.key}
                  onMouseEnter={() => setHoveredFeature(group.key)}
                  onMouseLeave={() => setHoveredFeature(null)}
                  onClick={() => {
                    setSelectedFeature(group.key);
                    setDetailModal({ visible: true, feature: group, top3: data.top3 || [] });
                  }}
                  className={`relative bg-gradient-to-br from-slate-900/80 to-slate-800/60 rounded-xl p-4 border-2 transition-all duration-500 cursor-pointer overflow-hidden ${
                    isVisible ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-8'
                  } ${
                    isCritical ? 'border-red-500/70 bg-gradient-to-br from-red-950/40 to-red-900/30 shadow-2xl shadow-red-500/30' : 
                    isHigh ? 'border-red-500/50 bg-gradient-to-br from-red-950/30 to-red-900/20 shadow-xl shadow-red-500/20' : 
                    'border-slate-700/50 hover:border-cyan-500/60 hover:shadow-xl hover:shadow-cyan-500/20'
                  }`}
                >
                  {/* 背景光效 */}
                  <div className={`absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100 ${
                    isCritical ? 'bg-[radial-gradient(circle_at_50%_50%,rgba(239,68,68,0.2),transparent_70%)]' :
                    isHigh ? 'bg-[radial-gradient(circle_at_50%_50%,rgba(251,146,60,0.15),transparent_70%)]' :
                    'bg-[radial-gradient(circle_at_50%_50%,rgba(6,182,212,0.1),transparent_70%)]'
                  }`} />
                  {/* 实时子项滚动展示 */}
                  <div className="relative z-10 mb-2 overflow-hidden">
                    <div className="text-[10px] text-cyan-300 font-mono animate-[scroll_10s_linear_infinite] whitespace-nowrap">
                      {group.key === 'semantic' && '[检测到敏感指令: cat /etc/shadow] [发现编码绕过: Base64]'}
                      {group.key === 'sequence' && '[异常时序模式] [快速连续执行] [夜间活动峰值]'}
                      {group.key === 'edge' && '[异常连接数激增] [跨区域通信] [非标准端口]'}
                      {group.key === 'structure' && '[图谱拓扑异常] [孤立节点] [环形结构]'}
                      {group.key === 'node' && '[进程节点异常] [文件访问异常] [网络套接字异常]'}
                    </div>
                  </div>
                  <div className="relative z-10 flex items-center justify-between text-sm mb-3">
                    <div className="flex items-center gap-2">
                      <div className={`w-1.5 h-1.5 rounded-full ${
                        isCritical ? 'bg-red-500 animate-pulse shadow-lg shadow-red-500' :
                        isHigh ? 'bg-orange-500 shadow-lg shadow-orange-500' :
                        'bg-cyan-500 shadow-lg shadow-cyan-500'
                      }`} />
                      <span className={`font-bold ${
                        isCritical || isHigh ? 'text-red-300' : 'text-slate-200'
                      }`}>
                        {group.key === 'structure' ? '图谱拓扑特征' : 
                         group.key === 'node' ? '节点实体分布' :
                         group.key === 'edge' ? '行为路径关联' :
                         group.key === 'sequence' ? '时序行为指纹' :
                         group.key === 'semantic' ? '攻击语义向量' : group.name}
                      </span>
                      {isCritical && (
                        <span className="px-2 py-0.5 text-[10px] font-black bg-red-500/50 text-red-100 border border-red-400 rounded-md shadow-lg shadow-red-500/50">
                          极危
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`text-lg font-black font-mono ${
                        isCritical ? 'text-red-400 drop-shadow-[0_0_10px_rgba(239,68,68,1)]' :
                        isHigh ? 'text-orange-400 drop-shadow-[0_0_8px_rgba(251,146,60,0.8)]' :
                        'text-cyan-400 drop-shadow-[0_0_8px_rgba(6,182,212,0.8)]'
                      }`}>{data.label}</span>
                      <Eye size={14} className="text-slate-400 hover:text-cyan-300 transition-colors" />
                    </div>
                  </div>
                  {/* 激光流光进度条 */}
                  <div className="relative z-10 h-3 bg-slate-900/80 rounded-full overflow-hidden shadow-inner">
                    {/* 基线标记 */}
                    <div 
                      className="absolute top-0 h-full w-1 bg-yellow-400 z-10 rounded-full" 
                      style={{ left: `${baselinePos}%`, boxShadow: '0 0 8px rgba(250,204,21,1), 0 0 16px rgba(250,204,21,0.5)' }} 
                    />
                    {/* 进度条主体 */}
                    <div 
                      className={`absolute h-full rounded-full transition-all duration-700 relative overflow-hidden ${
                        isCritical
                          ? 'bg-gradient-to-r from-red-600 via-red-500 to-orange-500 animate-pulse'
                          : isHigh 
                          ? 'bg-gradient-to-r from-red-500 via-orange-500 to-orange-400' 
                          : 'bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500'
                      }`}
                      style={{ 
                        width: isVisible ? `${barWidth}%` : '0%', 
                        boxShadow: isCritical
                          ? '0 0 20px rgba(239,68,68,1), 0 0 40px rgba(239,68,68,0.6), inset 0 0 10px rgba(255,255,255,0.3)'
                          : isHigh 
                          ? '0 0 12px rgba(251,146,60,0.8), 0 0 24px rgba(251,146,60,0.4), inset 0 0 8px rgba(255,255,255,0.2)' 
                          : '0 0 10px rgba(6,182,212,0.6), 0 0 20px rgba(6,182,212,0.3), inset 0 0 6px rgba(255,255,255,0.2)' 
                      }}
                    >
                      {/* 激光流光扫过效果 */}
                      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/40 to-transparent animate-[laser_2s_ease-in-out_infinite]" style={{ width: '30%' }} />
                    </div>
                  </div>
                  {/* 基线对比数值化 */}
                  <div className="relative z-10 mt-3 text-[10px] font-mono flex items-center justify-between px-3 py-2 bg-slate-950/60 rounded-lg border border-slate-700/40">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-500">当前测算值:</span>
                      <span className="text-cyan-300 font-bold">{data.current.toFixed(3)}</span>
                    </div>
                    <div className="h-3 w-px bg-slate-700" />
                    <div className="flex items-center gap-2">
                      <span className="text-slate-500">历史基线:</span>
                      <span className="text-yellow-300 font-bold">{data.baseline.toFixed(3)}</span>
                    </div>
                  </div>
                </div>
              );
            })}

            {/* 子特征详情弹窗 - 居中全屏显示 */}
            {detailModal.visible && (
              <div 
                className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-lg"
                onClick={() => setDetailModal({ visible: false, feature: null, top3: [] })}
              >
                <div 
                  className="relative bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 border-2 border-cyan-500/50 rounded-2xl p-8 w-[85%] max-w-[1200px] h-[85vh] shadow-2xl shadow-cyan-500/20 animate-fadeIn flex flex-col"
                  onClick={(e) => e.stopPropagation()}
                >
                  {/* 背景光效 */}
                  <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_0%,rgba(6,182,212,0.15),transparent_50%)]" />
                  <div className="absolute inset-0 bg-[radial-gradient(circle_at_0%_100%,rgba(168,85,247,0.1),transparent_50%)]" />
                  
                  {/* 标题 */}
                  <div className="relative z-10 mb-6 flex items-center justify-between border-b border-cyan-500/30 pb-4">
                    <div className="flex items-center gap-4">
                      <div className="p-3 bg-gradient-to-br from-cyan-500/20 to-purple-500/20 rounded-xl border border-cyan-500/50">
                        <Activity size={24} className="text-cyan-400" />
                      </div>
                      <div>
                        <div className="text-2xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-400">
                          {detailModal.feature?.key === 'structure' ? '图谱拓扑特征' : 
                           detailModal.feature?.key === 'node' ? '节点实体分布' :
                           detailModal.feature?.key === 'edge' ? '行为路径关联' :
                           detailModal.feature?.key === 'sequence' ? '时序行为指纹' :
                           detailModal.feature?.key === 'semantic' ? '攻击语义向量' : detailModal.feature?.name}
                        </div>
                        <div className="text-sm text-slate-400 font-mono mt-1">子特征详细分析 · 共 {detailModal.top3.length} 项特征</div>
                      </div>
                    </div>
                    <button 
                      onClick={() => setDetailModal({ visible: false, feature: null, top3: [] })}
                      className="w-10 h-10 flex items-center justify-center rounded-xl bg-slate-800/50 border border-slate-700 text-slate-400 hover:text-red-400 hover:border-red-500/50 hover:bg-red-500/10 transition-all text-2xl"
                    >×</button>
                  </div>
                  
                  {/* 所有子特征列表 - 优化表格UI */}
                  <div className="relative z-10 flex-1 overflow-hidden">
                    <div className="h-full overflow-y-auto scrollbar-thin pr-2">
                      <table className="w-full">
                        <thead className="sticky top-0 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 backdrop-blur-sm z-10 shadow-lg">
                          <tr className="border-b-2 border-cyan-500/50">
                            <th className="text-left py-4 px-4 text-xs font-bold text-cyan-300 uppercase tracking-wider">序号</th>
                            <th className="text-left py-4 px-4 text-xs font-bold text-cyan-300 uppercase tracking-wider">特征名称</th>
                            <th className="text-center py-4 px-4 text-xs font-bold text-cyan-300 uppercase tracking-wider">特征值</th>
                            <th className="text-center py-4 px-4 text-xs font-bold text-cyan-300 uppercase tracking-wider">强度分析</th>
                            <th className="text-center py-4 px-4 text-xs font-bold text-cyan-300 uppercase tracking-wider">状态</th>
                          </tr>
                        </thead>
                        <tbody>
                          {detailModal.top3.map((item, idx) => {
                            // 特征名称中文映射
                            const featureNameMap: Record<string, string> = {
                              'node_count': '节点总数', 'edge_count': '边总数', 'node_edge_ratio': '节点边比率',
                              'avg_degree': '平均度数', 'density': '图密度', 'diameter': '图直径',
                              'avg_clustering': '平均聚类系数', 'connected_components': '连通分量',
                              'process_node_count': '进程节点数', 'attacker_node_count': '攻击源节点',
                              'file_node_count': '文件节点数', 'socket_node_count': '网络套接字',
                              'server_node_count': '服务器节点', 'other_node_count': '其他节点',
                              'exec_edge_count': '执行边数', 'read_edge_count': '读取边数',
                              'write_edge_count': '写入边数', 'connect_edge_count': '连接边数',
                              'fork_edge_count': '分支边数', 'other_edge_count': '其他边数',
                              'time_span_seconds': '时间跨度(秒)', 'burst_count': '突发次数',
                              'night_activity': '夜间活动', 'operation_entropy': '操作熄',
                              'rce_score': '远程执行评分', 'webshell_score': 'WebShell评分',
                              'privilege_escalation_score': '提权评分', 'sql_injection_score': 'SQL注入评分',
                              'sensitive_file_access_count': '敏感文件访问', 'critical_process_count': '关键进程数'
                            };
                            const chineseName = featureNameMap[item.name] || item.name;
                            const scoreVal = parseFloat(item.score);
                            const intensity = Math.min(scoreVal * 100, 100);
                            
                            return (
                              <tr key={idx} className="border-b border-slate-700/20 hover:bg-gradient-to-r hover:from-cyan-500/10 hover:to-purple-500/10 transition-all duration-300 group">
                                <td className="py-4 px-4">
                                  <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-purple-500 flex items-center justify-center text-white text-sm font-black shadow-lg group-hover:scale-110 transition-transform">
                                    {idx + 1}
                                  </div>
                                </td>
                                <td className="py-4 px-4">
                                  <div className="text-sm font-bold text-slate-200 group-hover:text-cyan-300 transition-colors">{chineseName}</div>
                                  <div className="text-xs text-slate-500 font-mono mt-0.5">{item.name}</div>
                                </td>
                                <td className="py-4 px-4 text-center">
                                  <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-slate-900/50 rounded-lg border border-slate-700/50">
                                    <span className="text-sm font-mono text-cyan-400 font-bold">{item.score}</span>
                                  </div>
                                </td>
                                <td className="py-4 px-4">
                                  <div className="flex items-center justify-center gap-3">
                                    <div className="flex-1 max-w-[200px] h-2.5 bg-slate-900/80 rounded-full overflow-hidden border border-slate-700/50">
                                      <div 
                                        className={`h-full rounded-full transition-all duration-500 ${
                                          scoreVal > 0.7 ? 'bg-gradient-to-r from-red-500 via-orange-500 to-red-600' :
                                          scoreVal > 0.4 ? 'bg-gradient-to-r from-orange-500 via-yellow-500 to-orange-600' :
                                          'bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500'
                                        }`}
                                        style={{ 
                                          width: `${intensity}%`,
                                          boxShadow: scoreVal > 0.7 ? '0 0 10px rgba(239,68,68,0.6)' : 
                                                     scoreVal > 0.4 ? '0 0 10px rgba(251,146,60,0.6)' : 
                                                     '0 0 10px rgba(6,182,212,0.6)'
                                        }}
                                      />
                                    </div>
                                    <span className={`text-xs font-bold min-w-[40px] text-right ${
                                      scoreVal > 0.7 ? 'text-red-400' :
                                      scoreVal > 0.4 ? 'text-orange-400' : 'text-cyan-400'
                                    }`}>{intensity.toFixed(1)}%</span>
                                  </div>
                                </td>
                                <td className="py-4 px-4 text-center">
                                  <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold ${
                                    scoreVal > 0.7 ? 'bg-red-500/20 text-red-300 border border-red-500/50' :
                                    scoreVal > 0.4 ? 'bg-orange-500/20 text-orange-300 border border-orange-500/50' :
                                    'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50'
                                  }`}>
                                    <div className={`w-2 h-2 rounded-full ${
                                      scoreVal > 0.7 ? 'bg-red-400 animate-pulse' :
                                      scoreVal > 0.4 ? 'bg-orange-400' : 'bg-cyan-400'
                                    }`} />
                                    {scoreVal > 0.7 ? '高危' : scoreVal > 0.4 ? '警告' : '正常'}
                                  </span>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'threats' && (
          <div className="space-y-4 animate-fadeIn">
            {threatDistribution.map(([type, count], idx) => (
              <div key={type} className="bg-black/30 rounded-lg p-3 border border-slate-700/50">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-slate-300 truncate flex-1">{type}</span>
                  <span className="text-sm font-bold text-cyan-400 font-mono ml-2">{count}次</span>
                </div>
                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-cyan-500 to-purple-500 rounded-full transition-all duration-500"
                    style={{ width: `${(count / maxCount) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'targets' && (
          <div className="space-y-2 animate-fadeIn">
            {aggregation.targetIps.map((ip, idx) => (
              <div 
                key={ip} 
                className="bg-black/30 rounded-lg p-3 border border-slate-700/50 flex items-center gap-3 group hover:border-purple-500/30 transition-colors"
              >
                <div className="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center border border-purple-500/30">
                  <Server size={14} className="text-purple-400" />
                </div>
                <div className="flex-1">
                  <div className="text-sm font-mono text-slate-300 group-hover:text-white transition-colors">{ip}</div>
                  <div className="text-xs text-slate-500">受攻击资产</div>
                </div>
                <Shield size={14} className="text-slate-600 group-hover:text-purple-400 transition-colors" />
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 底部统计 */}
      <div className="p-4 border-t border-cyan-500/20 bg-black/30">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-2 text-cyan-400">
            <BarChart3 size={14} />
            <span className="font-mono">智能聚合分析</span>
          </div>
          <div className="text-slate-500">
            {totalAlerts}条告警 → {totalSources}个攻击源
          </div>
        </div>
      </div>
    </div>
  );
};

// ============ 全新科技感因果溯源拓扑图组件 ============
interface TopologyGraphProps {
  graphData: any;
  visibleNodes: number;
  phase: AnalysisPhase;
}

// ============ 1. 扩充节点样式配置 (新增 process, file, socket) ============
const NODE_STYLES: Record<string, { 
  bg: string; 
  border: string; 
  glow: string; 
  icon: string;
  label: string;
}> = {
  attacker: { 
    bg: 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)', 
    border: '#ef4444', 
    glow: '#ef4444',
    icon: '⚡',
    label: '攻击源'
  },
  // 新增：进程节点 (核心!)
  process: { 
    bg: 'linear-gradient(135deg, #7c3aed 0%, #4c1d95 100%)', 
    border: '#a78bfa', 
    glow: '#8b5cf6',
    icon: '⚙️', 
    label: '进程'
  },
  // 新增：文件节点 (核心!)
  file: { 
    bg: 'linear-gradient(135deg, #059669 0%, #064e3b 100%)', 
    border: '#34d399', 
    glow: '#10b981',
    icon: '�', 
    label: '文件'
  },
  // 新增：套接字节点
  socket: { 
    bg: 'linear-gradient(135deg, #0284c7 0%, #0c4a6e 100%)', 
    border: '#38bdf8', 
    glow: '#0ea5e9',
    icon: '🌐', 
    label: '网络'
  },
  firewall: { 
    bg: 'linear-gradient(135deg, #d97706 0%, #92400e 100%)', 
    border: '#f59e0b', 
    glow: '#f59e0b',
    icon: '🛡️',
    label: '防护'
  },
  default: { 
    bg: 'linear-gradient(135deg, #475569 0%, #1e293b 100%)', 
    border: '#94a3b8', 
    glow: '#64748b',
    icon: '📦',
    label: '节点'
  },
};

// ============ 2. 升级分类逻辑 (支持后端返回的 type 字段) ============
const getNodeCategory = (node: any, index: number): string => {
  // 如果后端直接返回了 type 字段 (我们在 python 里加了)，直接用
  if (node.type && NODE_STYLES[node.type]) {
    return node.type;
  }

  // 兜底逻辑 (兼容旧数据)
  if (index === 0) return 'attacker';
  const label = (node.label || node.id || '').toLowerCase();
  
  if (label.includes('user') || label.includes('log') || label.includes('.ibd') || label.includes('/etc/')) return 'file';
  if (label.includes('nginx') || label.includes('bash') || label.includes('pid')) return 'process';
  if (label.includes('firewall')) return 'firewall';
  
  return 'default';
};

const TopologyGraph: React.FC<TopologyGraphProps> = ({ graphData, phase }) => {
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstanceRef = useRef<echarts.ECharts | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [displayedCount, setDisplayedCount] = useState(0);
  
  const nodes = graphData?.nodes || [];
  const edges = graphData?.edges || [];
  
  // 初始化节点位置
  useEffect(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    const W = 800, H = 450, PAD = 100;
    if (nodes.length === 0) return;
    
    // 构建邻接表和BFS分层
    const adj: Record<string, string[]> = {};
    nodes.forEach((n: any) => adj[n.id] = []);
    edges.forEach((e: any) => adj[e.source]?.push(e.target));
    
    const layers: string[][] = [[]];
    const visited = new Set<string>();
    const queue = [nodes[0].id];
    visited.add(nodes[0].id);
    layers[0].push(nodes[0].id);
    
    while (queue.length > 0) {
      const curr = queue.shift()!;
      const currLayer = layers.findIndex(l => l.includes(curr));
      (adj[curr] || []).forEach(next => {
        if (!visited.has(next)) {
          visited.add(next);
          if (!layers[currLayer + 1]) layers[currLayer + 1] = [];
          layers[currLayer + 1].push(next);
          queue.push(next);
        }
      });
    }
    
    // 未访问节点放最后一层
    nodes.forEach((n: any) => {
      if (!visited.has(n.id)) {
        if (!layers[layers.length]) layers.push([]);
        layers[layers.length - 1].push(n.id);
      }
    });
    
    // 计算位置
    const validLayers = layers.filter(l => l && l.length > 0);
    const hSpace = (W - 2 * PAD) / Math.max(validLayers.length - 1, 1);
    
    validLayers.forEach((layer, li) => {
      const vSpace = (H - 2 * PAD) / Math.max(layer.length + 1, 1);
      layer.forEach((nodeId, ni) => {
        positions[nodeId] = {
          x: validLayers.length === 1 ? W / 2 : PAD + li * hSpace,
          y: layer.length === 1 ? H / 2 : PAD + (ni + 1) * vSpace
        };
      });
    });
    
    setNodePositions(positions);
  }, [nodes, edges]);
  
  // 节点显示动画
  useEffect(() => {
    if (phase === 'generating') {
      setDisplayedCount(0);
      let count = 0;
      animationRef.current = setInterval(() => {
        count++;
        setDisplayedCount(count);
        if (count >= nodes.length) {
          clearInterval(animationRef.current!);
        }
      }, 600);
    } else if (phase === 'complete') {
      setDisplayedCount(nodes.length);
    }
    return () => { if (animationRef.current) clearInterval(animationRef.current); };
  }, [phase, nodes.length]);
  
  // 连线绘制动画
  useEffect(() => {
    if (phase === 'generating' || phase === 'complete') {
      const newProgress: Record<string, number> = {};
      edges.forEach((edge: any, idx: number) => {
        const edgeKey = `${edge.source}-${edge.target}`;
        newProgress[edgeKey] = 0;
      });
      setEdgeAnimProgress(newProgress);
      
      // 逐条绘制连线
      edges.forEach((edge: any, idx: number) => {
        const edgeKey = `${edge.source}-${edge.target}`;
        setTimeout(() => {
          let progress = 0;
          const animInterval = setInterval(() => {
            progress += 0.05;
            setEdgeAnimProgress(prev => ({ ...prev, [edgeKey]: Math.min(progress, 1) }));
            if (progress >= 1) clearInterval(animInterval);
          }, 20);
        }, idx * 300);
      });
    }
  }, [phase, edges]);
  
  // 拖拽处理函数
  const handleMouseDown = (e: React.MouseEvent<SVGGElement>, nodeId: string) => {
    e.stopPropagation();
    const svg = svgRef.current;
    if (!svg) return;
    
    const pt = svg.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    const svgP = pt.matrixTransform(svg.getScreenCTM()?.inverse());
    
    const pos = nodePositions[nodeId];
    setDraggingNode(nodeId);
    setDragOffset({ x: svgP.x - pos.x, y: svgP.y - pos.y });
  };
  
  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const svg = svgRef.current;
    if (!svg) return;
    
    if (draggingNode) {
      const pt = svg.createSVGPoint();
      pt.x = e.clientX;
      pt.y = e.clientY;
      const svgP = pt.matrixTransform(svg.getScreenCTM()?.inverse());
      
      setNodePositions(prev => ({
        ...prev,
        [draggingNode]: {
          x: Math.max(50, Math.min(750, svgP.x - dragOffset.x)),
          y: Math.max(50, Math.min(400, svgP.y - dragOffset.y))
        }
      }));
    }
  };
  
  const handleMouseUp = () => {
    setDraggingNode(null);
  };
  
  // 节点悬停处理
  const handleNodeHover = (e: React.MouseEvent<SVGGElement>, node: any) => {
    const svg = svgRef.current;
    if (!svg) return;
    
    const pt = svg.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    const svgP = pt.matrixTransform(svg.getScreenCTM()?.inverse());
    
    setHoveredNode(node);
    setTooltipPos({ x: svgP.x, y: svgP.y });
  };
  
  const handleNodeLeave = () => {
    setHoveredNode(null);
  };
  
  // 空数据处理
  if (!graphData?.nodes || nodes.length === 0) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center py-8">
          <AlertCircle className="w-16 h-16 text-yellow-400 mx-auto mb-4 animate-pulse" />
          <div className="text-yellow-400 font-bold text-lg mb-2">暂无图谱数据</div>
          <div className="text-slate-400 text-sm">AI引擎未返回溯源图谱节点数据</div>
        </div>
      </div>
    );
  }
  
  const visibleNodes = nodes.slice(0, displayedCount);
  const visibleEdges = edges.filter((e: any) => 
    visibleNodes.some((n: any) => n.id === e.source) && 
    visibleNodes.some((n: any) => n.id === e.target)
  );

  return (
    <div className="relative w-full h-full min-h-[400px] bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 rounded-xl overflow-hidden">
      {/* 科技感背景网格 */}
      <div className="absolute inset-0 opacity-20">
        <svg className="w-full h-full">
          <defs>
            <pattern id="grid-pattern" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(6, 182, 212, 0.5)" strokeWidth="0.5"/>
              <circle cx="0" cy="0" r="1.5" fill="rgba(6, 182, 212, 0.8)"/>
            </pattern>
            <radialGradient id="glow-center" cx="50%" cy="50%" r="60%">
              <stop offset="0%" stopColor="rgba(139, 92, 246, 0.15)"/>
              <stop offset="100%" stopColor="transparent"/>
            </radialGradient>
          </defs>
          <rect width="100%" height="100%" fill="url(#grid-pattern)"/>
          <rect width="100%" height="100%" fill="url(#glow-center)"/>
        </svg>
      </div>

      {/* 主SVG画布 */}
      <svg 
        ref={svgRef}
        className="w-full h-full relative z-10" 
        viewBox="0 0 800 450"
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <defs>
          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" result="blur"/>
            <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          <linearGradient id="edge-grad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#ef4444"/>
            <stop offset="50%" stopColor="#f59e0b"/>
            <stop offset="100%" stopColor="#8b5cf6"/>
          </linearGradient>
          <marker id="arrow" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#f59e0b"/>
          </marker>
        </defs>

        {/* 渲染连线（带绘制动画） */}
        {visibleEdges.map((edge: any, idx: number) => {
          const from = nodePositions[edge.source];
          const to = nodePositions[edge.target];
          if (!from || !to) return null;
          
          const edgeKey = `${edge.source}-${edge.target}`;
          const progress = edgeAnimProgress[edgeKey] || 0;
          
          // 计算贝塞尔曲线路径
          const midX = (from.x + to.x) / 2;
          const midY = (from.y + to.y) / 2 - 25;
          const fullPath = `M ${from.x} ${from.y} Q ${midX} ${midY} ${to.x} ${to.y}`;
          
          // 计算路径总长度用于动画
          const dx = to.x - from.x;
          const dy = to.y - from.y;
          const distance = Math.sqrt(dx * dx + dy * dy);
          
          // 根据进度计算当前绘制的路径
          const currentX = from.x + (to.x - from.x) * progress;
          const currentY = from.y + (to.y - from.y) * progress;
          const currentMidX = (from.x + currentX) / 2;
          const currentMidY = (from.y + currentY) / 2 - 25 * progress;
          const currentPath = `M ${from.x} ${from.y} Q ${currentMidX} ${currentMidY} ${currentX} ${currentY}`;
          
          return (
            <g key={`edge-${idx}`}>
              {/* 发光底层 */}
              {progress > 0 && (
                <path 
                  d={currentPath} 
                  fill="none" 
                  stroke="url(#edge-grad)" 
                  strokeWidth="3" 
                  opacity="0.4" 
                  filter="url(#glow)"
                />
              )}
              {/* 主连线 */}
              {progress > 0 && (
                <path 
                  d={currentPath} 
                  fill="none" 
                  stroke="url(#edge-grad)" 
                  strokeWidth="2" 
                  strokeDasharray="8,4" 
                  markerEnd={progress >= 1 ? "url(#arrow)" : ""}
                >
                  <animate attributeName="stroke-dashoffset" values="24;0" dur="1s" repeatCount="indefinite"/>
                </path>
              )}
              {/* 绘制动画的光点 */}
              {progress > 0 && progress < 1 && (
                <circle 
                  cx={currentX} 
                  cy={currentY} 
                  r="5" 
                  fill="#f59e0b" 
                  filter="url(#glow)"
                >
                  <animate attributeName="r" values="5;8;5" dur="0.5s" repeatCount="indefinite"/>
                </circle>
              )}
              {/* 完成后的流动粒子 */}
              {progress >= 1 && phase === 'complete' && (
                <circle r="4" fill="#ef4444" filter="url(#glow)">
                  <animateMotion dur="2s" repeatCount="indefinite" path={fullPath}/>
                </circle>
              )}
            </g>
          );
        })}

        {/* 渲染节点（可拖拽） */}
        {visibleNodes.map((node: any, idx: number) => {
          const pos = nodePositions[node.id];
          if (!pos) return null;
          const category = getNodeCategory(node, idx);
          const style = NODE_STYLES[category] || NODE_STYLES.default;
          const size = idx === 0 ? 45 : 38;
          const isDragging = draggingNode === node.id;
          const isHovered = hoveredNode?.id === node.id;
          
          return (
            <g 
              key={node.id} 
              transform={`translate(${pos.x}, ${pos.y})`} 
              className="cursor-move"
              onMouseDown={(e) => handleMouseDown(e, node.id)}
              onMouseEnter={(e) => handleNodeHover(e, node)}
              onMouseLeave={handleNodeLeave}
              style={{ cursor: isDragging ? 'grabbing' : 'grab' }}
            >
              {/* 脉冲动画 */}
              {idx === 0 && (
                <>
                  <circle r={size} fill="none" stroke={style.border} strokeWidth="2" opacity="0.5">
                    <animate attributeName="r" values={`${size};${size + 20};${size}`} dur="2s" repeatCount="indefinite"/>
                    <animate attributeName="opacity" values="0.5;0;0.5" dur="2s" repeatCount="indefinite"/>
                  </circle>
                  <circle r={size + 8} fill="none" stroke={style.border} strokeWidth="1" opacity="0.3">
                    <animate attributeName="r" values={`${size + 5};${size + 30}`} dur="1.5s" repeatCount="indefinite"/>
                    <animate attributeName="opacity" values="0.3;0" dur="1.5s" repeatCount="indefinite"/>
                  </circle>
                </>
              )}
              {/* 悬停高亮 */}
              {isHovered && (
                <circle r={size + 12} fill="none" stroke={style.border} strokeWidth="3" opacity="0.6">
                  <animate attributeName="opacity" values="0.6;0.3;0.6" dur="1s" repeatCount="indefinite"/>
                </circle>
              )}
              {/* 发光层 */}
              <circle r={size + 8} fill={style.border} opacity={isHovered ? "0.4" : "0.2"} filter="url(#glow)"/>
              {/* 主节点 */}
              <circle 
                r={size} 
                fill={style.border} 
                stroke="white" 
                strokeWidth={isHovered ? "3" : "2"} 
                opacity={isDragging ? "0.7" : "0.9"} 
                className="transition-all"
              />
              {/* 图标 */}
              <text y="5" textAnchor="middle" fontSize="20" fill="white" pointerEvents="none">{style.icon}</text>
              {/* 标签 */}
              <text 
                y={size + 20} 
                textAnchor="middle" 
                fill="#e2e8f0" 
                fontSize="12" 
                fontFamily="monospace" 
                fontWeight={idx === 0 ? 'bold' : 'normal'}
                pointerEvents="none"
              >
                {node.label || node.id}
              </text>
            </g>
          );
        })}
        
        {/* 悬停提示框 - 优化版本：不透明背景+更大字体+更多信息 */}
        {hoveredNode && (
          <g transform={`translate(${Math.min(tooltipPos.x + 70, 450)}, ${Math.max(tooltipPos.y - 120, 20)})`}>
            {/* 完全不透明的背景 */}
            <rect 
              x="0" 
              y="0" 
              width="360" 
              height="auto" 
              rx="12" 
              fill="rgb(15, 23, 42)" 
              stroke="#06b6d4" 
              strokeWidth="3"
              filter="url(#glow)"
            />
            <foreignObject x="0" y="0" width="360" height="320">
              <div className="p-5 text-white" style={{ fontFamily: 'monospace', fontSize: '14px' }}>
                <div className="font-bold text-cyan-400 mb-4 text-xl border-b border-cyan-500/30 pb-3 flex items-center gap-3">
                  <span className="text-3xl">{NODE_STYLES[getNodeCategory(hoveredNode, visibleNodes.indexOf(hoveredNode))]?.icon || '📦'}</span>
                  <div className="flex-1">
                    <div>{hoveredNode.label || hoveredNode.id}</div>
                    <div className="text-xs text-slate-400 font-normal mt-1">节点详细信息</div>
                  </div>
                </div>
                <div className="space-y-3 text-base">
                  <div className="flex justify-between items-center bg-slate-800/80 p-2 rounded">
                    <span className="text-slate-300 font-medium">节点ID:</span>
                    <span className="text-white font-mono text-sm bg-slate-900 px-3 py-1 rounded">{hoveredNode.id}</span>
                  </div>
                  <div className="flex justify-between items-center bg-slate-800/80 p-2 rounded">
                    <span className="text-slate-300 font-medium">类型:</span>
                    <span className="text-purple-400 font-bold text-base">{hoveredNode.type || NODE_STYLES[getNodeCategory(hoveredNode, visibleNodes.indexOf(hoveredNode))]?.label || '未知'}</span>
                  </div>
                  {hoveredNode.ip && (
                    <div className="flex justify-between items-center bg-slate-800/80 p-2 rounded">
                      <span className="text-slate-300 font-medium">IP地址:</span>
                      <span className="text-green-400 font-mono font-bold text-base">{hoveredNode.ip}</span>
                    </div>
                  )}
                  {hoveredNode.sourceIp && (
                    <div className="flex justify-between items-center bg-slate-800/80 p-2 rounded">
                      <span className="text-slate-300 font-medium">源IP:</span>
                      <span className="text-orange-400 font-mono font-bold text-base">{hoveredNode.sourceIp}</span>
                    </div>
                  )}
                  {hoveredNode.targetIp && (
                    <div className="flex justify-between items-center bg-slate-800/80 p-2 rounded">
                      <span className="text-slate-300 font-medium">目标IP:</span>
                      <span className="text-blue-400 font-mono font-bold text-base">{hoveredNode.targetIp}</span>
                    </div>
                  )}
                  {hoveredNode.attackType && (
                    <div className="flex justify-between items-center bg-red-900/30 p-2 rounded border border-red-500/30">
                      <span className="text-slate-300 font-medium">攻击类型:</span>
                      <span className="text-red-400 font-bold text-base">{hoveredNode.attackType}</span>
                    </div>
                  )}
                  {hoveredNode.affectedProcess && (
                    <div className="flex justify-between items-center bg-slate-800/80 p-2 rounded">
                      <span className="text-slate-300 font-medium">受影响进程:</span>
                      <span className="text-purple-400 font-mono font-bold text-base">{hoveredNode.affectedProcess}</span>
                    </div>
                  )}
                  {hoveredNode.affectedFile && (
                    <div className="flex justify-between items-center bg-slate-800/80 p-2 rounded">
                      <span className="text-slate-300 font-medium">受影响文件:</span>
                      <span className="text-cyan-400 font-mono text-sm">{hoveredNode.affectedFile}</span>
                    </div>
                  )}
                  {hoveredNode.port && (
                    <div className="flex justify-between items-center bg-slate-800/80 p-2 rounded">
                      <span className="text-slate-300 font-medium">端口:</span>
                      <span className="text-yellow-400 font-mono font-bold text-base">{hoveredNode.port}</span>
                    </div>
                  )}
                  {hoveredNode.service && (
                    <div className="flex justify-between items-center bg-slate-800/80 p-2 rounded">
                      <span className="text-slate-300 font-medium">服务:</span>
                      <span className="text-blue-400 font-bold text-base">{hoveredNode.service}</span>
                    </div>
                  )}
                  {hoveredNode.timestamp && (
                    <div className="flex justify-between items-center bg-slate-800/80 p-2 rounded">
                      <span className="text-slate-300 font-medium">时间戳:</span>
                      <span className="text-slate-400 font-mono text-sm">{hoveredNode.timestamp}</span>
                    </div>
                  )}
                  <div className="mt-3 pt-3 border-t border-slate-700">
                    <div className="text-slate-300 mb-2 font-medium text-base">节点描述:</div>
                    <div className="text-slate-200 text-sm leading-relaxed bg-slate-900 p-3 rounded border border-slate-700">
                      {hoveredNode.description || hoveredNode.details || (() => {
                        const category = getNodeCategory(hoveredNode, visibleNodes.indexOf(hoveredNode));
                        const descriptions: Record<string, string> = {
                          'attacker': `攻击源节点 - IP: ${hoveredNode.id}，发起了针对系统的恶意攻击行为，需要立即阻断和溯源分析。`,
                          'firewall': `防火墙节点 - ${hoveredNode.label || hoveredNode.id}，作为网络边界防护设备，检测并记录了异常流量特征。`,
                          'server': `服务器节点 - ${hoveredNode.label || hoveredNode.id}，系统主机，可能是攻击目标或中继跳板，需要检查系统日志和进程。`,
                          'service': `服务节点 - ${hoveredNode.label || hoveredNode.id}，运行的网络服务${hoveredNode.port ? `（端口${hoveredNode.port}）` : ''}，可能存在漏洞被利用。`,
                          'default': `网络节点 - ${hoveredNode.label || hoveredNode.id}，参与了攻击链路的传播，需要进一步分析其角色和行为。`
                        };
                        return descriptions[category] || descriptions['default'];
                      })()}
                    </div>
                  </div>
                  {hoveredNode.risk && (
                    <div className="mt-3 flex items-center justify-between bg-slate-800/50 p-2 rounded">
                      <span className="text-slate-400 font-medium">风险等级:</span>
                      <span className={`px-3 py-1 rounded-full text-sm font-bold ${
                        hoveredNode.risk === 'high' ? 'bg-red-500/30 text-red-400 border border-red-500/50' :
                        hoveredNode.risk === 'medium' ? 'bg-yellow-500/30 text-yellow-400 border border-yellow-500/50' :
                        'bg-green-500/30 text-green-400 border border-green-500/50'
                      }`}>
                        {hoveredNode.risk.toUpperCase()}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </foreignObject>
          </g>
        )}
      </svg>

      {/* 图例 */}
      <div className="absolute bottom-4 left-4 flex gap-4 text-xs bg-black/50 px-4 py-2 rounded-lg border border-cyan-500/30 backdrop-blur">
        {Object.entries(NODE_STYLES).map(([key, style]) => (
          <div key={key} className="flex items-center gap-2">
            <div className="w-4 h-4 rounded-full flex items-center justify-center text-[10px]" style={{ backgroundColor: style.border, boxShadow: `0 0 10px ${style.glow}` }}>
              {style.icon}
            </div>
            <span className="text-slate-300">{style.label}</span>
          </div>
        ))}
      </div>

      {/* 状态指示器 */}
      <div className="absolute top-4 right-4 flex items-center gap-2 px-4 py-2 bg-black/60 rounded-full border border-cyan-500/30 backdrop-blur">
        <div className={`w-2.5 h-2.5 rounded-full ${phase === 'complete' ? 'bg-green-500' : 'bg-cyan-500 animate-pulse'}`}/>
        <span className="text-sm text-slate-200 font-mono">
          {phase === 'complete' ? `✓ 溯源完成 ${nodes.length}节点` : `扫描中 ${displayedCount}/${nodes.length}`}
        </span>
      </div>

      {/* 进度条 */}
      {phase === 'generating' && (
        <div className="absolute bottom-0 left-0 right-0 h-1.5 bg-slate-800">
          <div className="h-full bg-gradient-to-r from-cyan-500 via-purple-500 to-red-500 transition-all duration-500" style={{ width: `${(displayedCount / nodes.length) * 100}%` }}/>
        </div>
      )}
    </div>
  );
};

// ============ 增强版数据传输分析组件 ============
interface EnhancedAnalysisProps {
  aggregation: AggregatedAlert | null;
  phase: AnalysisPhase;
  logs: Array<{ time: string; type: string; message: string }>;
  graphData: any;
  onComplete: () => void;
}

const EnhancedAnalysisView: React.FC<EnhancedAnalysisProps> = ({ 
  aggregation, phase, logs, graphData, onComplete
}) => {
  const [visibleNodes, setVisibleNodes] = useState<number>(0);
  const scrollRef = useRef<HTMLDivElement>(null);

  // 自动滚动日志
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  // 图谱生成动画 - 慢速逐个显示节点
  useEffect(() => {
    if (phase === 'generating' && graphData?.nodes) {
      const totalNodes = graphData.nodes.length;
      let current = 0;
      
      // 重置可见节点数
      setVisibleNodes(0);
      
      const timer = setInterval(() => {
        current += 1;
        setVisibleNodes(current);
        if (current >= totalNodes) {
          clearInterval(timer);
          // 所有节点显示完成后，等待1秒再调用完成回调
          setTimeout(() => {
            if (onComplete) onComplete();
          }, 1000);
        }
      }, 800); // 每个节点间隔800ms，让动画更明显
      
      return () => clearInterval(timer);
    }
  }, [phase, graphData?.nodes?.length]); // 移除onComplete依赖，只依赖nodes数量

  const phaseConfig = {
    idle: { label: '准备就绪', progress: 0, color: 'slate' },
    sending: { label: '发送请求数据', progress: 20, color: 'cyan' },
    processing: { label: 'AI引擎深度分析', progress: 50, color: 'purple' },
    receiving: { label: '接收分析结果', progress: 75, color: 'green' },
    generating: { label: '生成溯源图谱', progress: 90, color: 'emerald' },
    complete: { label: '分析完成', progress: 100, color: 'green' }
  };

  const currentPhase = phaseConfig[phase];

  return (
    <div className="h-full bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6 overflow-auto">
      <div className="max-w-5xl mx-auto">
        {/* 标题 */}
        <div className="text-center mb-8">
          <div className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-500 font-mono mb-2">
            PIDS 因果溯源分析系统
          </div>
          <div className="text-sm text-slate-400">基于溯源图的入侵检测与攻击路径还原</div>
        </div>

        {/* 分析流程可视化 */}
        <div className="bg-slate-900/50 border border-cyan-500/20 rounded-xl p-6 mb-6">
          <div className="flex items-center justify-between mb-6">
            {/* 步骤1: 客户端 */}
            <div className="text-center flex-1">
              <div className={`w-16 h-16 mx-auto rounded-xl flex items-center justify-center mb-2 transition-all ${
                phase === 'sending' ? 'bg-cyan-500/30 border-2 border-cyan-400 animate-pulse' : 'bg-slate-800/50 border border-slate-700'
              }`}>
                <Terminal className={`w-8 h-8 ${phase === 'sending' ? 'text-cyan-400' : 'text-slate-500'}`} />
              </div>
              <div className="text-xs text-slate-400">客户端</div>
              <div className="text-xs text-cyan-400 font-mono mt-1">发送请求</div>
            </div>

            <ArrowRight className={`w-6 h-6 ${['sending', 'processing', 'receiving', 'generating', 'complete'].includes(phase) ? 'text-cyan-400' : 'text-slate-700'}`} />

            {/* 步骤2: AI服务器 */}
            <div className="text-center flex-1">
              <div className={`w-16 h-16 mx-auto rounded-xl flex items-center justify-center mb-2 transition-all ${
                phase === 'processing' ? 'bg-purple-500/30 border-2 border-purple-400 animate-pulse' : 'bg-slate-800/50 border border-slate-700'
              }`}>
                <Cpu className={`w-8 h-8 ${phase === 'processing' ? 'text-purple-400' : 'text-slate-500'}`} />
              </div>
              <div className="text-xs text-slate-400">AI引擎</div>
              <div className="text-xs text-purple-400 font-mono mt-1">深度分析</div>
            </div>

            <ArrowRight className={`w-6 h-6 ${['receiving', 'generating', 'complete'].includes(phase) ? 'text-green-400' : 'text-slate-700'}`} />

            {/* 步骤3: 返回数据 */}
            <div className="text-center flex-1">
              <div className={`w-16 h-16 mx-auto rounded-xl flex items-center justify-center mb-2 transition-all ${
                phase === 'receiving' ? 'bg-green-500/30 border-2 border-green-400 animate-pulse' : 'bg-slate-800/50 border border-slate-700'
              }`}>
                <Database className={`w-8 h-8 ${phase === 'receiving' ? 'text-green-400' : 'text-slate-500'}`} />
              </div>
              <div className="text-xs text-slate-400">数据返回</div>
              <div className="text-xs text-green-400 font-mono mt-1">接收结果</div>
            </div>

            <ArrowRight className={`w-6 h-6 ${['generating', 'complete'].includes(phase) ? 'text-emerald-400' : 'text-slate-700'}`} />

            {/* 步骤4: 生成图谱 */}
            <div className="text-center flex-1">
              <div className={`w-16 h-16 mx-auto rounded-xl flex items-center justify-center mb-2 transition-all ${
                phase === 'generating' || phase === 'complete' ? 'bg-emerald-500/30 border-2 border-emerald-400' : 'bg-slate-800/50 border border-slate-700'
              } ${phase === 'generating' ? 'animate-pulse' : ''}`}>
                <Network className={`w-8 h-8 ${phase === 'generating' || phase === 'complete' ? 'text-emerald-400' : 'text-slate-500'}`} />
              </div>
              <div className="text-xs text-slate-400">图谱生成</div>
              <div className="text-xs text-emerald-400 font-mono mt-1">可视化</div>
            </div>
          </div>

          {/* 进度条 */}
          <div className="mb-4">
            <div className="flex justify-between text-xs mb-2">
              <span className={`text-${currentPhase.color}-400 font-medium`}>{currentPhase.label}</span>
              <span className="text-slate-500 font-mono">{currentPhase.progress}%</span>
            </div>
            <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
              <div 
                className={`h-full bg-gradient-to-r from-cyan-500 via-purple-500 to-emerald-500 rounded-full transition-all duration-1000`}
                style={{ width: `${currentPhase.progress}%` }}
              />
            </div>
          </div>
        </div>

        {/* 两列布局：请求参数 + 实时日志 */}
        <div className="grid grid-cols-2 gap-6 mb-6">
          {/* 请求参数 */}
          <div className="bg-slate-900/50 border border-cyan-500/20 rounded-xl p-4">
            <div className="text-sm font-bold text-cyan-400 mb-3 flex items-center gap-2">
              <Terminal size={16} />
              请求参数 (JSON)
            </div>
            <div className="bg-black/50 rounded-lg p-4 font-mono text-sm border border-slate-700/50">
              <div className="text-slate-500 mb-2">// 发送至 AI 分析引擎</div>
              <div className="text-cyan-400">{'{'}</div>
              <div className="pl-4">
                <span className="text-purple-400">"源IP地址"</span>: <span className="text-green-400">"{aggregation?.sourceIp || '-'}"</span>,
              </div>
              <div className="pl-4">
                <span className="text-purple-400">"目标IP"</span>: <span className="text-green-400">"{aggregation?.targetIps?.[0] || '-'}"</span>,
              </div>
              <div className="pl-4">
                <span className="text-purple-400">"攻击类型"</span>: <span className="text-green-400">"{aggregation?.primaryThreatType || '-'}"</span>,
              </div>
              <div className="pl-4">
                <span className="text-purple-400">"聚合次数"</span>: <span className="text-yellow-400">{aggregation?.count || 0}</span>,
              </div>
              <div className="pl-4">
                <span className="text-purple-400">"威胁等级"</span>: <span className="text-red-400">"{aggregation?.severity || '-'}"</span>
              </div>
              <div className="text-cyan-400">{'}'}</div>
            </div>
          </div>

          {/* 实时日志 */}
          <div className="bg-slate-900/50 border border-cyan-500/20 rounded-xl p-4">
            <div className="text-sm font-bold text-cyan-400 mb-3 flex items-center gap-2">
              <Activity size={16} />
              实时分析日志
              <div className="ml-auto w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            </div>
            <div 
              ref={scrollRef}
              className="bg-black/50 rounded-lg p-3 font-mono text-xs border border-slate-700/50 h-[180px] overflow-y-auto space-y-1"
            >
              {logs.length === 0 ? (
                <div className="text-slate-600 italic">等待分析任务...</div>
              ) : (
                logs.map((log, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="text-slate-600 shrink-0">[{log.time}]</span>
                    <span className={`font-bold shrink-0 ${
                      log.type === 'req' ? 'text-yellow-400' :
                      log.type === 'res' ? 'text-green-400' :
                      log.type === 'error' ? 'text-red-400' : 'text-cyan-400'
                    }`}>
                      [{log.type.toUpperCase()}]
                    </span>
                    <span className="text-slate-300 break-all">{log.message}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* 拓扑图可视化 - 使用新的SVG组件 */}
        {(phase === 'generating' || phase === 'complete') && graphData && (
          <div className="bg-slate-900/50 border border-emerald-500/20 rounded-xl p-4 overflow-hidden">
            <div className="text-sm font-bold text-emerald-400 mb-4 flex items-center gap-2">
              <Network size={16} />
              因果溯源拓扑图
              {graphData.nodes && graphData.nodes.length > 0 && (
                <span className="ml-auto text-xs text-slate-500 font-mono">
                  {graphData.nodes.length} 节点 · {graphData.edges?.length || 0} 连接
                </span>
              )}
            </div>
            
            {/* ECharts树状图可视化 */}
            <div className="h-[400px]">
              <PIDSGraph 
                graphData={graphData}
                alerts={[]}
                currentAlert={null}
              />
            </div>
            
            {/* 分析完成提示 */}
            {phase === 'complete' && graphData.nodes && graphData.nodes.length > 0 && (
              <div className="mt-4 flex items-center justify-center gap-3 py-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
                <CheckCircle className="w-5 h-5 text-emerald-400" />
                <span className="text-emerald-400 font-bold">溯源分析完成</span>
                <span className="text-slate-400 text-sm">
                  · 已识别 {graphData.nodes.length} 个关键节点
                </span>
              </div>
            )}
          </div>
        )}

        {/* 攻击源详细统计 */}
        {aggregation && (
          <div className="mt-6 grid grid-cols-4 gap-4">
            <div className="bg-slate-900/50 border border-red-500/20 rounded-xl p-4 text-center">
              <Target className="w-8 h-8 text-red-400 mx-auto mb-2" />
              <div className="text-2xl font-bold text-red-400 font-mono">{aggregation.count}</div>
              <div className="text-xs text-slate-400 mt-1">攻击次数</div>
            </div>
            <div className="bg-slate-900/50 border border-cyan-500/20 rounded-xl p-4 text-center">
              <Shield className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
              <div className="text-2xl font-bold text-cyan-400 font-mono">{aggregation.threatTypes.length}</div>
              <div className="text-xs text-slate-400 mt-1">威胁类型</div>
            </div>
            <div className="bg-slate-900/50 border border-purple-500/20 rounded-xl p-4 text-center">
              <Server className="w-8 h-8 text-purple-400 mx-auto mb-2" />
              <div className="text-2xl font-bold text-purple-400 font-mono">{aggregation.targetIps.length}</div>
              <div className="text-xs text-slate-400 mt-1">受影响资产</div>
            </div>
            <div className="bg-slate-900/50 border border-yellow-500/20 rounded-xl p-4 text-center">
              <Clock className="w-8 h-8 text-yellow-400 mx-auto mb-2" />
              <div className="text-lg font-bold text-yellow-400 font-mono">
                {Math.ceil((new Date(aggregation.latestTime).getTime() - new Date(aggregation.earliestTime).getTime()) / (1000 * 60 * 60 * 24))}天
              </div>
              <div className="text-xs text-slate-400 mt-1">攻击持续</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// ============ 主组件 ============
const ThreatTracing: React.FC = () => {
  const chartRef = useRef<HTMLDivElement>(null);
  const [selectedCity, setSelectedCity] = useState<any>(null);
  const [chartInstance, setChartInstance] = useState<echarts.ECharts | null>(null);
  const [tracingEvents, setTracingEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<ViewMode>('geo');
  const [selectedAlert, setSelectedAlert] = useState<any>(null);
  
  // 聚合数据状态
  const [aggregatedAlerts, setAggregatedAlerts] = useState<AggregatedAlert[]>([]);
  const [filteredAlerts, setFilteredAlerts] = useState<AggregatedAlert[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAggregation, setSelectedAggregation] = useState<AggregatedAlert | null>(null);
  
  // AI图谱生成状态
  const [graphData, setGraphData] = useState<any>(null);
  const [graphError, setGraphError] = useState<string | null>(null);
  
  // 当前正在展示的 threatId（用于增量合并判断）
  const [currentThreatId, setCurrentThreatId] = useState<string | null>(null);
  
  // 分析阶段状态
  const [analysisPhase, setAnalysisPhase] = useState<AnalysisPhase>('idle');
  
  // PIDS视图启动状态
  const [pidsStarted, setPidsStarted] = useState(false);
  
  // 分析完成状态
  const [analysisComplete, setAnalysisComplete] = useState(false);
  
  // System Log - 用于分析界面内嵌显示
  const [systemLogs, setSystemLogs] = useState<Array<{ time: string; type: string; message: string }>>([]);
  
  const addLog = useCallback((type: string, message: string) => {
    const time = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    setSystemLogs(prev => [...prev.slice(-30), { time, type, message }]);
  }, []);

  /**
   * 增量合并图谱数据（核心函数）
   * @param newData 新接收到的图谱数据
   * @param incomingThreatId 新数据的 threatId
   */
  const mergeGraphData = useCallback((newData: any, incomingThreatId: string) => {
    setGraphData((prevData: any) => {
      // 情况1：没有旧数据，直接使用新数据
      if (!prevData || !prevData.nodes) {
        console.log('[增量合并] 初始化图谱，节点数:', newData?.nodes?.length || 0);
        return newData;
      }

      // 情况2：threatId 不同，说明是新攻击，清空旧数据
      if (currentThreatId !== incomingThreatId) {
        console.log('[增量合并] 检测到新攻击，清空旧图谱');
        console.log('  旧 threatId:', currentThreatId);
        console.log('  新 threatId:', incomingThreatId);
        return newData;
      }

      // 情况3：threatId 相同，执行增量合并
      console.log('[增量合并] 同一攻击，追加新节点');
      
      // 合并节点（去重）
      const existingNodeIds = new Set(prevData.nodes.map((n: any) => n.id));
      const newNodes = newData.nodes?.filter((n: any) => !existingNodeIds.has(n.id)) || [];
      const mergedNodes = [...prevData.nodes, ...newNodes];
      
      // 合并边（去重）
      const existingEdgeKeys = new Set(
        prevData.edges?.map((e: any) => `${e.source}-${e.target}`) || []
      );
      const newEdges = newData.edges?.filter(
        (e: any) => !existingEdgeKeys.has(`${e.source}-${e.target}`)
      ) || [];
      const mergedEdges = [...(prevData.edges || []), ...newEdges];

      console.log('  原有节点:', prevData.nodes.length);
      console.log('  新增节点:', newNodes.length);
      console.log('  合并后节点:', mergedNodes.length);
      console.log('  原有边:', prevData.edges?.length || 0);
      console.log('  新增边:', newEdges.length);
      console.log('  合并后边:', mergedEdges.length);

      return {
        nodes: mergedNodes,
        edges: mergedEdges
      };
    });
  }, [currentThreatId]);

  // 搜索过滤
  useEffect(() => {
    const filtered = filterAggregatedAlerts(aggregatedAlerts, searchTerm);
    setFilteredAlerts(filtered);
  }, [searchTerm, aggregatedAlerts]);

  // 当切换到PIDS视图时，重置启动状态
  useEffect(() => {
    if (viewMode === 'pids') {
      setPidsStarted(false);
      setSelectedAggregation(null);
      setSelectedAlert(null);
      setGraphData(null);
    }
  }, [viewMode]);

  /**
   * 自动轮询机制：每 2 秒拉取最新告警数据，实现增量合并
   * 解决手动刷新导致 currentThreatId 状态丢失的问题
   */
  useEffect(() => {
    // 只在 PIDS 视图且已启动分析时才轮询
    if (viewMode !== 'pids' || !pidsStarted || !currentThreatId) {
      return;
    }

    console.log('[自动轮询] 启动轮询机制，每 2 秒检查新数据');
    console.log('[自动轮询] 当前 threatId:', currentThreatId);

    // 记录上次的告警数量，用于检测变化
    let lastAlertCount = 0;

    const pollInterval = setInterval(async () => {
      try {
        // 🔥 轮询后端获取最新告警数据，增量合并节点
        const token = localStorage.getItem('auth_token');
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (token) {
          headers['token'] = token;
        }
        
        // 获取最新的告警数据（最近10条）
        const response = await fetch(`http://127.0.0.1:8985/api/analysis/alert?pageNum=1&pageSize=20`, {
          headers: headers
        });
        const result = await response.json();
        
        if (result.code === 1 && result.data?.records?.length > 0) {
          const alerts = result.data.records;
          console.log(`[流式轮询] 获取到 ${alerts.length} 条告警数据`);
          
          // 🔥 核心修复：只处理当前选中攻击源IP的告警
          const currentSourceIp = selectedAggregation?.sourceIp;
          if (!currentSourceIp) {
            console.log('[流式轮询] 没有选中的攻击源，跳过轮询');
            return;
          }
          
          // 过滤只属于当前攻击源的告警
          const filteredAlerts = alerts.filter((alert: any) => alert.sourceIp === currentSourceIp);
          console.log(`[流式轮询] 过滤后属于 ${currentSourceIp} 的告警: ${filteredAlerts.length} 条`);
          
          if (filteredAlerts.length === 0) {
            console.log('[流式轮询] 无新告警，跳过更新');
            return;
          }
          
          // 🔥 增量合并节点：实现链式拓扑
          let hasNewNodes = false;
          const currentNodes = graphData?.nodes || [];
          const currentEdges = graphData?.edges || [];
          const newNodes = [...currentNodes];
          const newEdges = [...currentEdges];
          
          // 用于去重
          const existingNodeIds = new Set(currentNodes.map((n: any) => n.id));
          const existingEdgeIds = new Set(currentEdges.map((e: any) => `${e.source}_${e.target}`));
          
          // 🔥 维护最近活跃节点，实现链式连接
          let lastActiveNode: string | null = null;
          
          filteredAlerts.forEach((alert: any) => {
            const { affectedProcess, affectedFile, sourceIp, targetIp, threatId } = alert;
            
            // 添加攻击源节点
            const attackerNodeId = `attacker_${sourceIp.replace(/\./g, '_')}`;
            if (!existingNodeIds.has(attackerNodeId)) {
              newNodes.push({
                id: attackerNodeId,
                label: sourceIp,
                type: 'attacker',
                category: 0,
                symbolSize: 60,
                itemStyle: { color: '#ef4444' }
              });
              existingNodeIds.add(attackerNodeId);
              hasNewNodes = true;
              console.log(`[流式轮询] ✅ 新增攻击源节点: ${sourceIp}`);
            }
            
            // 🔥 添加防火墙节点作为中间层
            const firewallNodeId = `firewall_${sourceIp.replace(/\./g, '_')}`;
            if (!existingNodeIds.has(firewallNodeId)) {
              newNodes.push({
                id: firewallNodeId,
                label: 'Firewall',
                type: 'firewall',
                category: 1,
                symbolSize: 60,
                itemStyle: { color: '#f97316' }
              });
              existingNodeIds.add(firewallNodeId);
              hasNewNodes = true;
              console.log(`[流式轮询] ✅ 新增防火墙节点`);
              
              // 连接：攻击源 -> 防火墙
              const edgeId = `${attackerNodeId}_${firewallNodeId}`;
              if (!existingEdgeIds.has(edgeId)) {
                newEdges.push({
                  source: attackerNodeId,
                  target: firewallNodeId,
                  label: '突破'
                });
                existingEdgeIds.add(edgeId);
              }
            }
            
            // 设置防火墙为当前活跃节点
            lastActiveNode = firewallNodeId;
            
            // 🔥 添加进程节点，连接到上一个活跃节点
            if (affectedProcess && affectedProcess.trim()) {
              const processNodeId = `process_${affectedProcess.replace(/[^a-zA-Z0-9]/g, '_')}_${threatId}`;
              if (!existingNodeIds.has(processNodeId)) {
                newNodes.push({
                  id: processNodeId,
                  label: affectedProcess,
                  type: 'process',
                  category: 2,
                  symbol: 'rect',
                  symbolSize: 50,
                  itemStyle: { color: '#a855f7' }
                });
                existingNodeIds.add(processNodeId);
                hasNewNodes = true;
                console.log(`[流式轮询] ✅ 新增进程节点: ${affectedProcess}`);
                
                // 🔥 链式连接：上一个活跃节点 -> 当前进程
                if (lastActiveNode) {
                  const edgeId = `${lastActiveNode}_${processNodeId}`;
                  if (!existingEdgeIds.has(edgeId)) {
                    newEdges.push({
                      source: lastActiveNode,
                      target: processNodeId,
                      label: '执行'
                    });
                    existingEdgeIds.add(edgeId);
                  }
                }
                
                // 更新活跃节点
                lastActiveNode = processNodeId;
              } else {
                // 节点已存在，但仍然更新活跃节点
                lastActiveNode = processNodeId;
              }
            }
            
            // 🔥 添加文件节点，连接到上一个活跃节点（通常是进程）
            if (affectedFile && affectedFile.trim()) {
              const fileNodeId = `file_${affectedFile.replace(/[^a-zA-Z0-9]/g, '_')}_${threatId}`;
              if (!existingNodeIds.has(fileNodeId)) {
                newNodes.push({
                  id: fileNodeId,
                  label: affectedFile,
                  type: 'file',
                  category: 3,
                  symbol: 'triangle',
                  symbolSize: 45,
                  itemStyle: { color: '#22c55e' }
                });
                existingNodeIds.add(fileNodeId);
                hasNewNodes = true;
                console.log(`[流式轮询] ✅ 新增文件节点: ${affectedFile}`);
                
                // 🔥 链式连接：上一个活跃节点 -> 文件
                if (lastActiveNode) {
                  const edgeId = `${lastActiveNode}_${fileNodeId}`;
                  if (!existingEdgeIds.has(edgeId)) {
                    newEdges.push({
                      source: lastActiveNode,
                      target: fileNodeId,
                      label: '访问'
                    });
                    existingEdgeIds.add(edgeId);
                  }
                }
                
                // 更新活跃节点
                lastActiveNode = fileNodeId;
              }
            }
          });
          
          // 🔥 如果有新节点，更新图谱
          if (hasNewNodes) {
            const updatedGraphData = {
              nodes: newNodes,
              edges: newEdges
            };
            console.log(`[流式轮询] 🔥🔥🔥 检测到新节点！更新图谱: ${currentNodes.length} → ${newNodes.length}`);
            setGraphData(updatedGraphData);
            addLog('success', `🔥 实时更新: 新增 ${newNodes.length - currentNodes.length} 个节点！总计 ${newNodes.length} 个节点`);
          } else {
            console.log('[流式轮询] 无新节点，跳过更新');
          }
        }
      } catch (error) {
        console.error('[流式轮询] 轮询失败:', error);
      }
    }, 1000); // 每 1 秒轮询一次

    // 清理定时器
    return () => {
      console.log('[自动轮询] 停止轮询');
      clearInterval(pollInterval);
    };
  }, [viewMode, pidsStarted, graphData, currentThreatId, selectedAggregation, mergeGraphData, addLog]);

  /**
   * 调用AI引擎生成PIDS溯源图谱 - 慢速动画展示完整流程
   */
  const handleGenerateGraph = useCallback(async (alert: any, aggregation?: AggregatedAlert) => {
    if (!alert) return;
    
    const sourceIp = alert.sourceIp || alert.maliciousIp || 'unknown';
    const targetIp = alert.targetIp || '192.168.1.1';
    const attackType = alert.attackType || alert.threatType || 'Unknown';
    const incomingThreatId = alert.threatId || `${sourceIp}_${targetIp}`;
    
    // 🔥 核心修改：判断是新攻击还是增量更新
    const isNewAttack = currentThreatId !== incomingThreatId;
    
    if (isNewAttack) {
      // 新攻击：清空旧数据，重置状态
      console.log('[PIDS] 检测到新攻击，清空旧图谱');
      console.log('  旧 threatId:', currentThreatId);
      console.log('  新 threatId:', incomingThreatId);
      
      setSystemLogs([]);
      setGraphError(null);
      setGraphData(null);
      setAnalysisComplete(false);
      setCurrentThreatId(incomingThreatId);
    } else {
      // 同一攻击：增量更新，不清空数据
      console.log('[PIDS] 同一攻击，准备增量合并节点');
      console.log('  threatId:', incomingThreatId);
    }
    
    // 阶段1: 发送请求 (2秒)
    setAnalysisPhase('sending');
    addLog('info', '初始化分析任务...');
    await new Promise(r => setTimeout(r, 800));
    addLog('req', `POST /api/tracing/result/generate-graph`);
    addLog('info', `源IP: ${sourceIp}`);
    addLog('info', `目标IP: ${targetIp}`);
    addLog('info', `攻击类型: ${attackType}`);
    await new Promise(r => setTimeout(r, 1200));
    
    // 阶段2: AI引擎处理 (3秒)
    setAnalysisPhase('processing');
    addLog('info', '请求已发送至AI分析引擎...');
    await new Promise(r => setTimeout(r, 1000));
    addLog('info', 'AI引擎正在分析攻击特征...');
    await new Promise(r => setTimeout(r, 1000));
    addLog('info', '正在构建因果溯源图谱...');
    await new Promise(r => setTimeout(r, 1000));
    
    try {
      // 实际调用API
      const data = await TracingService.generateGraph(sourceIp, targetIp, attackType);
      
      // 阶段3: 接收结果 (1.5秒)
      setAnalysisPhase('receiving');
      addLog('res', '收到AI引擎响应');
      await new Promise(r => setTimeout(r, 500));
      addLog('info', `解析数据: ${data?.nodes?.length || 0} 个节点`);
      addLog('info', `解析数据: ${data?.edges?.length || 0} 条边`);
      await new Promise(r => setTimeout(r, 1000));
      
      // 阶段4: 生成图谱
      setAnalysisPhase('generating');
      addLog('info', '开始生成溯源图谱...');
      
      // 调试日志：检查返回的数据结构
      console.log('[DEBUG] Graph data received:', data);
      console.log('[DEBUG] Nodes count:', data?.nodes?.length || 0);
      console.log('[DEBUG] Edges count:', data?.edges?.length || 0);
      console.log('[DEBUG] Nodes detail:', data?.nodes);
      console.log('[DEBUG] Edges detail:', data?.edges);
      
      // 🔥 核心修改：使用增量合并而非直接覆盖
      if (isNewAttack) {
        // 新攻击：直接设置数据
        console.log('[PIDS] 新攻击，直接设置图谱数据');
        setGraphData(data);
      } else {
        // 同一攻击：增量合并
        console.log('[PIDS] 同一攻击，执行增量合并');
        mergeGraphData(data, incomingThreatId);
        addLog('info', `追加新节点: +${data?.nodes?.length || 0} 个节点`);
      }
      
      // 判断是否为降级模式
      if (data?.mode === 'fallback') {
        addLog('info', '运行在降级模式 - AI引擎离线');
      } else {
        addLog('info', 'AI引擎分析成功');
      }
      
    } catch (err: any) {
      console.error('[AI Engine] Failed to generate graph:', err);
      addLog('error', `分析失败: ${err.message || '连接超时'}`);
      setGraphError(err.message || 'AI 引擎连接超时');
      setAnalysisPhase('idle');
    }
  }, [addLog, analysisPhase, currentThreatId, mergeGraphData]);
  
  // 分析完成回调
  const handleAnalysisComplete = useCallback(() => {
    setAnalysisPhase('complete');
    setAnalysisComplete(true);
    addLog('info', '溯源分析完成!');
  }, [addLog]);

  /**
   * 选择聚合项时的处理 - 启动分析流程
   */
  const handleSelectAggregation = useCallback((aggregation: AggregatedAlert) => {
    // 如果正在分析中，提示用户等待
    if (analysisPhase !== 'idle' && analysisPhase !== 'complete') {
      console.log('[PIDS] 分析正在进行中，无法切换攻击源');
      return;
    }
    
    // 设置选中的聚合项
    setSelectedAggregation(aggregation);
    const firstAlert = aggregation.alerts[0];
    setSelectedAlert(firstAlert);
    
    // 启动PIDS分析
    setPidsStarted(true);
    
    // 调用AI引擎生成图谱
    addLog('info', `选择攻击源: ${aggregation.sourceIp}`);
    addLog('info', `聚合攻击次数: ${aggregation.count}`);
    addLog('info', `主要威胁类型: ${aggregation.primaryThreatType}`);
    
    // 使用setTimeout包装handleGenerateGraph调用，避免闭包陷阱和依赖问题
    setTimeout(() => handleGenerateGraph(firstAlert, aggregation), 0);
  }, [addLog, analysisPhase]);


  // 获取真实NIDS告警数据
  useEffect(() => {
    const fetchTracingData = async () => {
      try {
        // 优先使用NIDS真实告警数据
        const nidsData = await ThreatService.getHistory();
        
        if (nidsData && nidsData.length > 0) {
          // 转换为统一格式
          const formattedData = nidsData.map((item: any, idx: number) => ({
            id: item.id || idx,
            maliciousIp: item.sourceIp,
            sourceIp: item.sourceIp,
            targetIp: item.targetIp,
            threatType: item.type,
            attackType: item.type,
            severity: item.riskLevel === 'High' ? 'high' : item.riskLevel === 'Medium' ? 'medium' : 'low',
            detectedTime: item.timestamp,
            eventTime: item.timestamp,
            malwareOrigin: 'NIDS',
            details: item.details
          }));
          
          setTracingEvents(formattedData);
          addLog('info', `Loaded ${formattedData.length} real NIDS alerts`);
          
          // 聚合数据
          const aggregated = aggregateAlertsByIP(formattedData);
          setAggregatedAlerts(aggregated);
          setFilteredAlerts(aggregated);
        } else {
          // 无NIDS数据时尝试获取溯源表数据
          const tracingData = await TracingService.getList(1, 100);
          if (tracingData && tracingData.length > 0) {
            setTracingEvents(tracingData);
            const aggregated = aggregateAlertsByIP(tracingData);
            setAggregatedAlerts(aggregated);
            setFilteredAlerts(aggregated);
          } else {
            addLog('info', 'No real data available, using mock data');
            const mockData = getMockTracingEvents();
            setTracingEvents(mockData);
            const aggregated = aggregateAlertsByIP(mockData);
            setAggregatedAlerts(aggregated);
            setFilteredAlerts(aggregated);
          }
        }
      } catch (err) {
        console.error("Failed to fetch tracing data:", err);
        addLog('error', 'Failed to fetch NIDS data, using mock');
        const mockData = getMockTracingEvents();
        setTracingEvents(mockData);
        const aggregated = aggregateAlertsByIP(mockData);
        setAggregatedAlerts(aggregated);
        setFilteredAlerts(aggregated);
      } finally {
        setLoading(false);
      }
    };

    fetchTracingData();
    // 轮询更新
    const interval = setInterval(fetchTracingData, 10000);
    return () => clearInterval(interval);
  }, [addLog]);

  // 模拟溯源数据
  const getMockTracingEvents = () => [
    {
      id: 1,
      maliciousIp: '45.227.253.98',
      sourceIp: '45.227.253.98',
      targetIp: '192.168.1.10',
      threatType: 'SQL Injection',
      attackType: 'SQL Injection',
      severity: 'high',
      detectedTime: new Date().toISOString(),
      eventTime: new Date().toLocaleString(),
      malwareOrigin: '境外',
    },
    {
      id: 2,
      maliciousIp: '103.45.67.89',
      sourceIp: '103.45.67.89',
      targetIp: '192.168.1.15',
      threatType: 'Brute Force',
      attackType: 'Brute Force',
      severity: 'high',
      detectedTime: new Date(Date.now() - 300000).toISOString(),
      eventTime: new Date(Date.now() - 300000).toLocaleString(),
      malwareOrigin: '北京',
    },
    {
      id: 3,
      maliciousIp: '185.220.101.45',
      sourceIp: '185.220.101.45',
      targetIp: '192.168.1.20',
      threatType: 'XSS Attack',
      attackType: 'XSS',
      severity: 'medium',
      detectedTime: new Date(Date.now() - 600000).toISOString(),
      eventTime: new Date(Date.now() - 600000).toLocaleString(),
      malwareOrigin: '上海',
    },
    {
      id: 4,
      maliciousIp: '91.121.87.23',
      sourceIp: '91.121.87.23',
      targetIp: '192.168.1.5',
      threatType: 'Port Scan',
      attackType: 'Port Scan',
      severity: 'medium',
      detectedTime: new Date(Date.now() - 900000).toISOString(),
      eventTime: new Date(Date.now() - 900000).toLocaleString(),
      malwareOrigin: '广州',
    },
    {
      id: 5,
      maliciousIp: '194.26.29.113',
      sourceIp: '194.26.29.113',
      targetIp: '192.168.1.25',
      threatType: 'Malware Download',
      attackType: 'Malware',
      severity: 'critical',
      detectedTime: new Date(Date.now() - 1200000).toISOString(),
      eventTime: new Date(Date.now() - 1200000).toLocaleString(),
      malwareOrigin: '深圳',
    },
  ];

  // 初始化 ECharts 地图 (基础底图)
  useEffect(() => {
    const container = chartRef.current;
    if (!container) return;

    let chart: echarts.ECharts | null = null;
    let abortController = new AbortController();

    const initChart = async () => {
      // Ensure container has dimensions
      if (container.clientWidth === 0 || container.clientHeight === 0) {
        return;
      }

      if (!chart) {
        chart = echarts.init(container);
        setChartInstance(chart);
      }

      chart.showLoading({
        text: '正在初始化地理模型...',
        color: '#06b6d4',
        textColor: '#94a3b8',
        maskColor: 'rgba(2, 6, 23, 0.2)',
        zlevel: 0,
      });

      try {
        const response = await fetch('/maps/china.json', {
          signal: abortController.signal
        });
        const geoJson = await response.json();
        
        echarts.registerMap('china', geoJson);
        chart.hideLoading();

        // 构造节点数据
        const cityData = CHINA_GEO_NODES.map(node => ({
          ...node,
          value: [...node.coord, node.threats],
        }));

        const option: echarts.EChartsOption = {
          backgroundColor: 'transparent',
          tooltip: {
            trigger: 'item',
            backgroundColor: 'rgba(15, 23, 42, 0.9)',
            borderColor: '#334155',
            textStyle: { color: '#f1f5f9' },
            formatter: (params: any) => {
              if (params.seriesType === 'effectScatter') {
                return `
                  <div style="font-weight: bold; font-size: 16px; margin-bottom: 4px;">${params.name}</div>
                  <div style="font-size: 12px; color: #06b6d4;">威胁指数: <span style="color: white; font-family: monospace;">${params.value[2]}</span></div>
                  <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">主要威胁: ${params.data.type}</div>
                `;
              }
              return params.name;
            }
          },
          geo: {
            map: 'china',
            roam: true,
            zoom: 1.25,
            center: [105.1954, 36.8617],
            label: {
              show: true,
              color: '#94a3b8',
              fontSize: 10
            },
            itemStyle: {
              areaColor: '#0f172a',
              borderColor: '#1e293b',
              borderWidth: 1,
              shadowColor: 'rgba(6, 182, 212, 0.5)',
              shadowBlur: 10
            },
            emphasis: {
              itemStyle: {
                areaColor: '#1e293b',
                borderColor: '#06b6d4',
                borderWidth: 2
              },
              label: {
                color: '#fff'
              }
            }
          },
          series: [
            {
              name: 'Nodes',
              type: 'effectScatter',
              coordinateSystem: 'geo',
              data: cityData,
              symbolSize: (val: any) => val[2] / 5,
              showEffectOn: 'render',
              rippleEffect: {
                brushType: 'stroke',
                scale: 3
              },
              label: {
                show: false
              },
              itemStyle: {
                color: '#06b6d4',
                shadowBlur: 10,
                shadowColor: '#06b6d4'
              },
              zlevel: 1
            },
            {
              name: 'Attack Lines',
              type: 'lines',
              zlevel: 2,
              effect: {
                show: true,
                period: 4,
                trailLength: 0.5,
                color: '#ef4444',
                symbol: 'arrow',
                symbolSize: 5
              },
              lineStyle: {
                color: '#ef4444',
                width: 1,
                opacity: 0.4,
                curveness: 0.2
              },
              data: [] // Initial empty
            }
          ]
        };

        chart.setOption(option);
        
        chart.on('click', (params: any) => {
          if (params.seriesType === 'effectScatter') {
            setSelectedCity(params.data);
          }
        });

      } catch (error) {
        if (!abortController.signal.aborted) {
          console.error('Failed to load map data:', error);
          chart?.hideLoading();
        }
      }
    };

    initChart();

    const handleResize = () => chart?.resize();
    window.addEventListener('resize', handleResize);

    return () => {
      abortController.abort();
      window.removeEventListener('resize', handleResize);
      chart?.dispose();
    };
  }, []);

  // 监听 tracingEvents 更新地图连线
  useEffect(() => {
    // 🔥 修复：只在地理视图模式下更新地图，避免 InvalidStateError
    if (!chartInstance || !tracingEvents || viewMode !== 'geo') return;

    // 真实攻击飞线数据生成逻辑
    const generateLines = () => {
      if (tracingEvents.length === 0) return [];
      
      const lines: any[] = [];
      // 目标中心设为深圳 (User Request)
      const targetNode = CHINA_GEO_NODES.find(n => n.id === 'sz');
      if (!targetNode) return [];

      tracingEvents.forEach(event => {
        // 尝试根据 malwareOrigin 匹配源节点
        let sourceNode = CHINA_GEO_NODES.find(n => event.malwareOrigin && n.name.includes(event.malwareOrigin));
        
        // 如果无法直接匹配，且存在恶意IP，使用IP哈希映射到某个节点作为演示
        if (!sourceNode && event.maliciousIp) {
            const sum = event.maliciousIp.split('.').reduce((acc: number, part: string) => acc + (parseInt(part) || 0), 0);
            sourceNode = CHINA_GEO_NODES[sum % CHINA_GEO_NODES.length];
        }

        if (sourceNode && sourceNode.id !== targetNode.id) {
          lines.push({
            fromName: sourceNode.name,
            toName: targetNode.name,
            coords: [sourceNode.coord, targetNode.coord],
            value: 80 // 默认高危
          });
        }
      });
      
      return lines;
    };

    // 安全更新Attack Lines的数据
    try {
      const currentOption = chartInstance.getOption();
      if (currentOption && currentOption.series && Array.isArray(currentOption.series) && currentOption.series.length >= 2) {
        // 只更新第二个series的data，并确保不触发重新渲染错误
        chartInstance.setOption({
          series: [
            { name: 'Nodes' }, // 空对象保持不变
            { 
              name: 'Attack Lines', 
              data: generateLines(),
              silent: true // 禁止交互，避免渲染错误
            }
          ]
        }, {
          notMerge: false,
          lazyUpdate: true // 延迟更新，避免频繁渲染
        });
      }
    } catch (e) {
      console.warn('[ECharts] Failed to update series:', e);
      // 如果更新失败，尝试重新初始化图表
      try {
        chartInstance.clear();
        chartInstance.resize();
      } catch (resizeError) {
        console.warn('[ECharts] Failed to recover:', resizeError);
      }
    }

  }, [tracingEvents, chartInstance, viewMode]);

  const handleZoom = (delta: number) => {
    if (chartInstance) {
      const option = chartInstance.getOption() as any;
      const currentZoom = option.geo[0].zoom;
      chartInstance.setOption({
        geo: { zoom: currentZoom + delta }
      });
    }
  };

  const handleReset = () => {
    if (chartInstance) {
      chartInstance.setOption({
        geo: { 
          center: [105.1954, 36.8617],
          zoom: 1.25 
        }
      });
      setSelectedCity(null);
    }
  };

  return (
    <div className="h-full flex flex-col animate-fade-in relative overflow-hidden space-y-6">
      {/* Header */}
      <PageHeader 
        title="攻击溯源分析" 
        subtitle="全球威胁溯源可视化图谱" 
        showLive 
        liveText="追踪中"
      >
        <div className="flex gap-3 items-center">
          {/* 视图切换开关 */}
          <div className="relative rounded-xl p-1 flex items-center overflow-hidden" style={{background: 'rgba(20, 30, 40, 0.9)', border: '1px solid rgba(255, 255, 255, 0.1)'}}>
            <button
              onClick={() => setViewMode('geo')}
              className={`px-4 py-2 rounded-lg flex items-center gap-2 transition-all text-sm font-medium ${
                viewMode === 'geo' 
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50' 
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Map size={16} />
              地理拓扑
            </button>
            <button
              onClick={() => setViewMode('pids')}
              className={`px-4 py-2 rounded-lg flex items-center gap-2 transition-all text-sm font-medium ${
                viewMode === 'pids' 
                  ? 'bg-red-500/20 text-red-400 border border-red-500/50' 
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Network size={16} />
              PIDS因果溯源
            </button>
          </div>

          <div className="relative rounded-xl px-4 py-2.5 flex items-center gap-3 overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(0,30,40,0.95) 0%, rgba(0,50,60,0.9) 100%)'}}>
             <div className="absolute inset-0 rounded-xl border border-cyan-500/30"></div>
             <Globe size={20} className="text-cyan-400 relative z-10" />
             <div className="relative z-10">
               <div className="text-[10px] text-slate-500 uppercase">监控节点</div>
               <div className="text-lg font-bold text-cyan-400 font-mono">{viewMode === 'pids' ? (graphData?.nodes?.length || 0) : CHINA_GEO_NODES.length}</div>
             </div>
          </div>
          <div className="relative rounded-xl px-4 py-2.5 flex items-center gap-3 overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(40,0,20,0.95) 0%, rgba(60,0,30,0.9) 100%)'}}>
             <div className="absolute inset-0 rounded-xl border border-red-500/30"></div>
             <AlertTriangle size={20} className="text-red-400 relative z-10" />
             <div className="relative z-10">
               <div className="text-[10px] text-slate-500 uppercase">溯源事件</div>
               <div className="text-lg font-bold text-red-400 font-mono">{viewMode === 'pids' ? (graphData?.edges?.length || 0) : tracingEvents.length}</div>
             </div>
          </div>
        </div>
      </PageHeader>

      {/* Main Content Area */}
      <div className="flex-1 relative rounded-2xl overflow-hidden flex" style={{background: 'linear-gradient(145deg, rgba(0,5,15,0.98) 0%, rgba(0,15,25,0.95) 100%)'}}>
        <div className="absolute inset-0 rounded-2xl border border-cyan-500/20"></div>
        <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent"></div>
        
        {viewMode === 'geo' ? (
          <>
            {/* Map Container */}
            <div className="flex-1 relative">
               {/* Legend */}
               <div className="absolute bottom-5 left-5 z-20 pointer-events-none">
                 <div className="glass-panel p-4 rounded-lg space-y-2 pointer-events-auto">
                   <div className="text-xs font-bold text-slate-400 mb-2 uppercase tracking-wider">Map Legend</div>
                   <div className="flex items-center gap-2 text-xs text-slate-300">
                     <span className="w-2 h-2 rounded-full bg-cyber-accent shadow-[0_0_8px_#06b6d4]"></span> 监控正常
                   </div>
                   <div className="flex items-center gap-2 text-xs text-slate-300">
                     <span className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_#ef4444]"></span> 威胁检测
                   </div>
                   <div className="flex items-center gap-2 text-xs text-slate-300">
                     <span className="w-8 h-0.5 bg-gradient-to-r from-red-500/0 via-red-500 to-red-500/0"></span> 攻击链路
                   </div>
                 </div>
               </div>

               {/* Map Controls */}
               <div className="absolute top-5 right-5 z-20 flex flex-col gap-2">
                  <button onClick={() => handleZoom(0.2)} className="p-2.5 bg-cyber-900/90 rounded-lg border border-cyber-700 hover:border-cyber-accent hover:text-cyber-accent text-slate-400 shadow-xl transition-all active:scale-95"><ZoomIn size={20} /></button>
                  <button onClick={() => handleZoom(-0.2)} className="p-2.5 bg-cyber-900/90 rounded-lg border border-cyber-700 hover:border-cyber-accent hover:text-cyber-accent text-slate-400 shadow-xl transition-all active:scale-95"><ZoomOut size={20} /></button>
                  <button onClick={handleReset} className="p-2.5 bg-cyber-900/90 rounded-lg border border-cyber-700 hover:border-cyber-accent hover:text-cyber-accent text-slate-400 shadow-xl transition-all active:scale-95"><Crosshair size={20} /></button>
               </div>

               {/* ECharts Container */}
               <div ref={chartRef} className="w-full h-full z-10 min-h-[500px]" style={{ minHeight: '500px' }} />
            </div>

            {/* Real-time List Panel (Left Side Overlay) */}
            <div className="absolute top-5 left-5 z-20 w-80 max-h-[60%] flex flex-col pointer-events-none space-y-4">
                 {selectedCity && (
                   <div className="glass-panel p-4 rounded-xl pointer-events-auto border border-cyan-500/30 animate-slide-right bg-cyber-900/90 backdrop-blur-md">
                     <div className="flex justify-between items-start mb-3">
                       <div>
                         <h3 className="text-xl font-bold text-white flex items-center gap-2">
                           <span className="w-2 h-6 bg-cyan-500 rounded-full"></span>
                           {selectedCity.name}
                         </h3>
                         <p className="text-xs text-slate-400 mt-1 font-mono">
                           COORD: [{selectedCity.coord[0].toFixed(2)}, {selectedCity.coord[1].toFixed(2)}]
                         </p>
                       </div>
                       <button 
                         onClick={() => setSelectedCity(null)}
                         className="text-slate-500 hover:text-white transition-colors"
                       >
                         ✕
                       </button>
                     </div>
                     
                     <div className="space-y-3">
                       <div className="bg-black/40 p-3 rounded-lg border border-cyan-500/20">
                         <p className="text-xs text-cyan-400/80 mb-1">当前威胁指数</p>
                         <div className="flex items-end gap-2">
                           <span className="text-2xl font-mono font-bold text-white">{selectedCity.threats}</span>
                           <span className="text-xs text-slate-500 mb-1">Events/Hour</span>
                         </div>
                         <div className="w-full h-1.5 bg-gray-700 rounded-full mt-2 overflow-hidden">
                           <div 
                             className="h-full bg-gradient-to-r from-cyan-500 to-blue-500" 
                             style={{width: `${Math.min(selectedCity.threats, 100)}%`}}
                           ></div>
                         </div>
                       </div>

                       <div className="bg-black/40 p-3 rounded-lg border border-red-500/20">
                         <p className="text-xs text-red-400/80 mb-1">主要威胁类型</p>
                         <p className="text-sm font-bold text-white flex items-center gap-2">
                           <AlertTriangle size={14} className="text-red-500" />
                           {selectedCity.type}
                         </p>
                       </div>

                       <div className="p-3 bg-slate-800/50 rounded-lg">
                         <p className="text-xs text-slate-400 mb-1">最新情报详情</p>
                         <p className="text-xs text-slate-300 leading-relaxed">
                           {selectedCity.details}
                         </p>
                       </div>
                     </div>
                   </div>
                 )}
            </div>
          </>
        ) : (
          /* PIDS因果溯源视图 - 聚合展示 */
          <div className="flex-1 flex h-[calc(100vh-64px)]">
            {/* 左侧聚合列表 - 科技感攻击源导航 (18%) */}
            <div className="w-[18%] min-w-[240px] max-w-[280px] border-r border-cyan-500/20 flex flex-col bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950 relative overflow-hidden">
              {/* 顶部装饰线 */}
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-500 to-transparent" />
              
              {/* 头部标题 */}
              <div className="p-3 border-b border-cyan-500/20 relative">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500/30 to-purple-500/30 flex items-center justify-center border border-cyan-500/50">
                    <Target className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div>
                    <div className="text-base font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-400">
                      威胁源追踪
                    </div>
                    <div className="text-xs text-slate-500 font-mono">THREAT SOURCES</div>
                  </div>
                  <div className="ml-auto flex items-center gap-1.5 px-2 py-1 bg-red-500/20 border border-red-500/30 rounded-full">
                    <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                    <span className="text-xs text-red-400 font-mono">{filteredAlerts.length}</span>
                  </div>
                </div>
                
                {/* 搜索框 */}
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-cyan-400/50" size={16} />
                  <input
                    type="text"
                    placeholder="搜索IP或攻击类型..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 bg-black/40 border border-cyan-500/30 rounded-xl text-white text-sm font-mono placeholder-slate-600 focus:outline-none focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20 transition-all"
                  />
                </div>
                
                {/* 统计信息 */}
                <div className="mt-3 flex items-center justify-between text-xs bg-black/20 rounded-lg p-2">
                  <div className="flex items-center gap-2">
                    <Activity size={12} className="text-cyan-400" />
                    <span className="text-slate-400">
                      <span className="text-cyan-400 font-bold font-mono">{filteredAlerts.length}</span> 个攻击源
                    </span>
                  </div>
                  <div className="text-slate-500 font-mono">
                    {tracingEvents.length} 条原始告警
                  </div>
                </div>
              </div>

              {/* 攻击源列表 - 使用科技感卡片 */}
              <div className="flex-1 overflow-y-auto p-3 space-y-2 scrollbar-thin scrollbar-thumb-cyan-500/20 scrollbar-track-transparent">
                {filteredAlerts.length > 0 ? filteredAlerts.map((agg, idx) => (
                  <CyberAttackCard
                    key={agg.sourceIp}
                    aggregation={agg}
                    isSelected={selectedAggregation?.sourceIp === agg.sourceIp}
                    onClick={() => handleSelectAggregation(agg)}
                    index={idx}
                  />
                )) : (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <div className="w-16 h-16 rounded-full bg-slate-800/50 flex items-center justify-center mb-4">
                      <Shield size={32} className="text-slate-600" />
                    </div>
                    <div className="text-slate-500 text-sm">
                      {searchTerm ? '未找到匹配的攻击源' : '暂无威胁事件'}
                    </div>
                    <div className="text-slate-600 text-xs mt-1">系统安全</div>
                  </div>
                )}
              </div>
              
              {/* 底部装饰 */}
              <div className="absolute bottom-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent" />
            </div>

            {/* 右侧主视图区域 */}
            <div className="flex-1 relative">
              {!pidsStarted ? (
                /* PIDS启动页 */
                <div className="flex items-center justify-center h-full bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
                  <div className="text-center">
                    {/* Logo */}
                    <div className="mb-12">
                      <div className="text-7xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 mb-4 tracking-wider animate-pulse">
                        P.I.D.S.
                      </div>
                      <div className="text-slate-400 text-lg font-mono tracking-[0.3em] mb-2">
                        PROVENANCE-BASED INTRUSION DETECTION SYSTEM
                      </div>
                      <div className="text-cyan-500 text-sm font-mono">
                        神经溯源分析引擎 v3.0
                      </div>
                    </div>

                    {/* 启动按钮 */}
                    <button
                      onClick={() => {
                        setPidsStarted(true);
                        if (filteredAlerts.length > 0) {
                          handleSelectAggregation(filteredAlerts[0]);
                        }
                      }}
                      className="group relative px-16 py-6 rounded-xl overflow-hidden transition-all duration-300 hover:scale-105"
                    >
                      {/* 按钮发光背景 */}
                      <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/30 via-blue-500/30 to-purple-500/30 group-hover:from-cyan-500/50 group-hover:via-blue-500/50 group-hover:to-purple-500/50 transition-all" />
                      <div className="absolute inset-0 border-2 border-cyan-500/50 group-hover:border-cyan-400 rounded-xl transition-all" />
                      <div className="absolute inset-0 animate-pulse" style={{
                        boxShadow: '0 0 30px rgba(6, 182, 212, 0.4), inset 0 0 30px rgba(6, 182, 212, 0.2)'
                      }} />
                      
                      <div className="relative flex items-center gap-4">
                        <Zap className="w-8 h-8 text-cyan-400 group-hover:text-cyan-300" />
                        <span className="text-2xl font-bold text-cyan-400 group-hover:text-cyan-300 font-mono tracking-wide">
                          PIDS 因果溯源解析
                        </span>
                      </div>
                    </button>

                    {/* 详细统计信息 */}
                    <div className="mt-12 grid grid-cols-4 gap-6 max-w-2xl mx-auto">
                      <div className="bg-slate-900/50 border border-cyan-500/20 rounded-xl p-4 text-center">
                        <div className="text-3xl font-bold text-cyan-400 font-mono">{filteredAlerts.length}</div>
                        <div className="text-xs text-slate-400 mt-1">聚合攻击源</div>
                      </div>
                      <div className="bg-slate-900/50 border border-purple-500/20 rounded-xl p-4 text-center">
                        <div className="text-3xl font-bold text-purple-400 font-mono">{tracingEvents.length}</div>
                        <div className="text-xs text-slate-400 mt-1">原始告警</div>
                      </div>
                      <div className="bg-slate-900/50 border border-red-500/20 rounded-xl p-4 text-center">
                        <div className="text-3xl font-bold text-red-400 font-mono">
                          {filteredAlerts.filter(a => a.severity === 'high' || a.severity === '高危').length}
                        </div>
                        <div className="text-xs text-slate-400 mt-1">高危威胁</div>
                      </div>
                      <div className="bg-slate-900/50 border border-yellow-500/20 rounded-xl p-4 text-center">
                        <div className="text-3xl font-bold text-yellow-400 font-mono">
                          {new Set(filteredAlerts.map(a => a.primaryThreatType)).size}
                        </div>
                        <div className="text-xs text-slate-400 mt-1">威胁类型</div>
                      </div>
                    </div>

                    {/* 威胁类型分布 */}
                    <div className="mt-8 max-w-xl mx-auto">
                      <div className="text-sm text-slate-400 mb-3 text-left">主要威胁类型分布</div>
                      <div className="flex flex-wrap gap-2 justify-center">
                        {Array.from(new Set(filteredAlerts.slice(0, 10).map(a => a.primaryThreatType))).map((type, idx) => (
                          <span key={idx} className="px-3 py-1 bg-slate-800/50 border border-slate-700 rounded-full text-xs text-slate-300">
                            {type}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* 提示信息 */}
                    <div className="mt-8 text-slate-500 text-sm">
                      点击左侧攻击源列表选择目标，或点击上方按钮开始分析
                    </div>

                    {/* 版本信息 */}
                    <div className="mt-12 text-slate-600 text-xs font-mono">
                      御链天鉴 KAIROS 引擎 | © 2026 智联安全
                    </div>
                  </div>
                </div>
              ) : graphError ? (
                /* AI引擎错误提示 */
                <div className="flex items-center justify-center h-full">
                  <div className="text-center p-8 bg-slate-900/50 rounded-xl border border-red-500/30 max-w-md">
                    <AlertTriangle size={64} className="mx-auto mb-4 text-red-400 animate-pulse" />
                    <h3 className="text-xl font-bold text-red-400 mb-2 font-mono">AI引擎连接失败</h3>
                    <p className="text-slate-400 mb-4">{graphError}</p>
                    <div className="flex gap-3 justify-center">
                      <button 
                        onClick={() => selectedAlert && handleGenerateGraph(selectedAlert)}
                        className="px-4 py-2 bg-cyan-500/20 text-cyan-400 rounded-lg border border-cyan-500/30 hover:bg-cyan-500/30 transition-colors font-mono text-sm"
                      >
                        重试连接
                      </button>
                      <button 
                        onClick={() => {
                          setPidsStarted(false);
                          setAnalysisPhase('idle');
                        }}
                        className="px-4 py-2 bg-slate-700/50 text-slate-400 rounded-lg border border-slate-600/30 hover:bg-slate-600/30 transition-colors font-mono text-sm"
                      >
                        返回首页
                      </button>
                    </div>
                  </div>
                </div>
              ) : selectedAggregation ? (
                /* 增强版分析视图 - 展示完整分析流程 */
                <div className="absolute inset-0">
                  {/* 返回按钮 */}
                  <div className="absolute top-4 left-4 z-30">
                    <button
                      onClick={() => {
                        setPidsStarted(false);
                        setAnalysisPhase('idle');
                        setSelectedAggregation(null);
                      }}
                      className="px-4 py-2 bg-slate-900/90 border border-cyan-500/50 rounded-lg text-cyan-400 text-sm font-mono hover:bg-cyan-500/20 transition-all flex items-center gap-2 backdrop-blur-md shadow-lg shadow-cyan-500/20"
                    >
                      ← 返回首页
                    </button>
                  </div>
                  
                  {/* 增强版分析界面 */}
                  <EnhancedAnalysisView
                    aggregation={selectedAggregation}
                    phase={analysisPhase}
                    logs={systemLogs}
                    graphData={graphData}
                    onComplete={handleAnalysisComplete}
                  />
                </div>
              ) : (
                <div className="flex items-center justify-center h-full text-slate-500 text-lg">
                  <div className="text-center">
                    <AlertTriangle size={48} className="mx-auto mb-4 text-slate-600" />
                    <p>正在加载数据...</p>
                  </div>
                </div>
              )}
            </div>

            {/* 右侧详情面板 - 威胁情报分析 (26%) */}
            {selectedAggregation && (
              <div className="w-[26%] min-w-[300px] max-w-[400px] border-l border-cyan-500/20 overflow-y-auto" style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(6,182,212,0.5) rgba(15,23,42,0.5)' }}>
                <CyberDetailPanel 
                  aggregation={selectedAggregation}
                  totalAlerts={tracingEvents.length}
                  totalSources={aggregatedAlerts.length}
                />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatTracing;
