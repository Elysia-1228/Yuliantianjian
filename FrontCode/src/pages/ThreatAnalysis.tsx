import React, { useState, useEffect } from 'react';
import { ComposedChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Bar } from 'recharts';
import { Filter, Download, RefreshCw, Loader2, FileCheck, Shield, AlertTriangle, TrendingUp, Activity } from 'lucide-react';
import PageHeader from '../components/PageHeader';
import { AnalysisService } from '../services/connector';

const ThreatAnalysis: React.FC = () => {
  const [timeRange, setTimeRange] = useState('24h');
  const [chartData, setChartData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [exportSuccess, setExportSuccess] = useState(false);

  // Fetch real data when timeRange changes
  useEffect(() => {
    fetchData(timeRange);
  }, [timeRange]);

  const fetchData = async (range: string) => {
    setLoading(true);
    try {
      // 使用新的聚合统计接口
      const data = await AnalysisService.getTrend(range);
      
      // 数据处理与聚合
      const processedData = processData(data, range);
      setChartData(processedData);
    } catch (error) {
      console.error("Failed to fetch analysis data:", error);
    } finally {
      setLoading(false);
    }
  };

  const processData = (data: any[], range: string) => {
    if (!data || data.length === 0) return [];

    return data.map(item => {
        // 后端返回 { time_bucket: "2023-10-27 10:00:00", count: 5 }
        const fullTime = item.time_bucket; 
        let displayTime = fullTime;

        if (range === '24h') {
            // "2023-10-27 10:00:00" -> "10:00"
            displayTime = fullTime.substring(11, 16);
        } else {
            // "2023-10-27" -> "10-27"
            displayTime = fullTime.substring(5, 10);
        }

        return {
            name: displayTime,
            attacks: item.count,
            traffic: 0 // 暂时无流量数据
        };
    });
  };

  const handleRefresh = () => {
    fetchData(timeRange);
  };

  const handleExport = () => {
      setIsExporting(true);
      setExportSuccess(false);
      
      try {
          if (!chartData || chartData.length === 0) {
              alert("当前没有数据可导出");
              setIsExporting(false);
              return;
          }

          // Convert chartData to CSV
          const headers = ['Time', 'Attacks', 'Traffic(Bytes)'];
          const csvContent = [
              headers.join(','),
              ...chartData.map(row => `${row.name},${row.attacks},${row.traffic}`)
          ].join('\n');
          
          const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
          const url = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = url;
          link.setAttribute('download', `threat_analysis_${new Date().toISOString().slice(0,10)}.csv`);
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          
          setExportSuccess(true);
          setTimeout(() => setExportSuccess(false), 3000);
      } catch (e) {
          console.error("Export failed", e);
      } finally {
          setIsExporting(false);
      }
  };

  return (
    <div className="space-y-8 animate-slide-up">
      {/* Header & Controls */}
      <PageHeader title="威胁流量分析" subtitle="多维度威胁数据可视化大屏">
        <div className="flex gap-3">
           <button onClick={handleRefresh} className={`p-2.5 bg-cyber-800 border border-cyber-700 rounded-lg text-slate-300 hover:text-white hover:border-cyber-accent transition-all ${loading ? 'animate-spin text-cyber-accent' : ''}`}>
             <RefreshCw size={18} />
           </button>
           
           <button 
             onClick={handleExport}
             disabled={isExporting}
             className={`flex items-center gap-2 px-4 py-2 border rounded-lg text-sm transition-all min-w-[120px] justify-center ${
                 exportSuccess 
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/50' 
                    : 'bg-cyber-800 border-cyber-700 text-slate-300 hover:text-white hover:bg-cyber-700'
             }`}
           >
             {isExporting ? (
                 <Loader2 size={16} className="animate-spin" />
             ) : exportSuccess ? (
                 <><FileCheck size={16} /> 导出成功</>
             ) : (
                 <><Download size={16} /> 导出报表</>
             )}
           </button>
        </div>
      </PageHeader>

      {/* 统计卡片 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="relative rounded-2xl p-5 overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(0,20,40,0.95) 0%, rgba(0,40,60,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-cyan-500/30"></div>
          <div className="absolute -right-4 -top-4 w-20 h-20 bg-cyan-500/20 rounded-full blur-2xl"></div>
          <div className="relative z-10">
            <div className="flex items-center justify-between">
              <Shield size={20} className="text-cyan-400" />
              <span className="text-xs text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse"></span>
                实时
              </span>
            </div>
            <p className="text-4xl font-mono font-bold text-white mt-3">{chartData.reduce((sum, d) => sum + (d.attacks || 0), 0)}</p>
            <p className="text-sm text-slate-400 mt-1">检测到的威胁</p>
          </div>
        </div>

        <div className="relative rounded-2xl p-5 overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(40,0,20,0.95) 0%, rgba(60,0,30,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-red-500/30"></div>
          <div className="absolute -right-4 -top-4 w-20 h-20 bg-red-500/20 rounded-full blur-2xl"></div>
          <div className="relative z-10">
            <AlertTriangle size={20} className="text-red-400" />
            <p className="text-4xl font-mono font-bold text-red-400 mt-3">{Math.max(...chartData.map(d => d.attacks || 0), 0)}</p>
            <p className="text-sm text-slate-400 mt-1">峰值攻击次数</p>
          </div>
        </div>

        <div className="relative rounded-2xl p-5 overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(20,30,0,0.95) 0%, rgba(40,50,0,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-yellow-500/30"></div>
          <div className="absolute -right-4 -top-4 w-20 h-20 bg-yellow-500/20 rounded-full blur-2xl"></div>
          <div className="relative z-10">
            <TrendingUp size={20} className="text-yellow-400" />
            <p className="text-4xl font-mono font-bold text-yellow-400 mt-3">{chartData.length > 0 ? Math.round(chartData.reduce((sum, d) => sum + (d.attacks || 0), 0) / chartData.length) : 0}</p>
            <p className="text-sm text-slate-400 mt-1">平均攻击频率</p>
          </div>
        </div>

        <div className="relative rounded-2xl p-5 overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(0,30,20,0.95) 0%, rgba(0,50,30,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-emerald-500/30"></div>
          <div className="absolute -right-4 -top-4 w-20 h-20 bg-emerald-500/20 rounded-full blur-2xl"></div>
          <div className="relative z-10">
            <Activity size={20} className="text-emerald-400" />
            <p className="text-4xl font-mono font-bold text-emerald-400 mt-3">98.5%</p>
            <p className="text-sm text-slate-400 mt-1">拦截成功率</p>
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="relative rounded-2xl p-4 flex flex-wrap gap-6 items-center overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(0,10,20,0.95) 0%, rgba(0,20,30,0.9) 100%)'}}>
        <div className="absolute inset-0 rounded-2xl border border-blue-500/20"></div>
        <div className="relative z-10 flex flex-wrap gap-6 items-center w-full">
          <div className="flex items-center gap-3">
             <Filter size={16} className="text-cyan-400" />
             <span className="text-sm font-bold text-slate-300">维度筛选:</span>
          </div>
          
          <div className="flex items-center gap-2">
             <select className="bg-black/30 border border-cyan-500/30 rounded-lg px-3 py-1.5 text-sm text-slate-300 outline-none hover:border-cyan-500/60 focus:border-cyan-400 transition-colors cursor-pointer" disabled={loading}>
               <option>所有攻击类型</option>
               <option>DDoS 洪水</option>
               <option>SQL 注入</option>
               <option>恶意软件通信</option>
             </select>
          </div>

          <div className="h-6 w-px bg-cyan-500/20"></div>

          <div className="flex items-center gap-2 bg-black/30 rounded-lg p-1 border border-cyan-500/20">
             {['24h', '7d', '30d'].map(range => (
               <button
                 key={range}
                 onClick={() => setTimeRange(range)}
                 disabled={loading}
                 className={`px-4 py-1.5 text-xs font-bold rounded-lg transition-all ${
                   timeRange === range 
                     ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-lg shadow-cyan-500/30' 
                     : 'text-slate-400 hover:text-white hover:bg-white/5'
                 }`}
               >
                 {range === '24h' ? '24小时' : range === '7d' ? '7天' : '30天'}
               </button>
             ))}
          </div>
        </div>
      </div>

      {/* Main Chart Area */}
      <div className="glass-panel rounded-xl p-6 h-[550px] relative">
        <div className="flex justify-between items-center mb-6">
           <h3 className="text-lg font-bold text-white flex items-center gap-2">
             <span className="w-1 h-6 bg-cyber-accent rounded-full"></span>
             攻击频率与流量趋势
           </h3>
           <div className="flex gap-4 text-xs">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-sm bg-blue-500"></span>
                <span className="text-slate-400">攻击次数</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-cyber-accent"></span>
                <span className="text-slate-400">流量占比</span>
              </div>
           </div>
        </div>

        <div className="h-[85%] w-full relative">
            {loading && (
                <div className="absolute inset-0 z-10 flex items-center justify-center bg-cyber-900/20 backdrop-blur-sm rounded-lg transition-all">
                    <Loader2 size={40} className="text-cyber-accent animate-spin" />
                </div>
            )}
            <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={chartData} margin={{ top: 20, right: 20, bottom: 20, left: 0 }}>
                <defs>
                <linearGradient id="colorTraffic" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorAttacks" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.3}/>
                </linearGradient>
                </defs>
                <CartesianGrid stroke="#334155" strokeDasharray="3 3" vertical={false} opacity={0.4} />
                <XAxis 
                dataKey="name" 
                stroke="#94a3b8" 
                tickLine={false} 
                axisLine={false}
                dy={10}
                fontSize={12}
                />
                <YAxis 
                yAxisId="left" 
                stroke="#94a3b8" 
                tickLine={false} 
                axisLine={false}
                label={{ value: '事件数', angle: -90, position: 'insideLeft', fill: '#64748b', fontSize: 10 }}
                fontSize={12}
                />
                <YAxis 
                yAxisId="right" 
                orientation="right" 
                stroke="#06b6d4" 
                tickLine={false} 
                axisLine={false}
                label={{ value: '流量 %', angle: 90, position: 'insideRight', fill: '#06b6d4', fontSize: 10 }}
                fontSize={12}
                />
                <Tooltip 
                contentStyle={{ 
                    backgroundColor: 'rgba(15, 23, 42, 0.9)', 
                    borderColor: '#334155', 
                    color: '#f1f5f9',
                    borderRadius: '8px',
                    backdropFilter: 'blur(4px)',
                    boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)'
                }}
                cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                />
                <Bar 
                yAxisId="left" 
                dataKey="attacks" 
                barSize={20} 
                fill="url(#colorAttacks)" 
                radius={[4, 4, 0, 0]} 
                animationDuration={1000}
                />
                <Area 
                yAxisId="right" 
                type="monotone" 
                dataKey="traffic" 
                stroke="#06b6d4" 
                strokeWidth={3} 
                fill="url(#colorTraffic)" 
                dot={{ r: 4, fill: '#06b6d4', strokeWidth: 2, stroke: '#fff' }}
                activeDot={{ r: 6, fill: '#fff', stroke: '#06b6d4' }}
                animationDuration={1000}
                />
            </ComposedChart>
            </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

export default ThreatAnalysis;