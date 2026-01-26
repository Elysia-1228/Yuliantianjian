import React, { useEffect, useState } from 'react';
import { XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, AreaChart, Area } from 'recharts';
import { Cpu, Network, Wifi, AlertOctagon, HardDrive, FileSearch, FolderOpen, Database, Shield, UserCheck, ShieldCheck, AlertTriangle, Lock, Key, Activity } from 'lucide-react';
import { Link } from 'react-router-dom';
import PageHeader from '../components/PageHeader';
import { MonitorService, ConfigService, ThreatService } from '../services/connector';

const HostMonitoring: React.FC = () => {
  const [data, setData] = useState<any[]>([]);
  const [hostId, setHostId] = useState('');
  const [hosts, setHosts] = useState<any[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'unstable' | 'disconnected'>('disconnected');
  const [latency, setLatency] = useState(0);
  const [logs, setLogs] = useState<{time: string, type: string, msg: string}[]>([]);
  
  // NIDS 网络威胁统计
  const [nidsStats, setNidsStats] = useState<{high: number, medium: number, low: number, total: number, types: {name: string, count: number}[]}>({high: 0, medium: 0, low: 0, total: 0, types: []});

  // Load hosts
  useEffect(() => {
    const fetchHosts = async () => {
      try {
        const allHostsMap = new Map<string, any>();
        try {
          const configRes = await ConfigService.getHostList(1, 100);
          if (configRes.list) {
            configRes.list.forEach((h: any) => {
              if (h.hostIp) {
                allHostsMap.set(h.hostIp, { id: h.id, hostIp: h.hostIp, source: 'config' });
              }
            });
          }
        } catch (e) {
          console.error("Failed to load config hosts", e);
        }

        try {
          const monitorRes = await MonitorService.getMonitorList(1, 100);
          if (monitorRes) {
            monitorRes.forEach((h: any) => {
               if (h.hostId && !allHostsMap.has(h.hostId)) {
                 allHostsMap.set(h.hostId, { id: `auto-${h.hostId}`, hostIp: h.hostId, source: 'active' });
               }
            });
          }
        } catch (e) {
           console.error("Failed to load active hosts", e);
        }

        const combinedHosts = Array.from(allHostsMap.values());
        setHosts(combinedHosts);

        if (!hostId && combinedHosts.length > 0) {
           setHostId(combinedHosts[0].hostIp);
        }
      } catch (e) {
        console.error("Failed to load hosts", e);
      }
    };
    fetchHosts();
  }, []);

  // 获取NIDS网络威胁统计
  useEffect(() => {
    const fetchNidsStats = async () => {
      try {
        const threats = await ThreatService.getHistory();
        if (threats && threats.length > 0) {
          const high = threats.filter((t: any) => t.riskLevel === 'High').length;
          const medium = threats.filter((t: any) => t.riskLevel === 'Medium').length;
          const low = threats.filter((t: any) => t.riskLevel === 'Low').length;
          
          // 统计攻击类型
          const typeCount: Record<string, number> = {};
          threats.forEach((t: any) => {
            typeCount[t.type] = (typeCount[t.type] || 0) + 1;
          });
          const types = Object.entries(typeCount)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([name, count]) => ({ name, count }));
          
          setNidsStats({ high, medium, low, total: threats.length, types });
        }
      } catch (e) {
        console.error("Failed to fetch NIDS stats", e);
      }
    };
    fetchNidsStats();
    const interval = setInterval(fetchNidsStats, 10000); // 每10秒刷新
    return () => clearInterval(interval);
  }, []);

  const MAX_DATA_POINTS = 30;

  useEffect(() => {
    if (!hostId) return;
    setData([]);

    const fetchHostData = async () => {
      const startTime = Date.now();
      try {
        const actualHostId = hostId === 'localhost' ? '192.168.31.254' : hostId;
        const serverData = await MonitorService.getHostStatus(actualHostId);
        const endTime = Date.now();
        setLatency(endTime - startTime);
        
        if (serverData) {
          setConnectionStatus('connected');
          const now = new Date().toLocaleTimeString('zh-CN');
          
          // 生成真实日志
          setLogs(prev => {
            const newLogs = [...prev];
            if (serverData.cpuUsage > 80) {
              newLogs.push({time: now, type: '告警', msg: `CPU负载过高: ${serverData.cpuUsage.toFixed(1)}%`});
            }
            if (serverData.memoryUsage > 85) {
              newLogs.push({time: now, type: '告警', msg: `内存使用过高: ${serverData.memoryUsage.toFixed(1)}%`});
            }
            if (serverData.diskUsage > 90) {
              newLogs.push({time: now, type: '警告', msg: `磁盘空间不足: ${serverData.diskUsage.toFixed(1)}%`});
            }
            newLogs.push({time: now, type: '信息', msg: `数据采集成功 - CPU:${serverData.cpuUsage.toFixed(1)}% 内存:${serverData.memoryUsage.toFixed(1)}%`});
            // 保留最后20条
            return newLogs.slice(-20);
          });
          
          setData(prev => {
            const newPoint = {
              time: prev.length > 0 ? prev[prev.length - 1].time + 1 : 0,
              cpu: serverData.cpuUsage || 0,
              memory: serverData.memoryUsage || 0,
              net: serverData.networkConn || 0,
              diskUsage: serverData.diskUsage || 0,
              diskInfo: serverData.diskInfo || '0 GB / 0 GB',
              fileStatus: serverData.fileStatus ? JSON.parse(serverData.fileStatus) : [],
              timestamp: serverData.monitorTime,
              // 新增字段：真实硬件信息
              cpuModel: serverData.cpuModel || 'Unknown CPU',
              cpuCores: serverData.cpuCores || 0,
              cpuFreq: serverData.cpuFreq || 0,
              memoryInfo: serverData.memoryInfo || 'Unknown Memory',
              memoryTotalGb: serverData.memoryTotalGb || 0,
              memoryUsedGb: serverData.memoryUsedGb || 0,
              diskTotalGb: serverData.diskTotalGb || 0,
              diskUsedGb: serverData.diskUsedGb || 0,
              diskFreeGb: serverData.diskFreeGb || 0,
              diskPartitions: serverData.diskPartitions ? JSON.parse(serverData.diskPartitions) : []
            };
            
            const newData = [...prev, newPoint];
            if (newData.length > MAX_DATA_POINTS) {
              return newData.slice(newData.length - MAX_DATA_POINTS);
            }
            return newData;
          });
        } else {
            setConnectionStatus('disconnected');
            setLogs(prev => [...prev, {time: new Date().toLocaleTimeString('zh-CN'), type: '错误', msg: '无法获取主机数据'}].slice(-20));
        }
      } catch (err: any) {
        console.error("Failed to fetch host data:", err);
        setConnectionStatus('disconnected');
      }
    };

    fetchHostData();
    const interval = setInterval(fetchHostData, 3000);
    return () => clearInterval(interval);
  }, [hostId]);

  const latest = data.length > 0 ? data[data.length - 1] : { 
      cpu: 0, 
      memory: 0, 
      net: 0,
      diskUsage: 0,
      diskInfo: '0 GB / 0 GB',
      fileStatus: [],
      cpuModel: 'Unknown CPU',
      cpuCores: 0,
      cpuFreq: 0,
      memoryInfo: 'Unknown Memory',
      memoryTotalGb: 0,
      memoryUsedGb: 0,
      diskTotalGb: 0,
      diskUsedGb: 0,
      diskFreeGb: 0,
      diskPartitions: []
  };

  const StatusBadge = () => {
    if (connectionStatus === 'disconnected') {
      return (
        <div className="flex items-center gap-2 px-4 py-2 bg-red-500/20 border border-red-500/50 rounded-lg text-red-400 text-sm font-bold animate-pulse font-mono">
           <AlertOctagon size={16} /> OFFLINE
        </div>
      );
    } else if (connectionStatus === 'unstable') {
      return (
        <div className="flex items-center gap-2 px-4 py-2 bg-yellow-500/20 border border-yellow-500/50 rounded-lg text-yellow-400 text-sm font-bold font-mono">
           <Wifi size={16} /> LATENCY: {latency}ms
        </div>
      );
    }
    return (
      <div className="flex items-center gap-2 px-4 py-2 bg-cyan-500/10 border border-cyan-500/40 rounded-lg text-cyan-400 text-sm font-bold font-mono shadow-lg shadow-cyan-500/20">
         <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shadow-lg shadow-cyan-400"></div>
         ONLINE ({latency}ms)
      </div>
    );
  };

  return (
    <div className="space-y-8 animate-fade-in">
      <PageHeader title="主机安全监控" subtitle="实时系统性能监测" showLive liveText="实时监控中">
        <StatusBadge />
        <div className="flex items-center gap-3">
          <span className="text-slate-400 text-sm hidden md:inline">监控目标:</span>
          <select 
            value={hostId}
            onChange={(e) => setHostId(e.target.value)}
            className="bg-cyber-900 border border-cyber-700 rounded-lg px-4 py-2 text-white outline-none focus:border-cyber-accent transition-all"
          >
            {hosts.length > 0 ? (
              hosts.map((host: any) => (
                <option key={host.id} value={host.hostIp}>
                  {host.hostIp}
                </option>
              ))
            ) : (
              <option value="" disabled>暂无目标</option>
            )}
          </select>
        </div>
      </PageHeader>

      {/* 主要数据卡片 */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* CPU Card */}
        <div className={`relative rounded-2xl p-6 overflow-hidden group transition-all duration-500 ${connectionStatus === 'disconnected' ? 'opacity-50 grayscale' : ''}`}
             style={{
               background: 'linear-gradient(145deg, rgba(0,20,40,0.95) 0%, rgba(0,40,80,0.9) 100%)',
               boxShadow: '0 0 40px rgba(0,255,255,0.15), inset 0 1px 0 rgba(0,255,255,0.2)'
             }}>
           {/* 霓虹边框 */}
           <div className="absolute inset-0 rounded-2xl border-2 border-cyan-500/40"></div>
           {/* 扫描线 */}
           <div className="absolute inset-0 overflow-hidden opacity-40 rounded-2xl">
             <div className="absolute w-full h-0.5 bg-gradient-to-r from-transparent via-cyan-400 to-transparent animate-scan"></div>
           </div>
           {/* 角落装饰 */}
           <div className="absolute top-0 left-0 w-6 h-6 border-t-2 border-l-2 border-cyan-400 rounded-tl-lg"></div>
           <div className="absolute top-0 right-0 w-6 h-6 border-t-2 border-r-2 border-cyan-400 rounded-tr-lg"></div>
           <div className="absolute bottom-0 left-0 w-6 h-6 border-b-2 border-l-2 border-cyan-400 rounded-bl-lg"></div>
           <div className="absolute bottom-0 right-0 w-6 h-6 border-b-2 border-r-2 border-cyan-400 rounded-br-lg"></div>
           
           <div className="relative z-10">
             <div className="flex justify-between items-start mb-2">
               <p className="text-cyan-400 text-lg font-bold flex items-center gap-2">
                 <Cpu size={24} className="text-cyan-300" /> CPU 负载
               </p>
               <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${latest.cpu > 80 ? 'bg-gradient-to-br from-red-500 to-orange-600' : 'bg-gradient-to-br from-cyan-500 to-blue-600'} shadow-xl`}>
                 <Cpu size={24} className="text-white" />
               </div>
             </div>
             <p className="text-cyan-400/60 text-sm mb-3">{latest.cpuModel}</p>
             <h3 className="text-6xl font-mono text-white font-black text-center py-2" style={{textShadow: '0 0 40px rgba(0,255,255,0.6)'}}>
               {latest.cpu.toFixed(1)}<span className="text-3xl text-cyan-400">%</span>
             </h3>
             <p className="text-center text-cyan-400/50 text-sm mt-1">{latest.cpuCores}核心 @ {latest.cpuFreq}GHz</p>
           </div>
           <div className="h-24 mt-6 -mx-2 relative z-10">
             <ResponsiveContainer width="100%" height="100%">
               <AreaChart data={data}>
                 <defs>
                   <linearGradient id="cpuGrad" x1="0" y1="0" x2="0" y2="1">
                     <stop offset="0%" stopColor="#00ffff" stopOpacity={0.5}/>
                     <stop offset="100%" stopColor="#00ffff" stopOpacity={0}/>
                   </linearGradient>
                 </defs>
                 <Area type="monotone" dataKey="cpu" stroke="#00ffff" strokeWidth={3} fill="url(#cpuGrad)" />
               </AreaChart>
             </ResponsiveContainer>
           </div>
        </div>

        {/* Memory Card */}
        <div className={`relative rounded-2xl p-6 overflow-hidden group transition-all duration-500 ${connectionStatus === 'disconnected' ? 'opacity-50 grayscale' : ''}`}
             style={{
               background: 'linear-gradient(145deg, rgba(20,0,40,0.95) 0%, rgba(60,0,80,0.9) 100%)',
               boxShadow: '0 0 40px rgba(255,0,255,0.15), inset 0 1px 0 rgba(255,0,255,0.2)'
             }}>
           <div className="absolute inset-0 rounded-2xl border-2 border-purple-500/40"></div>
           <div className="absolute inset-0 overflow-hidden opacity-40 rounded-2xl">
             <div className="absolute w-full h-0.5 bg-gradient-to-r from-transparent via-purple-400 to-transparent animate-scan" style={{animationDelay: '0.7s'}}></div>
           </div>
           <div className="absolute top-0 left-0 w-6 h-6 border-t-2 border-l-2 border-purple-400 rounded-tl-lg"></div>
           <div className="absolute top-0 right-0 w-6 h-6 border-t-2 border-r-2 border-purple-400 rounded-tr-lg"></div>
           <div className="absolute bottom-0 left-0 w-6 h-6 border-b-2 border-l-2 border-purple-400 rounded-bl-lg"></div>
           <div className="absolute bottom-0 right-0 w-6 h-6 border-b-2 border-r-2 border-purple-400 rounded-br-lg"></div>
           
           <div className="relative z-10">
             <div className="flex justify-between items-start mb-2">
               <p className="text-purple-400 text-lg font-bold flex items-center gap-2">
                 <Database size={24} className="text-purple-300" /> 内存使用
               </p>
               <div className="w-12 h-12 rounded-xl flex items-center justify-center bg-gradient-to-br from-purple-500 to-pink-600 shadow-xl">
                 <Database size={24} className="text-white" />
               </div>
             </div>
             <p className="text-purple-400/60 text-sm mb-3">{latest.memoryInfo}</p>
             <h3 className="text-6xl font-mono text-white font-black text-center py-2" style={{textShadow: '0 0 40px rgba(255,0,255,0.6)'}}>
               {latest.memory.toFixed(1)}<span className="text-3xl text-purple-400">%</span>
             </h3>
             <p className="text-center text-purple-400/50 text-sm mt-1">已用: {latest.memoryUsedGb}GB / {latest.memoryTotalGb}GB</p>
           </div>
           <div className="h-24 mt-6 -mx-2 relative z-10">
             <ResponsiveContainer width="100%" height="100%">
               <AreaChart data={data}>
                 <defs>
                   <linearGradient id="memGrad" x1="0" y1="0" x2="0" y2="1">
                     <stop offset="0%" stopColor="#ff00ff" stopOpacity={0.5}/>
                     <stop offset="100%" stopColor="#ff00ff" stopOpacity={0}/>
                   </linearGradient>
                 </defs>
                 <Area type="monotone" dataKey="memory" stroke="#ff00ff" strokeWidth={3} fill="url(#memGrad)" />
               </AreaChart>
             </ResponsiveContainer>
           </div>
        </div>
      </div>

      {/* 磁盘监控 - 重构版 */}
      <div className={`relative rounded-2xl p-6 overflow-hidden ${connectionStatus === 'disconnected' ? 'opacity-50 grayscale' : ''}`}
           style={{
             background: 'linear-gradient(145deg, rgba(5,15,35,0.98) 0%, rgba(10,25,50,0.95) 100%)',
             boxShadow: '0 0 40px rgba(0,150,255,0.1), inset 0 1px 0 rgba(100,200,255,0.1)'
           }}>
         {/* 装饰边框 */}
         <div className="absolute inset-0 rounded-2xl border border-cyan-500/20"></div>
         <div className="absolute top-0 left-0 w-8 h-8 border-t-2 border-l-2 border-cyan-400/50 rounded-tl-xl"></div>
         <div className="absolute top-0 right-0 w-8 h-8 border-t-2 border-r-2 border-cyan-400/50 rounded-tr-xl"></div>
         <div className="absolute bottom-0 left-0 w-8 h-8 border-b-2 border-l-2 border-cyan-400/50 rounded-bl-xl"></div>
         <div className="absolute bottom-0 right-0 w-8 h-8 border-b-2 border-r-2 border-cyan-400/50 rounded-br-xl"></div>
         
         {/* 扫描线动画 */}
         <div className="absolute inset-0 overflow-hidden opacity-30 rounded-2xl">
           <div className="absolute w-full h-0.5 bg-gradient-to-r from-transparent via-cyan-400 to-transparent animate-scan"></div>
         </div>
         
         {/* 头部 */}
         <div className="flex justify-between items-center mb-6 relative z-10">
            <h3 className="text-cyan-400 text-xl font-black flex items-center gap-3">
               <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/30 to-blue-600/30 flex items-center justify-center border border-cyan-500/30">
                 <HardDrive size={22} className="text-cyan-300" />
               </div>
               存储空间监控
            </h3>
            <div className="flex items-center gap-4">
               <div className="text-right">
                 <p className="text-3xl font-mono font-black text-white" style={{textShadow: '0 0 20px rgba(0,255,255,0.4)'}}>
                   {latest.diskUsedGb}<span className="text-lg text-cyan-400">GB</span>
                 </p>
                 <p className="text-xs text-cyan-400/60">已用 / {latest.diskTotalGb}GB 总计</p>
               </div>
               <div className="w-16 h-16 relative">
                 <svg className="w-full h-full -rotate-90">
                   <circle cx="32" cy="32" r="28" stroke="rgba(0,255,255,0.1)" strokeWidth="6" fill="none"/>
                   <circle cx="32" cy="32" r="28" stroke="url(#diskGradient)" strokeWidth="6" fill="none"
                     strokeDasharray={`${(latest.diskUsage || 0) * 1.76} 176`}
                     strokeLinecap="round"/>
                   <defs>
                     <linearGradient id="diskGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                       <stop offset="0%" stopColor="#06b6d4"/>
                       <stop offset="100%" stopColor="#3b82f6"/>
                     </linearGradient>
                   </defs>
                 </svg>
                 <span className="absolute inset-0 flex items-center justify-center text-sm font-bold text-cyan-300">
                   {(latest.diskUsage || 0).toFixed(0)}%
                 </span>
               </div>
            </div>
         </div>
         
         {/* 分区卡片网格 */}
         <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 relative z-10">
            {(latest.diskPartitions && latest.diskPartitions.length > 0) ? (
               latest.diskPartitions.map((partition: any, idx: number) => {
                 const isWarning = partition.percent > 70;
                 const isDanger = partition.percent > 90;
                 const colorClass = isDanger ? 'red' : isWarning ? 'amber' : 'cyan';
                 
                 return (
                   <div key={idx} 
                        className={`relative rounded-xl p-4 overflow-hidden group hover:scale-[1.02] transition-all duration-300 cursor-pointer`}
                        style={{
                          background: isDanger 
                            ? 'linear-gradient(145deg, rgba(127,29,29,0.3) 0%, rgba(153,27,27,0.2) 100%)'
                            : isWarning
                            ? 'linear-gradient(145deg, rgba(120,53,15,0.3) 0%, rgba(146,64,14,0.2) 100%)'
                            : 'linear-gradient(145deg, rgba(0,40,80,0.4) 0%, rgba(0,60,100,0.3) 100%)',
                          boxShadow: isDanger 
                            ? '0 0 20px rgba(239,68,68,0.15)'
                            : isWarning
                            ? '0 0 20px rgba(245,158,11,0.15)'
                            : '0 0 20px rgba(6,182,212,0.1)'
                        }}>
                      {/* 边框 */}
                      <div className={`absolute inset-0 rounded-xl border ${isDanger ? 'border-red-500/30' : isWarning ? 'border-amber-500/30' : 'border-cyan-500/20'}`}></div>
                      
                      {/* 悬停光效 */}
                      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-xl"
                           style={{background: `radial-gradient(circle at 50% 50%, ${isDanger ? 'rgba(239,68,68,0.1)' : isWarning ? 'rgba(245,158,11,0.1)' : 'rgba(6,182,212,0.1)'} 0%, transparent 70%)`}}></div>
                      
                      <div className="relative z-10">
                        {/* 磁盘图标和名称 */}
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-3">
                            <div className={`w-12 h-12 rounded-xl flex items-center justify-center text-lg font-black
                              ${isDanger ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 
                                isWarning ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 
                                'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'}`}>
                              {partition.name}:
                            </div>
                            <div>
                              <p className={`font-bold ${isDanger ? 'text-red-300' : isWarning ? 'text-amber-300' : 'text-cyan-300'}`}>
                                本地磁盘
                              </p>
                              <p className="text-xs text-slate-500">{partition.fstype}</p>
                            </div>
                          </div>
                          <div className={`text-2xl font-mono font-black ${isDanger ? 'text-red-400' : isWarning ? 'text-amber-400' : 'text-cyan-400'}`}
                               style={{textShadow: `0 0 15px ${isDanger ? 'rgba(239,68,68,0.5)' : isWarning ? 'rgba(245,158,11,0.5)' : 'rgba(6,182,212,0.5)'}`}}>
                            {partition.percent}%
                          </div>
                        </div>
                        
                        {/* 进度条 */}
                        <div className="w-full h-3 bg-black/40 rounded-full overflow-hidden mb-3 border border-white/5">
                          <div className={`h-full rounded-full transition-all duration-700 relative overflow-hidden`}
                               style={{ 
                                 width: `${partition.percent}%`,
                                 background: isDanger 
                                   ? 'linear-gradient(90deg, #dc2626 0%, #ef4444 50%, #f87171 100%)'
                                   : isWarning
                                   ? 'linear-gradient(90deg, #d97706 0%, #f59e0b 50%, #fbbf24 100%)'
                                   : 'linear-gradient(90deg, #0891b2 0%, #06b6d4 50%, #22d3ee 100%)'
                               }}>
                            {/* 光泽效果 */}
                            <div className="absolute inset-0 bg-gradient-to-b from-white/30 to-transparent h-1/2"></div>
                          </div>
                        </div>
                        
                        {/* 详细数据 */}
                        <div className="grid grid-cols-3 gap-2 text-center">
                          <div className="bg-black/30 rounded-lg py-2 px-1">
                            <p className={`text-sm font-mono font-bold ${isDanger ? 'text-red-300' : isWarning ? 'text-amber-300' : 'text-cyan-300'}`}>
                              {partition.used}GB
                            </p>
                            <p className="text-xs text-slate-500">已用</p>
                          </div>
                          <div className="bg-black/30 rounded-lg py-2 px-1">
                            <p className="text-sm font-mono font-bold text-emerald-300">{partition.free}GB</p>
                            <p className="text-xs text-slate-500">可用</p>
                          </div>
                          <div className="bg-black/30 rounded-lg py-2 px-1">
                            <p className="text-sm font-mono font-bold text-slate-300">{partition.total}GB</p>
                            <p className="text-xs text-slate-500">总计</p>
                          </div>
                        </div>
                      </div>
                   </div>
                 );
               })
            ) : (
               <div className="col-span-3 text-center py-12 text-slate-500">
                  <HardDrive size={48} className="mx-auto mb-3 opacity-30" />
                  <p className="text-lg">等待磁盘数据...</p>
               </div>
            )}
         </div>
      </div>

      {/* 网络图表区域 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
         {/* 网络连接图表 */}
         <div className={`lg:col-span-2 relative rounded-2xl p-6 flex flex-col ${connectionStatus === 'disconnected' ? 'opacity-50' : ''}`}
              style={{
                background: 'linear-gradient(145deg, rgba(0,10,20,0.95) 0%, rgba(0,30,50,0.9) 100%)',
                boxShadow: '0 0 30px rgba(0,200,255,0.1)'
              }}>
            <div className="absolute inset-0 rounded-2xl border-2 border-cyan-500/30"></div>
            <div className="absolute top-0 left-0 w-6 h-6 border-t-2 border-l-2 border-cyan-400 rounded-tl-lg"></div>
            <div className="absolute top-0 right-0 w-6 h-6 border-t-2 border-r-2 border-cyan-400 rounded-tr-lg"></div>
            <div className="absolute bottom-0 left-0 w-6 h-6 border-b-2 border-l-2 border-cyan-400 rounded-bl-lg"></div>
            <div className="absolute bottom-0 right-0 w-6 h-6 border-b-2 border-r-2 border-cyan-400 rounded-br-lg"></div>
            
            {/* 头部 */}
            <div className="flex justify-between items-center mb-4 shrink-0 relative z-10">
              <h3 className="text-xl font-black text-cyan-400 flex items-center gap-3">
                <Network size={26} className="text-cyan-300"/> 网络连接监控
              </h3>
              <div className="flex items-center gap-4">
                <div className="text-right">
                  <span className="text-4xl font-mono font-black text-cyan-300" style={{textShadow: '0 0 20px rgba(0,255,255,0.5)'}}>{latest.net}</span>
                  <p className="text-cyan-400/60 text-xs">当前连接数</p>
                </div>
              </div>
            </div>
            
            {/* 统计卡片 */}
            <div className="grid grid-cols-4 gap-3 mb-4 relative z-10">
              <div className="bg-black/40 rounded-xl p-3 border border-cyan-500/20 hover:border-cyan-500/50 transition-all cursor-pointer group">
                <p className="text-cyan-400/60 text-xs mb-1">最高峰值</p>
                <p className="text-xl font-mono font-bold text-cyan-300 group-hover:text-white transition-colors">
                  {data.length > 0 ? Math.max(...data.map(d => d.net)) : 0}
                </p>
              </div>
              <div className="bg-black/40 rounded-xl p-3 border border-emerald-500/20 hover:border-emerald-500/50 transition-all cursor-pointer group">
                <p className="text-emerald-400/60 text-xs mb-1">最低谷值</p>
                <p className="text-xl font-mono font-bold text-emerald-300 group-hover:text-white transition-colors">
                  {data.length > 0 ? Math.min(...data.map(d => d.net)) : 0}
                </p>
              </div>
              <div className="bg-black/40 rounded-xl p-3 border border-purple-500/20 hover:border-purple-500/50 transition-all cursor-pointer group">
                <p className="text-purple-400/60 text-xs mb-1">平均值</p>
                <p className="text-xl font-mono font-bold text-purple-300 group-hover:text-white transition-colors">
                  {data.length > 0 ? Math.round(data.reduce((a, b) => a + b.net, 0) / data.length) : 0}
                </p>
              </div>
              <div className="bg-black/40 rounded-xl p-3 border border-amber-500/20 hover:border-amber-500/50 transition-all cursor-pointer group">
                <p className="text-amber-400/60 text-xs mb-1">采样点数</p>
                <p className="text-xl font-mono font-bold text-amber-300 group-hover:text-white transition-colors">
                  {data.length}
                </p>
              </div>
            </div>
            
            {/* 图表 */}
            <div className="flex-1 min-h-[180px] relative z-10">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data}>
                  <defs>
                    <linearGradient id="netGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#00ffff" stopOpacity={0.4}/>
                      <stop offset="100%" stopColor="#00ffff" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#0c4a6e" strokeDasharray="3 3" vertical={false} opacity={0.5} />
                  <XAxis dataKey="time" hide />
                  <YAxis stroke="#0ea5e9" fontSize={14} tickLine={false} axisLine={false} />
                  <Tooltip 
                     contentStyle={{ backgroundColor: 'rgba(0,20,40,0.95)', borderColor: '#0ea5e9', borderRadius: '12px' }}
                     itemStyle={{ fontWeight: 'bold', color: '#00ffff' }}
                     labelStyle={{ display: 'none' }}
                  />
                  <Area type="monotone" dataKey="net" stroke="#00ffff" strokeWidth={3} fill="url(#netGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
         </div>

         {/* 终端日志 + 端口监控 */}
         <div className="flex flex-col gap-4">
            {/* 活跃端口监控 */}
            <div className={`relative rounded-2xl p-4 overflow-hidden ${connectionStatus === 'disconnected' ? 'opacity-50' : ''}`}
                 style={{
                   background: 'linear-gradient(145deg, rgba(20,10,0,0.95) 0%, rgba(50,30,0,0.9) 100%)',
                   boxShadow: '0 0 20px rgba(255,150,0,0.1)'
                 }}>
               <div className="absolute inset-0 rounded-2xl border-2 border-amber-500/30"></div>
               <h4 className="text-amber-400 text-base font-bold flex items-center gap-2 mb-3 relative z-10">
                 <Wifi size={18} className="text-amber-300" /> 活跃端口
               </h4>
               <div className="flex flex-wrap gap-2 relative z-10">
                 {[80, 443, 22, 3306, 8080, 6379].map((port) => (
                   <div key={port} className="px-3 py-2 bg-black/40 rounded-lg border border-amber-500/30 hover:border-amber-400 hover:bg-amber-500/10 transition-all cursor-pointer group">
                     <span className="font-mono text-amber-300 group-hover:text-white text-sm font-bold">{port}</span>
                   </div>
                 ))}
               </div>
            </div>
            
            {/* 终端日志 */}
            <div className="relative rounded-2xl overflow-hidden flex flex-col flex-1"
                 style={{
                   background: 'linear-gradient(180deg, rgba(0,0,0,0.98) 0%, rgba(0,20,10,0.95) 100%)',
                   boxShadow: '0 0 30px rgba(0,255,0,0.05)'
                 }}>
               <div className="absolute inset-0 rounded-2xl border-2 border-green-500/30"></div>
               <div className="px-4 py-3 bg-green-900/30 border-b border-green-500/30 flex items-center justify-between shrink-0 relative z-10">
                  <span className="text-sm text-green-400 font-black flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                    系统日志
                  </span>
                  <span className="text-xs text-green-500/60 font-mono">{logs.length} 条</span>
               </div>
               <div className="flex-1 p-3 font-mono text-xs space-y-1.5 overflow-auto relative z-10">
                  {logs.length === 0 ? (
                    <p className="text-green-400/50 text-center py-4">等待数据...</p>
                  ) : (
                    logs.slice().reverse().slice(0, 8).map((log, idx) => (
                      <p key={idx} className={`${
                        log.type === '告警' ? 'text-red-400' : 
                        log.type === '警告' ? 'text-yellow-400' : 
                        log.type === '错误' ? 'text-red-500' : 'text-green-400/80'
                      } hover:bg-green-500/10 px-2 py-1 rounded cursor-pointer transition-colors`}>
                        <span className="text-green-600">[{log.time}]</span> {log.msg.substring(0, 30)}...
                      </p>
                    ))
                  )}
               </div>
            </div>
         </div>
      </div>
    </div>
  );
};

export default HostMonitoring;
