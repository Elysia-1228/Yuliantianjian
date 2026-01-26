import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  ShieldCheck, Activity, Map, FileText, AlertTriangle, Globe, Clock, ArrowRight,
  Database, HardDrive, TrendingUp, Eye, Zap, Target, Shield, Lock
} from 'lucide-react';
import { AreaChart, Area, ResponsiveContainer } from 'recharts';
import { DashBoardService, AnalysisService, ThreatService, OrgService, ReportService, MonitorService } from '../services/connector';
import PageHeader from '../components/PageHeader';

const Home: React.FC = () => {
  const navigate = useNavigate();
  const [currentTime, setCurrentTime] = useState(new Date());
  const [safetyScore, setSafetyScore] = useState(0);
  const [stats, setStats] = useState({ todayAttacks: 0, activeThreats: 0, protectedAssets: 0 });
  const [trafficData, setTrafficData] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  // 真实数据状态
  const [reportCount, setReportCount] = useState(0);
  const [hostCount, setHostCount] = useState(0);
  const [orgCount, setOrgCount] = useState(0);
  const [traceCount, setTraceCount] = useState(0);
  const [threatTypes, setThreatTypes] = useState<{name: string, percent: number, color: string}[]>([]);
  const [trendData, setTrendData] = useState<any[]>([]);
  
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const dashboard = await DashBoardService.getSummary();
        if (dashboard) {
          setSafetyScore(dashboard.securityScore || 0);
          setStats({
            todayAttacks: dashboard.totalAttacksToday || 0,
            activeThreats: dashboard.activeThreats || 0,
            protectedAssets: dashboard.protectedAssets || 0
          });
        }
        const traffic = await AnalysisService.getTraffic(1, 20);
        if (traffic && traffic.length > 0) {
          setTrafficData(traffic.map((t: any) => ({ v: t.attackCount || 0 })).reverse());
        } else {
          setTrafficData([{v:0}, {v:0}, {v:0}, {v:0}, {v:0}]);
        }
        
        // 获取真实的威胁告警作为审计日志
        const threats = await ThreatService.getHistory();
        if (threats && threats.length > 0) {
          const logs = threats.slice(0, 12).map((t: any) => {
            const time = t.timestamp ? t.timestamp.split(' ')[1]?.substring(0, 8) || t.timestamp : '00:00:00';
            const isHigh = t.riskLevel === 'High';
            const isMedium = t.riskLevel === 'Medium';
            return {
              time,
              msg: `${t.type || '威胁事件'} | ${t.sourceIp || 'Unknown'} → ${t.targetIp || 'Unknown'}`,
              type: isHigh ? 'danger' : isMedium ? 'warning' : 'info',
              icon: isHigh ? '🔴' : isMedium ? '⚠' : 'ℹ️',
              id: t.id
            };
          });
          setAuditLogs(logs);
          
          // 计算威胁类型分布（真实数据）
          const typeCount: Record<string, number> = {};
          threats.forEach((t: any) => {
            const type = t.type || 'Unknown';
            typeCount[type] = (typeCount[type] || 0) + 1;
          });
          const total = threats.length;
          const colors = ['from-red-500 to-orange-500', 'from-yellow-500 to-amber-500', 'from-purple-500 to-pink-500', 'from-cyan-500 to-blue-500', 'from-emerald-500 to-teal-500'];
          const types = Object.entries(typeCount)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 4)
            .map(([name, count], i) => ({
              name: name.length > 8 ? name.substring(0, 8) + '...' : name,
              percent: Math.round((count / total) * 100),
              color: colors[i % colors.length]
            }));
          setThreatTypes(types);
          setTraceCount(threats.length);
        }
        
        // 获取报告数量
        try {
          const reports = await ReportService.getHistory();
          setReportCount(reports?.length || 0);
        } catch { setReportCount(0); }
        
        // 获取主机数量
        try {
          const hosts = await MonitorService.getMonitorList(1, 100);
          setHostCount(hosts?.length || 0);
        } catch { setHostCount(0); }
        
        // 获取组织数量
        try {
          const orgs = await OrgService.getAll();
          setOrgCount(orgs?.length || 0);
        } catch { setOrgCount(0); }
        
        // 获取趋势数据
        try {
          const trend = await AnalysisService.getTrend('24h');
          if (trend && trend.length > 0) {
            setTrendData(trend.map((t: any) => ({ v: t.count || 0 })));
          }
        } catch { }
      } catch (err) {
        console.error("Failed to fetch dashboard data", err);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  const quickActions = [
    { title: '威胁态势分析', desc: '查看全网攻击流量趋势与类型分布', path: '/analysis', icon: Activity, color: 'text-blue-400', bg: 'bg-blue-500/10' },
    { title: '攻击溯源图谱', desc: '基于地理位置追踪高危攻击源头', path: '/tracing', icon: Map, color: 'text-purple-400', bg: 'bg-purple-500/10' },
    { title: 'NIDS 网络入侵检测', desc: '网络流量实时威胁分析', path: '/alerts', icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-500/10' }
  ];

  // 默认日志（当API无数据时显示）
  const defaultLogs = [
    { time: new Date().toLocaleTimeString(), msg: '系统启动完成，等待数据...', type: 'info', icon: '✓' },
  ];
  const logs = auditLogs.length > 0 ? auditLogs : defaultLogs;

  return (
    <div className="space-y-6 animate-fade-in pb-10">
      <PageHeader title="安全态势总览" subtitle="欢迎回来，管理员 | 全网节点运行正常" showLive liveText="实时监控中">
        <div className="flex items-center gap-4 bg-cyber-900/50 p-3 rounded-xl border border-cyber-800 backdrop-blur-sm">
          <Clock size={20} className="text-cyber-accent" />
          <span className="font-mono text-xl text-white font-bold">{currentTime.toLocaleTimeString()}</span>
          <span className="text-sm text-slate-500 border-l border-slate-700 pl-4">{currentTime.toLocaleDateString()}</span>
        </div>
      </PageHeader>

      {/* 核心指标卡片 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        <div onClick={() => navigate('/hids')} className="relative bg-gradient-to-br from-cyber-900/80 to-cyber-950/80 p-6 rounded-2xl border border-emerald-500/20 overflow-hidden group hover:border-emerald-500/40 cursor-pointer transition-all">
          <div className="absolute -right-8 -top-8 w-32 h-32 bg-emerald-500/10 rounded-full blur-2xl"></div>
          <div className="relative z-10 flex items-center gap-4">
            <div className="relative w-20 h-20">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="40" fill="none" stroke="#1e293b" strokeWidth="8" />
                <circle cx="50" cy="50" r="40" fill="none" stroke="url(#scoreGradient)" strokeWidth="8" strokeLinecap="round" strokeDasharray={`${safetyScore * 2.51} 251`} />
                <defs><linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor="#10b981" /><stop offset="100%" stopColor="#06b6d4" /></linearGradient></defs>
              </svg>
              <div className="absolute inset-0 flex items-center justify-center"><span className="text-3xl font-bold text-emerald-400">{safetyScore}</span></div>
            </div>
            <div>
              <h3 className="text-slate-400 text-sm font-medium uppercase">安全评分</h3>
              <p className="text-emerald-400 text-base font-medium mt-1">状态良好</p>
              <div className="flex items-center gap-1 mt-2"><ShieldCheck size={16} className="text-emerald-500" /><span className="text-sm text-slate-500">防护已启用</span></div>
            </div>
          </div>
        </div>

        <div onClick={() => navigate('/analysis')} className="relative bg-gradient-to-br from-cyber-900/80 to-cyber-950/80 p-6 rounded-2xl border border-cyan-500/20 overflow-hidden group hover:border-cyan-500/40 cursor-pointer transition-all">
          <div className="absolute -right-8 -bottom-8 w-32 h-32 bg-cyan-500/10 rounded-full blur-2xl"></div>
          <div className="relative z-10">
            <div className="flex items-center justify-between">
              <h3 className="text-slate-400 text-sm font-medium uppercase">今日拦截</h3>
              <div className="w-20 h-10">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trafficData}><Area type="monotone" dataKey="v" stroke="#06b6d4" fill="url(#chartGradient)" strokeWidth={2} /><defs><linearGradient id="chartGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#06b6d4" stopOpacity={0.4} /><stop offset="100%" stopColor="#06b6d4" stopOpacity={0} /></linearGradient></defs></AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
            <p className="text-5xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent mt-2">{stats.todayAttacks}</p>
            <div className="flex items-center gap-2 mt-2">
              <span className="flex h-2 w-2 relative"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span><span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span></span>
              <span className="text-sm text-cyan-400">实时防御中</span>
            </div>
          </div>
        </div>

        <div className="relative bg-gradient-to-br from-cyber-900/80 to-cyber-950/80 p-6 rounded-2xl border border-purple-500/20 overflow-hidden group hover:border-purple-500/40 transition-all">
          <div className="absolute -left-8 -bottom-8 w-32 h-32 bg-purple-500/10 rounded-full blur-2xl"></div>
          <div className="relative z-10">
            <div className="flex items-center justify-between">
              <h3 className="text-slate-400 text-sm font-medium uppercase">受保护资产</h3>
              <div className="p-2.5 bg-purple-500/10 rounded-xl text-purple-400"><Globe size={20} /></div>
            </div>
            <p className="text-5xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent mt-2">{stats.protectedAssets}</p>
            <p className="text-sm text-slate-500 mt-2 flex items-center gap-1">全网覆盖 <ArrowRight size={14} /></p>
          </div>
        </div>

        <div onClick={() => navigate('/alerts')} className="relative bg-gradient-to-br from-red-950/50 to-cyber-950/80 p-6 rounded-2xl border border-red-500/30 overflow-hidden group hover:border-red-500/60 cursor-pointer transition-all">
          <div className="absolute -right-8 -top-8 w-32 h-32 bg-red-500/10 rounded-full blur-2xl animate-pulse"></div>
          <div className="relative z-10">
            <div className="flex items-center justify-between">
              <h3 className="text-red-300/70 text-sm font-medium uppercase">活跃威胁</h3>
              <div className="p-2.5 bg-red-500/20 rounded-xl text-red-400 animate-pulse"><AlertTriangle size={20} /></div>
            </div>
            <p className="text-5xl font-bold text-red-400 mt-2">{stats.activeThreats}</p>
            <p className="text-sm text-red-400/70 mt-2 flex items-center gap-1">点击立即处理 <ArrowRight size={14} /></p>
          </div>
        </div>
      </div>

      {/* 存储与防护卡片 - 增强视觉效果 */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div onClick={() => navigate('/hids')} className="relative rounded-2xl p-6 overflow-hidden cursor-pointer group hover:scale-[1.02] transition-all" style={{background: 'linear-gradient(145deg, rgba(0,30,20,0.95) 0%, rgba(0,50,30,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-emerald-500/30 group-hover:border-emerald-500/60"></div>
          <div className="absolute -right-10 -top-10 w-32 h-32 bg-emerald-500/20 rounded-full blur-2xl group-hover:bg-emerald-500/30 transition-all"></div>
          <div className="absolute -left-5 -bottom-5 w-20 h-20 bg-cyan-500/15 rounded-full blur-xl"></div>
          <div className="absolute top-4 right-4 w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></div>
          <div className="relative z-10">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-emerald-400 text-xl font-bold flex items-center gap-2"><HardDrive size={24} className="drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]" /> 存储空间</h3>
              <ArrowRight size={20} className="text-emerald-400/50 group-hover:text-emerald-400 group-hover:translate-x-1 transition-all" />
            </div>
            <div className="flex items-center gap-6">
              <div className="text-center">
                <p className="text-5xl font-mono font-bold bg-gradient-to-r from-white via-emerald-200 to-cyan-300 bg-clip-text text-transparent">68<span className="text-2xl text-emerald-400">%</span></p>
                <p className="text-base text-slate-400 mt-1">总使用率</p>
              </div>
              <div className="flex-1">
                <div className="relative h-4 bg-black/50 rounded-full overflow-hidden mb-3 shadow-inner">
                  <div className="absolute inset-y-0 left-0 bg-gradient-to-r from-emerald-600 via-emerald-500 to-cyan-400 rounded-full shadow-[0_0_10px_rgba(16,185,129,0.5)]" style={{width: '68%'}}></div>
                </div>
                <div className="flex justify-between text-base text-slate-400"><span>已用 <span className="text-emerald-300 font-bold">1.7TB</span></span><span>共 <span className="text-cyan-300 font-bold">2.5TB</span></span></div>
              </div>
            </div>
            <div className="grid grid-cols-4 gap-3 mt-4 pt-4 border-t border-emerald-500/20">
              <div className="text-center p-2 rounded-xl bg-cyan-500/10">
                <p className="text-2xl font-bold text-cyan-400">{traceCount}</p>
                <p className="text-sm text-slate-400">威胁记录</p>
              </div>
              <div className="text-center p-2 rounded-xl bg-purple-500/10">
                <p className="text-2xl font-bold text-purple-400">{reportCount}</p>
                <p className="text-sm text-slate-400">分析报告</p>
              </div>
              <div className="text-center p-2 rounded-xl bg-amber-500/10">
                <p className="text-2xl font-bold text-amber-400">{stats.activeThreats}</p>
                <p className="text-sm text-slate-400">活跃威胁</p>
              </div>
              <div className="text-center p-2 rounded-xl bg-emerald-500/10">
                <p className="text-2xl font-bold text-emerald-400">{stats.protectedAssets}</p>
                <p className="text-sm text-slate-400">采集节点</p>
              </div>
            </div>
          </div>
        </div>

        <div onClick={() => navigate('/alerts')} className="relative rounded-2xl p-5 overflow-hidden cursor-pointer group hover:scale-[1.02] transition-all" style={{background: 'linear-gradient(145deg, rgba(30,10,0,0.95) 0%, rgba(50,20,0,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-amber-500/30 group-hover:border-amber-500/60"></div>
          <div className="absolute -right-10 -top-10 w-32 h-32 bg-amber-500/20 rounded-full blur-2xl group-hover:bg-amber-500/30 transition-all"></div>
          <div className="absolute -left-5 -bottom-5 w-20 h-20 bg-orange-500/15 rounded-full blur-xl"></div>
          <div className="absolute top-4 right-16 w-2 h-2 bg-amber-400 rounded-full animate-pulse"></div>
          <div className="relative z-10">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-amber-400 text-lg font-bold flex items-center gap-2"><Lock size={20} className="drop-shadow-[0_0_8px_rgba(245,158,11,0.5)]" /> 防护墙</h3>
              <div className="flex items-center gap-2">
                <span className="text-sm px-2.5 py-1 bg-emerald-500/20 text-emerald-400 rounded-full border border-emerald-500/30 shadow-[0_0_10px_rgba(16,185,129,0.2)]">已启用</span>
                <ArrowRight size={18} className="text-amber-400/50 group-hover:text-amber-400 group-hover:translate-x-1 transition-all" />
              </div>
            </div>
            <div className="flex gap-4">
              <div className="flex-1 space-y-1.5">
                <div className="flex items-center justify-between text-sm"><span className="text-slate-300">DDoS防护</span><span className="text-emerald-400 animate-pulse">●</span></div>
                <div className="flex items-center justify-between text-sm"><span className="text-slate-300">入侵检测</span><span className="text-emerald-400 animate-pulse">●</span></div>
                <div className="flex items-center justify-between text-sm"><span className="text-slate-300">恶意扫描</span><span className="text-emerald-400 animate-pulse">●</span></div>
                <div className="flex items-center justify-between text-sm"><span className="text-slate-300">SQL注入</span><span className="text-emerald-400 animate-pulse">●</span></div>
                <div className="flex items-center justify-between text-sm"><span className="text-slate-300">XSS拦截</span><span className="text-emerald-400 animate-pulse">●</span></div>
              </div>
              <div className="border-l border-amber-500/20 pl-4 flex flex-col justify-between">
                <div>
                  <p className="text-2xl font-bold text-red-400">{stats.todayAttacks}</p>
                  <p className="text-xs text-slate-500">今日拦截</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-cyan-400">{orgCount}</p>
                  <p className="text-xs text-slate-500">管理部门</p>
                </div>
              </div>
            </div>
            <div className="flex items-center justify-between mt-3 pt-3 border-t border-amber-500/20">
              <p className="text-xl font-bold bg-gradient-to-r from-amber-400 to-orange-400 bg-clip-text text-transparent">5/5 <span className="text-sm text-slate-400">防护开启</span></p>
              <span className="text-xs text-slate-500">实时监控中</span>
            </div>
          </div>
        </div>
      </div>

      {/* 功能导航 + 日志 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-5">
          <h2 className="text-xl font-bold text-white flex items-center gap-2"><Zap size={18} className="text-cyan-400"/> 快速访问</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {quickActions.map((action, idx) => (
              <div key={idx} onClick={() => navigate(action.path)} className="relative bg-gradient-to-br from-cyber-900/60 to-cyber-950/60 p-4 rounded-2xl border border-cyber-700/50 cursor-pointer transition-all hover:-translate-y-1 hover:shadow-xl hover:shadow-cyan-500/10 group overflow-hidden">
                <div className={`absolute -right-8 -top-8 w-24 h-24 ${action.bg} rounded-full blur-2xl opacity-0 group-hover:opacity-100 transition-opacity`}></div>
                <div className="relative z-10 flex items-center gap-4">
                  <div className={`p-3 rounded-xl ${action.bg} ${action.color} border border-current/20 shadow-lg`}><action.icon size={22} /></div>
                  <div className="flex-1 min-w-0">
                    <h3 className="text-base font-bold text-white">{action.title}</h3>
                    <p className="text-xs text-slate-500 mt-0.5 truncate">{action.desc}</p>
                  </div>
                  <ArrowRight size={16} className="text-slate-600 group-hover:text-white transition-all" />
                </div>
              </div>
            ))}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="relative overflow-hidden rounded-2xl group cursor-pointer hover:scale-[1.02] transition-all" onClick={() => navigate('/reports')}>
              <div className="absolute inset-0 bg-gradient-to-br from-cyan-600/30 to-blue-600/20"></div>
              <div className="absolute inset-0 rounded-2xl border border-cyan-500/30 group-hover:border-cyan-500/50"></div>
              <div className="relative z-10 p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="p-2.5 bg-cyan-500/20 rounded-xl"><FileText size={20} className="text-cyan-400" /></div>
                  <span className="text-2xl font-bold text-cyan-400">{reportCount}</span>
                </div>
                <h3 className="text-base font-bold text-white">AI 智能报告</h3>
                <p className="text-slate-400 text-sm mt-1">已生成报告</p>
                <div className="mt-3 pt-3 border-t border-cyan-500/20 flex justify-between text-xs">
                  <span className="text-slate-500">实时数据</span>
                  <span className="text-cyan-400">查看 →</span>
                </div>
              </div>
            </div>
            <div className="relative overflow-hidden rounded-2xl group cursor-pointer hover:scale-[1.02] transition-all" onClick={() => navigate('/hids')}>
              <div className="absolute inset-0 bg-gradient-to-br from-emerald-600/30 to-cyan-600/20"></div>
              <div className="absolute inset-0 rounded-2xl border border-emerald-500/30 group-hover:border-emerald-500/50"></div>
              <div className="relative z-10 p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="p-2.5 bg-emerald-500/20 rounded-xl"><Shield size={20} className="text-emerald-400" /></div>
                  <span className="text-2xl font-bold text-emerald-400">{hostCount || stats.protectedAssets}</span>
                </div>
                <h3 className="text-base font-bold text-white">HIDS 监控</h3>
                <p className="text-slate-400 text-sm mt-1">在线主机数</p>
                <div className="mt-3 pt-3 border-t border-emerald-500/20 flex justify-between text-xs">
                  <span className="text-emerald-400">{hostCount > 0 ? '● 全部正常' : '待检测'}</span>
                  <span className="text-emerald-400">查看 →</span>
                </div>
              </div>
            </div>
            <div className="relative overflow-hidden rounded-2xl group cursor-pointer hover:scale-[1.02] transition-all" onClick={() => navigate('/org')}>
              <div className="absolute inset-0 bg-gradient-to-br from-purple-600/30 to-pink-600/20"></div>
              <div className="absolute inset-0 rounded-2xl border border-purple-500/30 group-hover:border-purple-500/50"></div>
              <div className="relative z-10 p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="p-2.5 bg-purple-500/20 rounded-xl"><Globe size={20} className="text-purple-400" /></div>
                  <span className="text-2xl font-bold text-purple-400">{orgCount}</span>
                </div>
                <h3 className="text-base font-bold text-white">组织管理</h3>
                <p className="text-slate-400 text-sm mt-1">部门总数</p>
                <div className="mt-3 pt-3 border-t border-purple-500/20 flex justify-between text-xs">
                  <span className="text-slate-500">实时数据</span>
                  <span className="text-purple-400">管理 →</span>
                </div>
              </div>
            </div>
            <div className="relative overflow-hidden rounded-2xl group cursor-pointer hover:scale-[1.02] transition-all" onClick={() => navigate('/tracing')}>
              <div className="absolute inset-0 bg-gradient-to-br from-red-600/30 to-orange-600/20"></div>
              <div className="absolute inset-0 rounded-2xl border border-red-500/30 group-hover:border-red-500/50"></div>
              <div className="relative z-10 p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="p-2.5 bg-red-500/20 rounded-xl"><Target size={20} className="text-red-400" /></div>
                  <span className="text-2xl font-bold text-red-400">{traceCount}</span>
                </div>
                <h3 className="text-base font-bold text-white">攻击溯源</h3>
                <p className="text-slate-400 text-sm mt-1">已追踪来源</p>
                <div className="mt-3 pt-3 border-t border-red-500/20 flex justify-between text-xs">
                  <span className="text-slate-500">高危 {stats.activeThreats}个</span>
                  <span className="text-red-400">分析 →</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="lg:col-span-1">
          <div className="bg-gradient-to-br from-cyber-900/60 to-cyber-950/60 rounded-2xl border border-cyber-700/50 overflow-hidden">
            <div className="p-4 border-b border-cyber-700/50 flex justify-between items-center">
              <h3 className="font-bold text-white flex items-center gap-2 text-base"><Eye size={16} className="text-cyan-400"/> 系统审计日志</h3>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-500">可滚动查看</span>
                <span className="flex h-2 w-2 relative"><span className="animate-ping absolute h-full w-full rounded-full bg-emerald-400 opacity-75"></span><span className="relative rounded-full h-2 w-2 bg-emerald-500"></span></span>
              </div>
            </div>
            <div className="p-3 overflow-y-auto space-y-1.5 max-h-[380px] scrollbar-thin scrollbar-thumb-cyber-700 scrollbar-track-transparent hover:scrollbar-thumb-cyber-600">
              {logs.map((log, i) => (
                <div key={i} onClick={() => navigate('/alerts')} className={`flex items-center gap-3 font-mono p-3 rounded-xl cursor-pointer hover:bg-cyber-800/50 hover:scale-[1.01] transition-all border border-transparent hover:border-cyber-600/30 ${log.type === 'danger' ? 'bg-gradient-to-r from-red-500/10 to-transparent' : log.type === 'warning' ? 'bg-gradient-to-r from-yellow-500/10 to-transparent' : log.type === 'success' ? 'bg-gradient-to-r from-emerald-500/10 to-transparent' : 'bg-gradient-to-r from-cyan-500/5 to-transparent'}`}>
                  <span className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm shadow-lg ${log.type === 'danger' ? 'bg-red-500/20 text-red-400 shadow-red-500/20' : log.type === 'warning' ? 'bg-yellow-500/20 text-yellow-400 shadow-yellow-500/20' : log.type === 'success' ? 'bg-emerald-500/20 text-emerald-400 shadow-emerald-500/20' : 'bg-cyan-500/20 text-cyan-400 shadow-cyan-500/20'}`}>{log.icon}</span>
                  <div className="flex-1 min-w-0">
                    <p className={`truncate text-sm font-medium ${log.type === 'danger' ? 'text-red-300' : log.type === 'warning' ? 'text-yellow-300' : log.type === 'success' ? 'text-emerald-300' : 'bg-gradient-to-r from-cyan-300 to-blue-300 bg-clip-text text-transparent'}`}>{log.msg}</p>
                    <p className="text-cyan-500/70 text-xs mt-0.5">{log.time}</p>
                  </div>
                </div>
              ))}
              {logs.length === 0 && <p className="text-center text-slate-500 py-4">暂无数据</p>}
            </div>
          </div>
        </div>
      </div>

      {/* 底部：威胁态势 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div onClick={() => navigate('/analysis')} className="relative rounded-2xl p-6 overflow-hidden cursor-pointer group" style={{background: 'linear-gradient(145deg, rgba(0,10,30,0.95) 0%, rgba(0,30,50,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-blue-500/30 group-hover:border-blue-500/50"></div>
          <div className="relative z-10">
            <h3 className="text-blue-400 text-lg font-bold flex items-center gap-2 mb-4"><Target size={18} /> 威胁类型分布</h3>
            <div className="space-y-3">
              {(threatTypes.length > 0 ? threatTypes : [{ name: '加载中...', percent: 0, color: 'from-slate-500 to-slate-600' }]).map((item, i) => (
                <div key={i} className="flex items-center gap-3">
                  <span className="text-sm text-slate-400 w-20">{item.name}</span>
                  <div className="flex-1 h-2.5 bg-black/50 rounded-full overflow-hidden"><div className={`h-full bg-gradient-to-r ${item.color} rounded-full`} style={{width: `${item.percent}%`}}></div></div>
                  <span className="text-sm text-slate-300 w-12 text-right">{item.percent}%</span>
                </div>
              ))}
              {threatTypes.length === 0 && <p className="text-center text-slate-500 text-sm">暂无威胁数据</p>}
            </div>
          </div>
        </div>

        <div onClick={() => navigate('/analysis')} className="relative rounded-2xl p-6 overflow-hidden cursor-pointer group" style={{background: 'linear-gradient(145deg, rgba(30,0,20,0.95) 0%, rgba(50,0,30,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-pink-500/30 group-hover:border-pink-500/50"></div>
          <div className="relative z-10">
            <h3 className="text-pink-400 text-lg font-bold flex items-center gap-2 mb-4"><TrendingUp size={18} /> 24小时攻击趋势</h3>
            <div className="h-32">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData.length > 0 ? trendData : trafficData}>
                  <defs><linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#ec4899" stopOpacity={0.5}/><stop offset="100%" stopColor="#ec4899" stopOpacity={0}/></linearGradient></defs>
                  <Area type="monotone" dataKey="v" stroke="#ec4899" strokeWidth={2} fill="url(#trendGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <div className="flex justify-between text-sm text-slate-500 mt-2"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>24:00</span></div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Home;
