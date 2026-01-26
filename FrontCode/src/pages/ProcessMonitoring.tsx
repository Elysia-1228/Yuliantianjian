import React, { useState, useEffect } from 'react';
import { AlertCircle, PlayCircle, StopCircle, Search, Loader2, ShieldCheck } from 'lucide-react';
import { MonitorService } from '../services/connector';

interface ProcessMonitoringProps {
  isEmbedded?: boolean;
}

const ProcessMonitoring: React.FC<ProcessMonitoringProps> = ({ isEmbedded = false }) => {
  const [processes, setProcesses] = useState<any[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(false);
  
  // Track async actions on specific processes
  const [processingId, setProcessingId] = useState<number | null>(null); // Uses DB ID
  const [actionType, setActionType] = useState<'kill' | 'trust' | null>(null);

  const fetchProcesses = async () => {
    try {
      setLoading(true);
      const data = await MonitorService.getProcesses(1, 100);
      // Map backend data to frontend structure
      const mapped = data.map((p: any) => ({
        id: p.id,
        pid: p.processId,
        name: p.processName,
        status: p.processStatus || 'running',
        abnormalReason: p.abnormalReason,
        // Mock resources as backend doesn't provide them yet
        cpu: (p.processId % 100) / 2, 
        memory: (p.processId % 200) + 20
      }));
      setProcesses(mapped);
    } catch (error) {
      console.error("Failed to fetch processes", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProcesses();
    // Poll every 5 seconds
    const interval = setInterval(fetchProcesses, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleKill = async (proc: any) => {
    if (!proc.id) return;
    setProcessingId(proc.id);
    setActionType('kill');
    
    try {
      await MonitorService.updateProcess(proc.id, { ...proc, processStatus: 'stopped' });
      // Optimistic update or wait for poll
      setProcesses(prev => prev.map(p => p.id === proc.id ? { ...p, status: 'stopped' } : p));
    } catch (e) {
      console.error("Failed to kill process", e);
    } finally {
      setProcessingId(null);
      setActionType(null);
    }
  };

  const handleTrust = async (proc: any) => {
    if (!proc.id) return;
    setProcessingId(proc.id);
    setActionType('trust');

    try {
      await MonitorService.updateProcess(proc.id, { ...proc, processStatus: 'running', abnormalReason: '' });
      setProcesses(prev => prev.map(p => 
        p.id === proc.id ? { ...p, status: 'running', abnormalReason: undefined } : p
      ));
      alert(`PID ${proc.pid} 的签名已加入白名单。`);
    } catch (e) {
      console.error("Failed to trust process", e);
    } finally {
      setProcessingId(null);
      setActionType(null);
    }
  };

  const filtered = processes.filter(p => p.name?.includes(searchTerm) || p.pid?.toString().includes(searchTerm));

  // Sort: Abnormal first
  const sorted = [...filtered].sort((a, b) => (a.status === 'abnormal' ? -1 : 1));

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex justify-between items-center">
        {!isEmbedded && (
          <div>
            <h2 className="text-2xl font-bold text-white">系统进程监控</h2>
            <p className="text-slate-400">主机: Server-Alpha (10.0.0.5)</p>
          </div>
        )}
        <div className={`relative ${isEmbedded ? 'w-full' : ''}`}>
          <Search className="absolute left-3 top-2.5 text-slate-500" size={18} />
          <input 
            type="text" 
            placeholder="搜索 PID 或名称..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-cyber-800 border border-cyber-700 rounded-lg pl-10 pr-4 py-2 text-white outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent w-full"
          />
        </div>
      </div>

      <div className="glass-panel rounded-xl overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead className="bg-cyber-900/80 text-slate-400 uppercase text-xs">
            <tr>
              <th className="p-4">PID</th>
              <th className="p-4">进程名称</th>
              <th className="p-4">状态</th>
              <th className="p-4">CPU %</th>
              <th className="p-4">内存 (MB)</th>
              <th className="p-4 text-right">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-700 text-slate-300">
            {sorted.map(proc => (
              <tr 
                key={proc.id || proc.pid} 
                className={`hover:bg-cyber-700/50 transition-colors ${
                    proc.status === 'abnormal' ? 'bg-red-500/5' : ''
                } ${processingId === proc.id ? 'opacity-50 pointer-events-none' : ''}`}
              >
                <td className="p-4 font-mono text-sm">{proc.pid}</td>
                <td className="p-4 font-bold text-white">{proc.name}</td>
                <td className="p-4">
                  <div className="flex items-center gap-2 group relative">
                    <span className={`px-2 py-1 rounded-full text-xs font-bold ${
                      proc.status === 'running' ? 'bg-emerald-500/20 text-emerald-400' :
                      proc.status === 'abnormal' ? 'bg-red-500/20 text-red-400' :
                      'bg-slate-700 text-slate-300'
                    }`}>
                      {proc.status?.toUpperCase()}
                    </span>
                    {proc.status === 'abnormal' && (
                      <>
                        <AlertCircle size={16} className="text-red-500 cursor-help" />
                        <div className="absolute left-full ml-2 w-64 bg-black border border-red-500 p-2 rounded text-xs text-red-200 opacity-0 group-hover:opacity-100 transition-opacity z-10 pointer-events-none shadow-xl">
                          威胁特征: {proc.abnormalReason}
                        </div>
                      </>
                    )}
                  </div>
                </td>
                <td className="p-4 font-mono">{proc.cpu}%</td>
                <td className="p-4 font-mono">{proc.memory}</td>
                <td className="p-4 text-right">
                  <div className="flex justify-end gap-2">
                      <button 
                        onClick={() => handleKill(proc)}
                        disabled={processingId === proc.id}
                        className="p-2 text-red-400 hover:bg-red-500/20 border border-transparent hover:border-red-500/30 rounded-lg transition-all disabled:opacity-50"
                        title="终止进程 (SIGKILL)"
                      >
                        {processingId === proc.id && actionType === 'kill' ? <Loader2 size={18} className="animate-spin" /> : <StopCircle size={18} />}
                      </button>
                      <button 
                        onClick={() => handleTrust(proc)}
                        disabled={processingId === proc.id}
                        className="p-2 text-cyber-accent hover:bg-cyber-accent/20 border border-transparent hover:border-cyber-accent/30 rounded-lg transition-all disabled:opacity-50" 
                        title="加入白名单"
                      >
                         {processingId === proc.id && actionType === 'trust' ? <Loader2 size={18} className="animate-spin" /> : <ShieldCheck size={18} />}
                      </button>
                  </div>
                </td>
              </tr>
            ))}
            {sorted.length === 0 && !loading && (
              <tr>
                <td colSpan={6} className="p-8 text-center text-slate-500">
                  暂无进程监控数据
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ProcessMonitoring;