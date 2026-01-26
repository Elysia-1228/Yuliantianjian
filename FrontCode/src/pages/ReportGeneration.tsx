import React, { useState, useEffect } from 'react';
import { FileText, Calendar, Loader2, CheckCircle, Terminal, Eye, Download, History, ChevronRight, X, Edit2, Trash2, Save, XCircle, Sparkles, Share2 } from 'lucide-react';
import PageHeader from '../components/PageHeader';
import { ReportService } from '../services/connector';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import html2canvas from 'html2canvas';
import { jsPDF } from 'jspdf';

const MarkdownRenderer: React.FC<{ content: string }> = ({ content }) => (
  <div className="prose prose-invert prose-sm max-w-none font-sans leading-relaxed">
    <ReactMarkdown 
      remarkPlugins={[remarkGfm]}
      components={{
      h1: ({node, ...props}) => <h1 className="text-2xl font-bold text-cyber-accent mb-6 border-b border-cyber-800 pb-2" {...props} />,
      h2: ({node, ...props}) => <h2 className="text-xl font-bold text-white mt-8 mb-4 flex items-center gap-2 before:content-[''] before:w-1 before:h-6 before:bg-cyber-accent before:rounded-full before:mr-2" {...props} />,
      h3: ({node, ...props}) => <h3 className="text-lg font-bold text-slate-200 mt-6 mb-3" {...props} />,
      ul: ({node, ...props}) => <ul className="list-disc list-outside ml-5 space-y-2 text-slate-300 my-4" {...props} />,
      li: ({node, ...props}) => <li className="marker:text-cyber-accent pl-1" {...props} />,
      strong: ({node, ...props}) => <strong className="text-white font-bold bg-cyber-900/50 px-1 rounded text-cyber-light" {...props} />,
      blockquote: ({node, ...props}) => <blockquote className="border-l-4 border-cyber-600 pl-4 py-2 my-4 italic text-slate-400 bg-cyber-900/20 rounded-r" {...props} />,
      code: ({node, ...props}) => {
        // @ts-ignore
        const {inline, className, children} = props;
        return <code className="font-mono text-sm bg-black/30 text-cyber-accent px-1.5 py-0.5 rounded border border-cyber-900" {...props} />
      },
      pre: ({node, ...props}) => <pre className="bg-black/40 p-4 rounded-lg overflow-x-auto border border-cyber-800 my-4" {...props} />,
      table: ({node, ...props}) => <div className="overflow-x-auto my-6"><table className="min-w-full text-left text-sm" {...props} /></div>,
      th: ({node, ...props}) => <th className="bg-cyber-900/80 p-3 font-bold text-white border-b border-cyber-700" {...props} />,
      td: ({node, ...props}) => <td className="p-3 border-b border-cyber-800/50 text-slate-300" {...props} />,
      hr: ({node, ...props}) => <hr className="border-cyber-800 my-8" {...props} />,
      p: ({node, ...props}) => <p className="mb-4 text-slate-300" {...props} />,
    }}
    >
      {content}
    </ReactMarkdown>
  </div>
);

const ReportGeneration: React.FC = () => {
  const [reportType, setReportType] = useState<'Daily' | 'Weekly' | 'Custom'>('Daily');
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedContent, setGeneratedContent] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  
  // History Management State
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editTitle, setEditTitle] = useState('');
  
  // History simulation
  const [historyLoading, setHistoryLoading] = useState(true);
  const [reportHistory, setReportHistory] = useState<{id: number, title: string, date: string, content: string}[]>([]);

  // Fetch history from backend
  useEffect(() => {
      fetchHistory();
  }, []);

  const fetchHistory = async () => {
      setHistoryLoading(true);
      try {
          const data = await ReportService.getHistory();
          // Map backend history to frontend format
          const formatted = data.map((item: any) => {
              let dateStr = 'Unknown';
              const input = item.createTime;

              try {
                  if (input) {
                      // Case 1: Array format [yyyy, MM, dd, HH, mm, ss]
                      if (Array.isArray(input)) {
                          const [y, m, d, h, min, s] = input;
                          const date = new Date(y, m - 1, d, h, min, s);
                          dateStr = date.toLocaleString();
                      } else {
                          const str = String(input).trim();
                          
                          // Case 2: Compact string "20251212224826" (14 chars)
                          if (/^\d{14}$/.test(str)) {
                               const y = str.substring(0, 4);
                               const m = str.substring(4, 6);
                               const d = str.substring(6, 8);
                               const h = str.substring(8, 10);
                               const min = str.substring(10, 12);
                               const s = str.substring(12, 14);
                               dateStr = `${y}-${m}-${d} ${h}:${min}:${s}`;
                          }
                          // Case 3: Compact string missing leading zero "2025121224826" (13 chars) -> 02:48:26
                          else if (/^\d{13}$/.test(str) && str.startsWith('20')) {
                               const y = str.substring(0, 4);
                               const m = str.substring(4, 6);
                               const d = str.substring(6, 8);
                               const h = str.substring(8, 9);
                               const min = str.substring(9, 11);
                               const s = str.substring(11, 13);
                               dateStr = `${y}-${m}-${d} 0${h}:${min}:${s}`;
                          }
                          // Case 4: Timestamp
                          else if (/^\d{13}$/.test(str)) {
                               dateStr = new Date(Number(str)).toLocaleString();
                          }
                          // Case 5: ISO or other
                          else {
                              const safeDateStr = str.includes('T') ? str : str.replace(' ', 'T');
                              const dateObj = new Date(safeDateStr);
                              if (!isNaN(dateObj.getTime())) {
                                  dateStr = dateObj.toLocaleString();
                              } else {
                                  dateStr = str;
                              }
                          }
                      }
                  }
              } catch (e) {
                  dateStr = String(input);
              }

              return {
                  id: item.id,
                  title: item.title || `安全报告-${item.id}`,
                  date: dateStr,
                  content: item.content
              };
          });
          setReportHistory(formatted);
      } catch (e) {
          console.error("Failed to fetch history", e);
      } finally {
          setHistoryLoading(false);
      }
  };

  const handleDeleteHistory = async (e: React.MouseEvent, id: number) => {
      e.stopPropagation(); // Prevent triggering preview
      if (!window.confirm('确定要删除这份报告吗？此操作不可恢复。')) return;

      try {
          // 尝试调用后端删除接口
          await ReportService.delete(id);
      } catch (e) {
          console.error("Backend delete failed, performing frontend-only delete", e);
          // 即使后端失败，前端也继续删除（为了演示效果）
      }
      
      // Frontend update (Always perform this for demo)
      setReportHistory(prev => prev.filter(item => item.id !== id));
      if (generatedContent && reportHistory.find(i => i.id === id)?.content === generatedContent) {
          setGeneratedContent(null);
      }
  };

  const startEditing = (e: React.MouseEvent, item: any) => {
      e.stopPropagation();
      setEditingId(item.id);
      setEditTitle(item.title);
  };

  const cancelEditing = (e: React.MouseEvent) => {
      e.stopPropagation();
      setEditingId(null);
      setEditTitle('');
  };

  const saveEditing = async (e: React.MouseEvent, id: number) => {
      e.stopPropagation();
      if (!editTitle.trim()) return;

      try {
          await ReportService.rename(id, editTitle);
          setReportHistory(prev => prev.map(item => 
              item.id === id ? { ...item, title: editTitle } : item
          ));
          setEditingId(null);
      } catch (e) {
          console.error("Rename failed", e);
          alert("重命名失败");
      }
  };

  const handleHistoryClick = (item: any) => {
      if (editingId !== null) return; // Prevent click when editing
      setGeneratedContent(item.content);
  };

  const handleShare = (e: React.MouseEvent, item: any) => {
      e.stopPropagation();
      
      const sharedItem = {
          id: item.id,
          title: item.title,
          source: '我发起的',
          time: '刚刚',
          status: 'shared',
          content: item.content
      };

      // Get existing shared reports
      const existingStr = localStorage.getItem('shared_reports');
      let existing = [];
      try {
          existing = existingStr ? JSON.parse(existingStr) : [];
      } catch (e) { existing = []; }
      
      // Avoid duplicates
      if (!existing.find((i: any) => i.id === item.id)) {
          existing.unshift(sharedItem);
          localStorage.setItem('shared_reports', JSON.stringify(existing));
          // Dispatch event so OrgManagement can listen if it wants (optional, but good for same-window sync if needed)
          window.dispatchEvent(new Event('storage')); 
          alert(`已分享报告 "${item.title}" 到存证共享平台`);
      } else {
          alert(`报告 "${item.title}" 已经是分享状态`);
      }
  };

  const handleExportPdf = async () => {
    if (!generatedContent) return;
    
    setIsExporting(true);
    const element = document.getElementById('report-content');
    if (!element) {
        setIsExporting(false);
        return;
    }

    try {
        const canvas = await html2canvas(element, {
            scale: 2,
            backgroundColor: '#030712', // cyber-950
            useCORS: true,
            logging: false,
            windowWidth: element.scrollWidth,
            windowHeight: element.scrollHeight
        });
        
        const imgData = canvas.toDataURL('image/png');
        const pdf = new jsPDF({
            orientation: 'portrait',
            unit: 'px',
            format: [canvas.width, canvas.height]
        });
        
        pdf.addImage(imgData, 'PNG', 0, 0, canvas.width, canvas.height);
        pdf.save(`security-report-${new Date().toISOString().split('T')[0]}.pdf`);
    } catch (err) {
        console.error("PDF Export failed:", err);
        alert("导出失败，请重试");
    } finally {
        setIsExporting(false);
    }
  };

  const handleGenerate = async () => {
    setIsGenerating(true);
    setGeneratedContent(null);
    setLogs([]);

    // Simulate process logs
    const steps = [
      "正在初始化 AI 引擎...",
      "连接威胁情报数据库...",
      `检索最近 ${reportType === 'Daily' ? '24小时' : '7天'} 数据...`,
      "分析攻击向量与特征...",
      "生成自然语言摘要...",
      "格式化输出..."
    ];

    // Show logs progressively (visual effect)
    let stepIndex = 0;
    // We start the interval but we also start the API call. 
    // If API returns fast, we clear interval.
    const logInterval = setInterval(() => {
        if (stepIndex < steps.length) {
            setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] INFO: ${steps[stepIndex]}`]);
            stepIndex++;
        }
    }, 800);

    try {
        const content = await ReportService.generate(reportType);
        
        clearInterval(logInterval);
        // Fill remaining logs if finished early
        while(stepIndex < steps.length) {
             setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] INFO: ${steps[stepIndex]}`]);
             stepIndex++;
        }
        setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] SUCCESS: 报告生成完成`]);
        
        setGeneratedContent(content);
        
        // Refresh history
        fetchHistory();
    } catch (error) {
        clearInterval(logInterval);
        setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ERROR: 生成失败 - 请检查后端连接`]);
        console.error(error);
    } finally {
        setIsGenerating(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader title="智能威胁报告引擎" subtitle="利用生成式 AI 自动化分析安全日志并生成决策报告" />

      {/* 统计卡片 */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="relative rounded-2xl p-5 overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(0,20,40,0.95) 0%, rgba(0,40,60,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-cyan-500/30"></div>
          <div className="absolute -right-4 -top-4 w-20 h-20 bg-cyan-500/20 rounded-full blur-2xl"></div>
          <div className="relative z-10 flex items-center gap-4">
            <FileText size={28} className="text-cyan-400" />
            <div>
              <p className="text-4xl font-mono font-bold text-white">{reportHistory.length}</p>
              <p className="text-sm text-slate-400 mt-1">历史报告</p>
            </div>
          </div>
        </div>
        <div className="relative rounded-2xl p-5 overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(20,0,40,0.95) 0%, rgba(40,0,60,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-purple-500/30"></div>
          <div className="absolute -right-4 -top-4 w-20 h-20 bg-purple-500/20 rounded-full blur-2xl"></div>
          <div className="relative z-10 flex items-center gap-4">
            <Sparkles size={28} className="text-purple-400" />
            <div>
              <p className="text-4xl font-mono font-bold text-purple-400">{isGenerating ? '生成中' : '已就绪'}</p>
              <p className="text-sm text-slate-400 mt-1">AI 引擎状态</p>
            </div>
          </div>
        </div>
        <div className="relative rounded-2xl p-5 overflow-hidden" style={{background: 'linear-gradient(145deg, rgba(0,30,20,0.95) 0%, rgba(0,50,30,0.9) 100%)'}}>
          <div className="absolute inset-0 rounded-2xl border border-emerald-500/30"></div>
          <div className="absolute -right-4 -top-4 w-20 h-20 bg-emerald-500/20 rounded-full blur-2xl"></div>
          <div className="relative z-10 flex items-center gap-4">
            <CheckCircle size={28} className="text-emerald-400" />
            <div>
              <p className="text-4xl font-mono font-bold text-emerald-400">{generatedContent ? '已生成' : '待生成'}</p>
              <p className="text-sm text-slate-400 mt-1">当前报告</p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Config Panel */}
        <div className="lg:col-span-1 space-y-6">
           <div className="glass-panel p-6 rounded-xl space-y-6">
              <div>
                <h3 className="text-sm font-bold text-white uppercase mb-4 flex items-center gap-2">
                  <Terminal size={16} className="text-cyber-accent"/> 参数配置
                </h3>
                <div className="space-y-3">
                  {[
                    { id: 'Daily', label: '每日安全日报', desc: '过去 24 小时概览' },
                    { id: 'Weekly', label: '每周态势周报', desc: '深度趋势分析' },
                    { id: 'Custom', label: '专项调查报告', desc: '特定事件复盘' }
                  ].map((type) => (
                    <div 
                      key={type.id}
                      onClick={() => setReportType(type.id as any)}
                      className={`p-4 rounded-lg border cursor-pointer transition-all duration-200 ${
                        reportType === type.id 
                          ? 'bg-cyber-accent/10 border-cyber-accent shadow-[0_0_10px_rgba(6,182,212,0.1)]' 
                          : 'bg-cyber-900/50 border-cyber-700 hover:bg-cyber-800'
                      }`}
                    >
                      <div className="flex justify-between items-center">
                        <span className={`font-bold text-sm ${reportType === type.id ? 'text-white' : 'text-slate-300'}`}>{type.label}</span>
                        {reportType === type.id && <CheckCircle size={16} className="text-cyber-accent" />}
                      </div>
                      <p className="text-xs text-slate-500 mt-1">{type.desc}</p>
                    </div>
                  ))}
                </div>
              </div>

              {reportType === 'Custom' && (
                <div className="animate-fade-in">
                   <label className="block text-xs font-bold text-slate-400 mb-2">起止日期</label>
                   <div className="relative">
                     <Calendar className="absolute left-3 top-2.5 text-slate-500" size={16} />
                     <input type="date" className="w-full bg-cyber-950 border border-cyber-700 rounded p-2 pl-10 text-sm text-white focus:border-cyber-accent outline-none" />
                   </div>
                </div>
              )}

              <button 
                onClick={handleGenerate}
                disabled={isGenerating}
                className="w-full py-3.5 bg-gradient-to-r from-cyber-accent to-blue-600 text-white font-bold rounded-lg shadow-lg shadow-blue-900/20 hover:shadow-blue-500/20 hover:scale-[1.02] transition-all disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none flex justify-center items-center gap-2"
              >
                {isGenerating ? <Loader2 className="animate-spin" size={20} /> : '启动 AI 生成'}
              </button>
           </div>

           {/* Report History Panel */}
           <div className="glass-panel p-6 rounded-xl">
               <h3 className="text-sm font-bold text-white uppercase mb-4 flex items-center gap-2">
                  <History size={16} className="text-slate-400"/> 历史归档
               </h3>
               {historyLoading ? (
                   <div className="space-y-3">
                       {[1,2,3].map(i => <div key={i} className="h-10 bg-cyber-800/50 rounded animate-pulse"></div>)}
                   </div>
               ) : (
                   <div className="space-y-2">
                       {reportHistory.map(item => (
                           <div 
                               key={item.id} 
                               onClick={() => handleHistoryClick(item)}
                               className="p-3 hover:bg-cyber-800 rounded cursor-pointer group flex justify-between items-center transition-colors border border-transparent hover:border-cyber-700"
                           >
                               <div className="flex-1 min-w-0 mr-4">
                                   {editingId === item.id ? (
                                       <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
                                           <input 
                                               type="text" 
                                               value={editTitle}
                                               onChange={(e) => setEditTitle(e.target.value)}
                                               className="bg-cyber-950 border border-cyber-600 rounded px-2 py-1 text-xs text-white w-full focus:border-cyber-accent outline-none"
                                               autoFocus
                                           />
                                           <button onClick={(e) => saveEditing(e, item.id)} className="text-emerald-500 hover:text-emerald-400">
                                               <Save size={14} />
                                           </button>
                                           <button onClick={cancelEditing} className="text-red-500 hover:text-red-400">
                                               <XCircle size={14} />
                                           </button>
                                       </div>
                                   ) : (
                                       <>
                                           <div className="text-sm text-slate-300 group-hover:text-white font-medium truncate" title={item.title}>
                                               {item.title}
                                           </div>
                                           <div className="text-xs text-slate-500 mt-1">{item.date}</div>
                                       </>
                                   )}
                               </div>
                               
                               {editingId !== item.id && (
                                       <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-all">
                                           <button 
                                               onClick={(e) => handleShare(e, item)}
                                               className="p-1.5 text-slate-400 hover:text-blue-400 hover:bg-cyber-900 rounded"
                                               title="分享到存证平台"
                                           >
                                               <Share2 size={14} />
                                           </button>
                                           <button 
                                               onClick={(e) => startEditing(e, item)}
                                           className="p-1.5 text-slate-400 hover:text-cyber-accent hover:bg-cyber-900 rounded"
                                           title="重命名"
                                       >
                                           <Edit2 size={14} />
                                       </button>
                                       <button 
                                           onClick={(e) => handleDeleteHistory(e, item.id)}
                                           className="p-1.5 text-slate-400 hover:text-red-500 hover:bg-cyber-900 rounded"
                                           title="删除"
                                       >
                                           <Trash2 size={14} />
                                       </button>
                                       <ChevronRight size={14} className="text-slate-600 group-hover:text-cyber-accent" />
                                   </div>
                               )}
                           </div>
                       ))}
                   </div>
               )}
           </div>
        </div>

        {/* Preview / Terminal Panel */}
        <div className="lg:col-span-3">
           <div className="glass-panel rounded-xl h-[700px] flex flex-col overflow-hidden border-cyber-700">
              {/* Header */}
              <div className="px-6 py-3 border-b border-cyber-700 flex justify-between items-center bg-cyber-900/80">
                 <div className="flex items-center gap-2">
                   <div className="flex gap-1.5">
                     <div className="w-3 h-3 rounded-full bg-red-500/50"></div>
                     <div className="w-3 h-3 rounded-full bg-yellow-500/50"></div>
                     <div className="w-3 h-3 rounded-full bg-green-500/50"></div>
                   </div>
                   <span className="ml-3 text-xs font-mono text-slate-400">report_preview.md</span>
                 </div>
                 {generatedContent && !isGenerating && (
                   <div className="flex gap-3">
                     <button 
                       onClick={() => setIsFullscreen(true)}
                       className="text-xs flex items-center gap-1 text-slate-300 hover:text-white transition-colors"
                     >
                       <Eye size={14} /> 全屏预览
                     </button>
                     <button 
                       onClick={handleExportPdf}
                       disabled={isExporting}
                       className="text-xs flex items-center gap-1 text-cyber-accent hover:text-cyan-300 transition-colors font-bold disabled:opacity-50"
                     >
                       {isExporting ? <Loader2 size={14} className="animate-spin"/> : <Download size={14} />} 
                       {isExporting ? '导出中...' : '导出 PDF'}
                     </button>
                   </div>
                 )}
              </div>
              
              {/* Content */}
              <div className="flex-1 p-0 bg-cyber-950/80 overflow-y-auto scrollbar-thin relative">
                 {isGenerating ? (
                   <div className="p-6 font-mono text-sm space-y-2">
                     {logs.map((log, idx) => (
                       <div key={idx} className="text-emerald-500/80 animate-fade-in">
                         <span className="mr-2">$</span>{log}
                       </div>
                     ))}
                     <div className="flex items-center gap-2 text-cyber-accent animate-pulse mt-4">
                       <span className="w-2 h-4 bg-cyber-accent block"></span>
                       正在处理...
                     </div>
                   </div>
                 ) : generatedContent ? (
                   <div className="p-8" id="report-content">
                     <MarkdownRenderer content={generatedContent} />
                     <div className="mt-8 pt-4 border-t border-cyber-800 flex items-center gap-2 text-xs text-slate-500 font-mono">
                       <CheckCircle size={12} className="text-emerald-500" /> GENERATION COMPLETE
                     </div>
                   </div>
                 ) : (
                   <div className="h-full flex flex-col items-center justify-center text-slate-600 gap-4">
                     <div className="w-20 h-20 rounded-full bg-cyber-800/50 flex items-center justify-center border border-cyber-700 border-dashed">
                       <Terminal size={32} />
                     </div>
                     <p className="text-sm">等待任务启动...</p>
                   </div>
                 )}
              </div>
           </div>
        </div>
      </div>

      {/* Full Screen Modal */}
      {isFullscreen && generatedContent && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-fade-in">
            <div className="bg-cyber-900 border border-cyber-700 rounded-xl w-full max-w-5xl h-[90vh] flex flex-col shadow-2xl shadow-black">
                <div className="flex justify-between items-center p-4 border-b border-cyber-700">
                    <h3 className="text-lg font-bold text-white flex items-center gap-2">
                        <FileText size={20} className="text-cyber-accent"/>
                        全屏预览模式
                    </h3>
                    <button 
                        onClick={() => setIsFullscreen(false)}
                        className="p-2 hover:bg-cyber-800 rounded-lg text-slate-400 hover:text-white transition-colors"
                    >
                        <X size={20} />
                    </button>
                </div>
                <div className="flex-1 overflow-y-auto p-8 bg-cyber-950/50">
                    <MarkdownRenderer content={generatedContent} />
                </div>
            </div>
        </div>
      )}
    </div>
  );
};

export default ReportGeneration;