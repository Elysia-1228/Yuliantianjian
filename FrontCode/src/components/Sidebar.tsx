import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldAlert, 
  Activity, 
  Map, 
  FileText, 
  Server, 
  Users, 
  LogOut,
  LayoutDashboard,
  Zap,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import logoImg from '../assets/logo.png';

interface SidebarProps {
  onLogout: () => void;
  isCollapsed: boolean;
  onToggle: (collapsed: boolean) => void;
}

const Sidebar: React.FC<SidebarProps> = ({ onLogout, isCollapsed, onToggle }) => {

  const navItems = [
    { to: '/', icon: LayoutDashboard, label: '首页' },
    { to: '/analysis', icon: Activity, label: '威胁分析中心' },
    { to: '/alerts', icon: ShieldAlert, label: '入侵安全检测' },
    { to: '/hids', icon: Server, label: '主机安全监控' },
    { to: '/tracing', icon: Map, label: '攻击溯源图谱' },
    { to: '/reports', icon: FileText, label: '智能报告生成' },
    { to: '/organization', icon: Users, label: '存证共享平台' },
  ];

  return (
    <aside 
      className={`bg-cyber-950 border-r border-cyber-800 flex flex-col h-screen fixed left-0 top-0 z-50 shadow-2xl shadow-cyber-900 transition-all duration-300 ease-in-out ${
        isCollapsed ? 'w-20' : 'w-72'
      }`}
    >
      {/* Brand Logo */}
      <div className="h-20 border-b border-cyber-800 flex items-center justify-center px-5 gap-4 bg-gradient-to-r from-cyber-900 to-cyber-950 relative">
        {/* Logo 图片 */}
        <div className={`w-14 h-14 relative flex items-center justify-center flex-shrink-0 transition-all duration-300 ${isCollapsed ? 'mx-auto' : ''}`}>
          <img 
            src={logoImg} 
            alt="Logo" 
            className="w-full h-full object-contain"
            style={{ filter: 'drop-shadow(0 0 10px rgba(6, 182, 212, 0.5))' }}
          />
        </div>
        <div className={`transition-all duration-300 overflow-hidden ${isCollapsed ? 'w-0 opacity-0' : 'w-auto opacity-100'}`}>
          <h1 className="text-xl font-bold bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 bg-clip-text text-transparent whitespace-nowrap">御链天鉴</h1>
          <p className="text-[10px] text-slate-500 tracking-widest whitespace-nowrap">网络安全智能分析平台</p>
        </div>
        
        {/* 收缩/展开按钮 */}
        <button
          onClick={() => onToggle(!isCollapsed)}
          className="absolute -right-3 top-1/2 -translate-y-1/2 w-6 h-6 bg-cyber-accent hover:bg-cyber-accent/80 rounded-full flex items-center justify-center shadow-lg shadow-cyber-accent/50 transition-all duration-300 hover:scale-110 z-10 border border-cyber-900"
          title={isCollapsed ? '展开侧边栏' : '收缩侧边栏'}
        >
          {isCollapsed ? <ChevronRight size={14} className="text-cyber-950" /> : <ChevronLeft size={14} className="text-cyber-950" />}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-6 px-4 space-y-2">
        <div className={`text-xs font-bold text-slate-500 uppercase tracking-wider mb-2 transition-all duration-300 overflow-hidden ${
          isCollapsed ? 'w-0 h-0 opacity-0' : 'px-4 opacity-100'
        }`}>主要模块</div>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center gap-3 py-3.5 rounded-xl transition-all duration-300 group relative overflow-hidden ${
                isCollapsed ? 'px-3 justify-center' : 'px-4'
              } ${
                isActive
                  ? 'bg-cyber-accent/10 text-cyber-accent shadow-[0_0_15px_rgba(6,182,212,0.15)] border border-cyber-accent/20'
                  : 'text-slate-400 hover:bg-cyber-800 hover:text-slate-200 hover:translate-x-1'
              }`
            }
            title={isCollapsed ? item.label : ''}
          >
            {({ isActive }) => (
              <>
                {isActive && !isCollapsed && <div className="absolute left-0 top-0 bottom-0 w-1 bg-cyber-accent rounded-l-full"></div>}
                <item.icon size={24} className={isActive ? "animate-pulse" : "group-hover:text-cyber-accent transition-colors"} />
                <span className={`font-medium text-sm tracking-wide transition-all duration-300 whitespace-nowrap ${
                  isCollapsed ? 'w-0 opacity-0 overflow-hidden' : 'w-auto opacity-100'
                }`}>{item.label}</span>
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User Profile / Logout */}
      <div className="p-4 border-t border-cyber-800 bg-gradient-to-t from-cyber-950 to-cyber-900/50">
        <div className={`flex items-center gap-3 p-3 rounded-xl bg-gradient-to-r from-cyber-800/50 to-cyber-800/30 border border-cyber-700/50 mb-3 transition-all duration-300 ${
          isCollapsed ? 'justify-center' : ''
        }`}>
          {/* 头像 - 渐变边框 */}
          <div className="relative">
            <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-cyan-500 via-blue-500 to-purple-500 p-[2px]">
              <div className="w-full h-full rounded-xl bg-cyber-900 flex items-center justify-center">
                <span className="font-bold text-sm bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">管理</span>
              </div>
            </div>
            {/* 在线状态指示器 */}
            <div className="absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 bg-cyber-900 rounded-full flex items-center justify-center">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            </div>
          </div>
          <div className={`flex-1 min-w-0 transition-all duration-300 overflow-hidden ${
            isCollapsed ? 'w-0 opacity-0' : 'w-auto opacity-100'
          }`}>
            <p className="text-sm font-bold text-white truncate">系统管理员</p>
            <p className="text-xs text-emerald-400 flex items-center gap-1">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              在线
            </p>
          </div>
        </div>
        <button
          onClick={onLogout}
          className={`flex items-center justify-center gap-2 w-full py-2.5 text-slate-400 bg-cyber-800/50 hover:bg-red-500/20 hover:text-red-400 border border-cyber-700/50 hover:border-red-500/30 rounded-xl transition-all duration-300 group ${
            isCollapsed ? 'px-3' : 'px-4'
          }`}
          title={isCollapsed ? '安全退出' : ''}
        >
          <LogOut size={16} className="group-hover:rotate-12 transition-transform" />
          <span className={`font-medium text-sm transition-all duration-300 whitespace-nowrap ${
            isCollapsed ? 'w-0 opacity-0 overflow-hidden' : 'w-auto opacity-100'
          }`}>安全退出</span>
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;