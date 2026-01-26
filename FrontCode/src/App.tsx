import React, { useState, useEffect } from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import DataCollection from './pages/DataCollection';
import ThreatAnalysis from './pages/ThreatAnalysis';
import ThreatAlerts from './pages/ThreatAlerts';
import ThreatTracing from './pages/ThreatTracing';
import ReportGeneration from './pages/ReportGeneration';
import HostMonitoring from './pages/HostMonitoring';
import ProcessMonitoring from './pages/ProcessMonitoring';
import OrgManagement from './pages/OrgManagement';
import Login from './pages/Login';
import Home from './pages/Home';

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isInit, setIsInit] = useState(true); // 用于初始化检查，防止页面闪烁
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState<boolean>(false); // 侧边栏收缩状态

  useEffect(() => {
    // 1. 初始化时检查本地存储中是否存在 auth_token
    const token = localStorage.getItem('auth_token');
    if (token) {
      setIsAuthenticated(true);
    }
    // 2. 从本地存储恢复侧边栏状态
    const sidebarState = localStorage.getItem('sidebar_collapsed');
    if (sidebarState === 'true') {
      setIsSidebarCollapsed(true);
    }
    setIsInit(false);
  }, []);

  // 登录成功回调
  const handleLogin = () => {
    setIsAuthenticated(true);
  };

  // 退出登录回调
  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    setIsAuthenticated(false);
  };

  // 侧边栏收缩状态切换回调
  const handleSidebarToggle = (collapsed: boolean) => {
    setIsSidebarCollapsed(collapsed);
    localStorage.setItem('sidebar_collapsed', collapsed.toString());
  };

  // 初始化期间不渲染任何内容，避免未授权时短暂显示受保护页面
  if (isInit) return null;

  return (
    <HashRouter>
      <Routes>
        {/* === 路由策略配置 === */}

        {/* 1. 登录页路由： */}
        {/* - 如果已登录 (isAuthenticated 为 true)，自动重定向到首页 (/) */}
        {/* - 如果未登录，显示 Login 组件 */}
        <Route 
          path="/login" 
          element={
            isAuthenticated ? <Navigate to="/" replace /> : <Login onLogin={handleLogin} />
          } 
        />

        {/* 2. 主应用受保护路由 (/*)：匹配所有非 /login 的路径 */}
        {/* - 如果已登录，渲染包含 Sidebar 和主内容的布局 */}
        {/* - 如果未登录，强制重定向到 /login */}
        <Route 
          path="/*" 
          element={
            isAuthenticated ? (
              <div className="flex min-h-screen bg-cyber-950 text-slate-200 font-sans">
                {/* 侧边栏导航 */}
                <Sidebar 
                  onLogout={handleLogout} 
                  isCollapsed={isSidebarCollapsed}
                  onToggle={handleSidebarToggle}
                />
                
                {/* 主内容区域 - 根据侧边栏状态动态调整左边距 */}
                <main className={`flex-1 p-8 overflow-y-auto h-screen bg-cyber-900/50 transition-all duration-300 ease-in-out ${
                  isSidebarCollapsed ? 'ml-20' : 'ml-72'
                }`}>
                  <Routes>
                    <Route path="/" element={<Home />} />
                    {/* <Route path="/collection" element={<DataCollection />} /> */}
                    <Route path="/analysis" element={<ThreatAnalysis />} />
                    <Route path="/alerts" element={<ThreatAlerts />} />
                    <Route path="/tracing" element={<ThreatTracing />} />
                    <Route path="/hids" element={<HostMonitoring />} />
                    <Route path="/hids/processes" element={<ProcessMonitoring />} />
                    <Route path="/reports" element={<ReportGeneration />} />
                    <Route path="/organization" element={<OrgManagement />} />
                    {/* 捕获未知路径，重定向回首页 */}
                    <Route path="*" element={<Navigate to="/" replace />} />
                  </Routes>
                </main>
              </div>
            ) : (
              <Navigate to="/login" replace />
            )
          } 
        />
      </Routes>
    </HashRouter>
  );
};

export default App;