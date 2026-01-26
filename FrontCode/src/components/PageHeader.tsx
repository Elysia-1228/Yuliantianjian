import React from 'react';
import HexLogo from './HexLogo';

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  showLive?: boolean;
  liveText?: string;
  children?: React.ReactNode;
}

const PageHeader: React.FC<PageHeaderProps> = ({ 
  title, 
  subtitle, 
  showLive = false, 
  liveText = '实时监控中',
  children 
}) => {
  return (
    <div className="flex justify-between items-center">
      <div className="flex items-center gap-4">
        <HexLogo size={64} />
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <span className="bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 bg-clip-text text-transparent">
              {title}
            </span>
            {showLive && (
              <span className="text-xs px-2.5 py-1 bg-gradient-to-r from-emerald-500/20 to-cyan-500/20 text-emerald-400 rounded-full border border-emerald-500/30 flex items-center gap-1">
                <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse"></span>
                {liveText}
              </span>
            )}
          </h1>
          {subtitle && (
            <p className="text-slate-400 mt-1.5">{subtitle}</p>
          )}
        </div>
      </div>
      {children && (
        <div className="flex items-center gap-4">
          {children}
        </div>
      )}
    </div>
  );
};

export default PageHeader;
