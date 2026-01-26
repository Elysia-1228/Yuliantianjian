/**
 * RadarLoading - 雷达扫描加载动画组件
 * 用于AI引擎分析时的Loading状态展示
 */

import React from 'react';
import './styles.css';

interface RadarLoadingProps {
  message?: string;
  subMessage?: string;
}

const RadarLoading: React.FC<RadarLoadingProps> = ({ 
  message = 'AI 分析中...', 
  subMessage = 'Connecting to Neural Engine' 
}) => {
  return (
    <div className="radar-loading-container">
      {/* 背景网格 */}
      <div className="radar-grid"></div>
      
      {/* 雷达主体 */}
      <div className="radar-wrapper">
        {/* 外圈 */}
        <div className="radar-circle radar-circle-outer"></div>
        <div className="radar-circle radar-circle-middle"></div>
        <div className="radar-circle radar-circle-inner"></div>
        
        {/* 十字准星 */}
        <div className="radar-crosshair horizontal"></div>
        <div className="radar-crosshair vertical"></div>
        
        {/* 扫描线 */}
        <div className="radar-sweep"></div>
        
        {/* 中心点 */}
        <div className="radar-center"></div>
        
        {/* 扫描到的目标点 */}
        <div className="radar-blip blip-1"></div>
        <div className="radar-blip blip-2"></div>
        <div className="radar-blip blip-3"></div>
      </div>
      
      {/* 文字提示 */}
      <div className="radar-text">
        <div className="radar-message">{message}</div>
        <div className="radar-submessage">{subMessage}</div>
        <div className="radar-dots">
          <span className="dot"></span>
          <span className="dot"></span>
          <span className="dot"></span>
        </div>
      </div>
      
      {/* 状态指示器 */}
      <div className="radar-status">
        <div className="status-item">
          <span className="status-dot active"></span>
          <span className="status-label">NEURAL LINK</span>
        </div>
        <div className="status-item">
          <span className="status-dot processing"></span>
          <span className="status-label">ANALYZING</span>
        </div>
        <div className="status-item">
          <span className="status-dot pending"></span>
          <span className="status-label">GRAPH GEN</span>
        </div>
      </div>
    </div>
  );
};

export default RadarLoading;
