import React from 'react';
import { Navigate } from 'react-router-dom';

const DataCollection: React.FC = () => {
  // 用户请求隐藏此页面，直接重定向到首页
  return <Navigate to="/" replace />;
};

export default DataCollection;
