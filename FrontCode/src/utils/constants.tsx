import React from 'react';
import { RiskLevel, ThreatEvent, SystemProcess, Organization } from '../types/index';

// ... (保留原有的 Mock Data MOCK_THREATS, MOCK_PROCESSES, MOCK_ORGS) ...
export const MOCK_THREATS: ThreatEvent[] = [
  { id: 'TH-1001', type: 'DDoS 洪水攻击', sourceIp: '192.168.1.105', targetIp: '10.0.0.5', timestamp: '2023-10-27 10:30', riskLevel: RiskLevel.HIGH, status: 'Pending', details: '检测到 UDP 协议异常流量峰值，超过基线 500%。' },
  { id: 'TH-1002', type: '勒索软件通信', sourceIp: '45.33.22.11', targetIp: '10.0.0.2', timestamp: '2023-10-27 11:15', riskLevel: RiskLevel.HIGH, status: 'Resolved', details: '识别到 WannaCry 变种的 C2 服务器通信特征。' },
  { id: 'TH-1003', type: '横向端口扫描', sourceIp: '172.16.0.50', targetIp: '10.0.0.8', timestamp: '2023-10-27 12:00', riskLevel: RiskLevel.LOW, status: 'Blocked', details: '内网主机尝试连接多个未授权端口。' },
  { id: 'TH-1004', type: 'SQL 注入尝试', sourceIp: '203.0.113.1', targetIp: '10.0.0.12', timestamp: '2023-10-27 13:45', riskLevel: RiskLevel.MEDIUM, status: 'Pending', details: '针对 /api/v1/login 接口的联合查询注入 Payload。' },
  { id: 'TH-1005', type: 'SSH 暴力破解', sourceIp: '198.51.100.2', targetIp: '10.0.0.5', timestamp: '2023-10-27 14:20', riskLevel: RiskLevel.MEDIUM, status: 'Pending', details: '源 IP 在 1 分钟内发起了 120 次 SSH 认证请求。' },
  { id: 'TH-1006', type: 'XSS 跨站脚本', sourceIp: '114.25.1.5', targetIp: '10.0.0.15', timestamp: '2023-10-27 15:10', riskLevel: RiskLevel.LOW, status: 'Resolved', details: '在评论区检测到存储型 XSS 脚本标签。' },
];

export const MOCK_PROCESSES: SystemProcess[] = [
  { pid: 1024, name: 'dockerd', status: 'running', cpu: 12.5, memory: 256 },
  { pid: 2048, name: 'nginx_worker', status: 'running', cpu: 5.2, memory: 128 },
  { pid: 4096, name: 'miner_x64', status: 'abnormal', cpu: 92.0, memory: 512, abnormalReason: 'CPU 长期占用过高，疑似挖矿脚本' },
  { pid: 8192, name: 'postgresql', status: 'sleeping', cpu: 1.2, memory: 1024 },
  { pid: 5555, name: 'bash_reverse', status: 'abnormal', cpu: 0.1, memory: 12, abnormalReason: '反弹 Shell 特征，连接外部高危 IP' },
  { pid: 101, name: 'systemd', status: 'running', cpu: 0.5, memory: 64 },
];

export const MOCK_ORGS: Organization[] = [
  { id: '1', name: '北京安全运营中心 (SOC)', memberCount: 5, maxMembers: 10, createdAt: '2023-01-15T09:00:00Z', adminPermission: true },
  { id: '2', name: '上海金融防御小组', memberCount: 18, maxMembers: 20, createdAt: '2023-03-10T14:30:00Z', adminPermission: false },
  { id: '3', name: '广州应急响应队', memberCount: 3, maxMembers: 5, createdAt: '2023-06-01T10:00:00Z', adminPermission: false },
];

// ECharts 使用的 GeoJSON 坐标 (经度, 纬度)
// 用于 3D 效果和精确地图定位
export const CHINA_GEO_NODES = [
  { id: 'bj', name: '北京', coord: [116.4074, 39.9042], threats: 156, type: 'APT攻击', details: '检测到针对政务云的持续渗透尝试' },
  { id: 'sh', name: '上海', coord: [121.4737, 31.2304], threats: 89, type: 'SQL注入', details: '金融交易接口遭遇高频注入攻击' },
  { id: 'gz', name: '广州', coord: [113.2644, 23.1291], threats: 45, type: '僵尸网络', details: 'IoT 设备出现大规模异常连接' },
  { id: 'sz', name: '深圳', coord: [114.0579, 22.5431], threats: 78, type: '数据泄露', details: '科技园区内网数据异常外传' },
  { id: 'cd', name: '成都', coord: [104.0668, 30.5728], threats: 67, type: '勒索软件', details: '工控系统检测到加密文件行为' },
  { id: 'wh', name: '武汉', coord: [114.3055, 30.5928], threats: 32, type: '端口扫描', details: '教育科研网段遭遇全端口扫描' },
  { id: 'xa', name: '西安', coord: [108.9398, 34.3416], threats: 28, type: '暴力破解', details: '服务器 SSH 服务遭遇字典攻击' },
  { id: 'hz', name: '杭州', coord: [120.1551, 30.2741], threats: 55, type: 'WebShell', details: '电商促销页面被植入后门' },
  { id: 'hk', name: '香港', coord: [114.1694, 22.3193], threats: 42, type: '钓鱼邮件', details: '针对跨国银行的定向网络钓鱼' },
  { id: 'tw', name: '台北', coord: [121.5654, 25.0330], threats: 35, type: 'DDoS', details: '区域性网络流量异常波动' }
];

// 详细的中国地图轮廓路径 (SVG Path 数据可用于 ECharts 自定义地图，或者直接加载 GeoJSON)
// 这里我们主要依赖 ECharts 加载 GeoJSON，故不再需要复杂的 SVG Path 常量
