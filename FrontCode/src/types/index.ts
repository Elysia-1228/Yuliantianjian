export enum RiskLevel {
  HIGH = 'High',
  MEDIUM = 'Medium',
  LOW = 'Low'
}

export interface ThreatEvent {
  id: string;
  type: string;
  sourceIp: string;
  targetIp: string;
  timestamp: string;
  riskLevel: RiskLevel;
  status: 'Pending' | 'Blocked' | 'Resolved';
  details?: string;
}

export interface HostConfig {
  id: string;
  name: string;
  ips: string[];
  frequency: number; // minutes
  status: 'Idle' | 'Collecting' | 'Error';
  lastCollection?: string;
  errorMessage?: string;
}

export interface SystemProcess {
  pid: number;
  name: string;
  status: 'running' | 'sleeping' | 'stopped' | 'abnormal';
  cpu: number;
  memory: number;
  abnormalReason?: string;
}

export interface HostCollectionConfig {
  id: number;
  hostIp: string;
  collectFreq: number;
  collectStatus: number; // 1: Running, 2: Paused, 3: Error, 0: Stopped
  createTime?: string;
  updateTime?: string;
}

export interface Organization {
  id: string;
  name: string;
  memberCount: number;
  maxMembers: number;
  createdAt: string;
  adminPermission: boolean;
}

export interface Report {
  id: string;
  type: 'Daily' | 'Weekly' | 'Custom';
  dateRange: string;
  status: 'Generating' | 'Completed' | 'Failed';
  url?: string;
  failReason?: string;
}

export interface ChartData {
  time: string;
  value: number;
  value2?: number;
}