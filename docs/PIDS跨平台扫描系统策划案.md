# PIDS 跨平台入侵检测与溯源系统 - 技术策划案

## 一、需求背景

### 1.1 当前问题
- **开发环境限制**：开发阶段在Windows主机上进行，但系统只能扫描远程Linux服务器
- **测试效率低**：每次测试需要部署到服务器才能验证功能
- **场景单一**：无法灵活切换扫描目标（本地/远程、Windows/Linux）

### 1.2 核心需求
1. **开发阶段**：直接扫描Windows本地主机的异常流量和系统状态
2. **部署阶段**：支持扫描Linux服务器的生产环境数据
3. **灵活切换**：前端界面可选择扫描目标（本地/远程、操作系统类型）

---

## 二、技术架构设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                    前端 React 应用                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  PIDS 控制面板                                        │   │
│  │  - 扫描目标选择器 (本地/远程)                         │   │
│  │  - 操作系统选择器 (Windows/Linux)                     │   │
│  │  - 扫描类型选择 (流量/进程/文件/注册表)               │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            ↓ HTTP/WebSocket
┌─────────────────────────────────────────────────────────────┐
│                   后端 API 服务层                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  路由分发器                                           │   │
│  │  - /api/pids/scan/local   → 本地扫描                 │   │
│  │  - /api/pids/scan/remote  → 远程扫描                 │   │
│  │  - /api/pids/agents       → Agent管理                │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            ↓
        ┌───────────────────┴───────────────────┐
        ↓                                       ↓
┌──────────────────┐                  ┌──────────────────┐
│  本地扫描 Agent   │                  │  远程扫描 Agent   │
│  (Windows)       │                  │  (Linux)         │
├──────────────────┤                  ├──────────────────┤
│ • WinPcap抓包    │                  │ • libpcap抓包    │
│ • 进程监控       │                  │ • 进程监控       │
│ • 注册表扫描     │                  │ • 文件监控       │
│ • 文件监控       │                  │ • 系统日志       │
│ • 事件日志       │                  │ • iptables规则   │
└──────────────────┘                  └──────────────────┘
```

### 2.2 核心组件

#### 2.2.1 前端扫描控制器
```typescript
interface ScanTarget {
  type: 'local' | 'remote';
  os: 'windows' | 'linux';
  host?: string;  // 远程主机IP
  port?: number;  // 远程主机端口
}

interface ScanConfig {
  target: ScanTarget;
  scanTypes: ('traffic' | 'process' | 'file' | 'registry')[];
  duration: number;  // 扫描时长（秒）
  filters?: {
    ports?: number[];
    protocols?: string[];
    processes?: string[];
  };
}
```

#### 2.2.2 本地扫描Agent（Windows）
- **技术栈**：Node.js + Native Addons (C++)
- **功能模块**：
  - 流量抓包：WinPcap/Npcap
  - 进程监控：Windows API (CreateToolhelp32Snapshot)
  - 注册表扫描：RegOpenKeyEx, RegQueryValueEx
  - 文件监控：ReadDirectoryChangesW
  - 事件日志：Windows Event Log API

#### 2.2.3 远程扫描Agent（Linux）
- **技术栈**：Python/Go + 系统调用
- **功能模块**：
  - 流量抓包：libpcap/tcpdump
  - 进程监控：/proc文件系统
  - 文件监控：inotify
  - 系统日志：syslog/journalctl
  - 防火墙规则：iptables

---

## 三、实现方案

### 3.1 阶段一：本地Windows扫描（开发优先）

#### 3.1.1 Windows流量抓包模块
```javascript
// backend/agents/windows/trafficCapture.js
const pcap = require('pcap');

class WindowsTrafficCapture {
  constructor() {
    this.session = null;
    this.packets = [];
  }

  start(config) {
    // 获取网络接口
    const device = pcap.findalldevs()[0];
    
    // 创建抓包会话
    this.session = pcap.createSession(device.name, {
      filter: config.filter || 'tcp or udp',
      buffer_size: 10 * 1024 * 1024
    });

    this.session.on('packet', (rawPacket) => {
      const packet = pcap.decode.packet(rawPacket);
      this.analyzePacket(packet);
    });
  }

  analyzePacket(packet) {
    // 检测异常流量特征
    const anomaly = this.detectAnomaly(packet);
    if (anomaly) {
      this.packets.push({
        timestamp: new Date(),
        srcIp: packet.payload.saddr,
        dstIp: packet.payload.daddr,
        protocol: packet.payload.protocol,
        anomalyType: anomaly.type,
        severity: anomaly.severity
      });
    }
  }

  detectAnomaly(packet) {
    // SQL注入特征检测
    // DDoS流量检测
    // 端口扫描检测
    // 返回异常类型和严重程度
  }

  stop() {
    if (this.session) {
      this.session.close();
    }
    return this.packets;
  }
}
```

#### 3.1.2 Windows进程监控模块
```javascript
// backend/agents/windows/processMonitor.js
const { exec } = require('child_process');
const os = require('os');

class WindowsProcessMonitor {
  async getProcessList() {
    return new Promise((resolve, reject) => {
      exec('wmic process get ProcessId,Name,CommandLine,ExecutablePath /format:csv', 
        (error, stdout, stderr) => {
          if (error) return reject(error);
          
          const processes = this.parseWmicOutput(stdout);
          const suspicious = this.detectSuspiciousProcesses(processes);
          resolve(suspicious);
        }
      );
    });
  }

  detectSuspiciousProcesses(processes) {
    const suspicious = [];
    
    processes.forEach(proc => {
      // 检测无签名进程
      // 检测高权限进程
      // 检测隐藏进程
      // 检测注入行为
      if (this.isSuspicious(proc)) {
        suspicious.push({
          pid: proc.ProcessId,
          name: proc.Name,
          path: proc.ExecutablePath,
          reason: '未知来源进程',
          severity: 'high'
        });
      }
    });
    
    return suspicious;
  }
}
```

#### 3.1.3 Windows注册表扫描模块
```javascript
// backend/agents/windows/registryScanner.js
const regedit = require('regedit');

class WindowsRegistryScanner {
  async scanAutoRun() {
    const keys = [
      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
    ];

    const results = await regedit.list(keys);
    return this.analyzeAutoRun(results);
  }

  analyzeAutoRun(results) {
    const suspicious = [];
    
    for (const [key, value] of Object.entries(results)) {
      value.values.forEach(entry => {
        // 检测可疑启动项
        if (this.isSuspiciousStartup(entry)) {
          suspicious.push({
            key: key,
            name: entry.name,
            value: entry.value,
            type: 'AutoRun',
            severity: 'medium'
          });
        }
      });
    }
    
    return suspicious;
  }
}
```

### 3.2 阶段二：远程Linux扫描

#### 3.2.1 SSH连接管理
```python
# backend/agents/linux/ssh_manager.py
import paramiko

class LinuxSSHManager:
    def __init__(self, host, port, username, password=None, key_file=None):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if key_file:
            self.client.connect(host, port, username, key_filename=key_file)
        else:
            self.client.connect(host, port, username, password)
    
    def execute_command(self, command):
        stdin, stdout, stderr = self.client.exec_command(command)
        return stdout.read().decode(), stderr.read().decode()
    
    def close(self):
        self.client.close()
```

#### 3.2.2 Linux流量抓包
```python
# backend/agents/linux/traffic_capture.py
class LinuxTrafficCapture:
    def __init__(self, ssh_manager):
        self.ssh = ssh_manager
    
    def start_capture(self, interface='eth0', duration=60):
        # 在远程服务器上启动tcpdump
        command = f"timeout {duration} tcpdump -i {interface} -w /tmp/capture.pcap"
        self.ssh.execute_command(command)
    
    def analyze_capture(self):
        # 下载pcap文件并分析
        sftp = self.ssh.client.open_sftp()
        sftp.get('/tmp/capture.pcap', './temp_capture.pcap')
        sftp.close()
        
        # 使用scapy分析
        from scapy.all import rdpcap
        packets = rdpcap('./temp_capture.pcap')
        return self.detect_anomalies(packets)
```

### 3.3 阶段三：统一API接口

#### 3.3.1 后端路由设计
```javascript
// backend/routes/pids.js
const express = require('express');
const router = express.Router();
const WindowsAgent = require('../agents/windows');
const LinuxAgent = require('../agents/linux');

// 启动扫描
router.post('/scan/start', async (req, res) => {
  const { target, scanTypes, duration } = req.body;
  
  let agent;
  if (target.type === 'local' && target.os === 'windows') {
    agent = new WindowsAgent();
  } else if (target.type === 'remote' && target.os === 'linux') {
    agent = new LinuxAgent(target.host, target.port, target.credentials);
  }
  
  const scanId = generateScanId();
  
  // 异步执行扫描
  agent.startScan(scanTypes, duration).then(results => {
    // 保存结果到数据库
    saveScanResults(scanId, results);
  });
  
  res.json({ scanId, status: 'started' });
});

// 获取扫描结果
router.get('/scan/:scanId/results', async (req, res) => {
  const results = await getScanResults(req.params.scanId);
  res.json(results);
});

// 实时扫描流（WebSocket）
router.ws('/scan/:scanId/stream', (ws, req) => {
  const scanId = req.params.scanId;
  
  // 订阅扫描事件
  scanEventEmitter.on(`scan:${scanId}:event`, (event) => {
    ws.send(JSON.stringify(event));
  });
});
```

### 3.4 阶段四：前端界面实现

#### 3.4.1 扫描目标选择器
```typescript
// FrontCode/src/components/PIDSScanControl.tsx
import React, { useState } from 'react';

interface ScanControlProps {
  onStartScan: (config: ScanConfig) => void;
}

const PIDSScanControl: React.FC<ScanControlProps> = ({ onStartScan }) => {
  const [targetType, setTargetType] = useState<'local' | 'remote'>('local');
  const [osType, setOsType] = useState<'windows' | 'linux'>('windows');
  const [scanTypes, setScanTypes] = useState<string[]>(['traffic']);
  
  return (
    <div className="bg-slate-900 rounded-xl p-6 border border-cyan-500/20">
      {/* 扫描目标选择 */}
      <div className="mb-6">
        <h3 className="text-cyan-400 font-bold mb-3">扫描目标</h3>
        <div className="flex gap-4">
          <button
            onClick={() => setTargetType('local')}
            className={`flex-1 py-3 rounded-lg border-2 transition-all ${
              targetType === 'local'
                ? 'bg-cyan-500/20 border-cyan-400 text-cyan-400'
                : 'border-slate-700 text-slate-400 hover:border-cyan-500/50'
            }`}
          >
            <Monitor className="w-6 h-6 mx-auto mb-1" />
            本地主机
          </button>
          <button
            onClick={() => setTargetType('remote')}
            className={`flex-1 py-3 rounded-lg border-2 transition-all ${
              targetType === 'remote'
                ? 'bg-purple-500/20 border-purple-400 text-purple-400'
                : 'border-slate-700 text-slate-400 hover:border-purple-500/50'
            }`}
          >
            <Server className="w-6 h-6 mx-auto mb-1" />
            远程服务器
          </button>
        </div>
      </div>

      {/* 操作系统选择 */}
      <div className="mb-6">
        <h3 className="text-cyan-400 font-bold mb-3">操作系统</h3>
        <div className="flex gap-4">
          <button
            onClick={() => setOsType('windows')}
            className={`flex-1 py-2 rounded-lg ${
              osType === 'windows'
                ? 'bg-blue-500/20 text-blue-400 border border-blue-400'
                : 'bg-slate-800 text-slate-400'
            }`}
          >
            Windows
          </button>
          <button
            onClick={() => setOsType('linux')}
            className={`flex-1 py-2 rounded-lg ${
              osType === 'linux'
                ? 'bg-green-500/20 text-green-400 border border-green-400'
                : 'bg-slate-800 text-slate-400'
            }`}
          >
            Linux
          </button>
        </div>
      </div>

      {/* 扫描类型选择 */}
      <div className="mb-6">
        <h3 className="text-cyan-400 font-bold mb-3">扫描类型</h3>
        <div className="grid grid-cols-2 gap-3">
          {[
            { id: 'traffic', label: '网络流量', icon: Network },
            { id: 'process', label: '进程监控', icon: Cpu },
            { id: 'file', label: '文件监控', icon: FileSearch },
            { id: 'registry', label: '注册表', icon: Database, disabled: osType !== 'windows' }
          ].map(type => (
            <label key={type.id} className={`flex items-center gap-2 p-3 rounded-lg border cursor-pointer ${
              scanTypes.includes(type.id)
                ? 'bg-cyan-500/10 border-cyan-400'
                : 'border-slate-700 hover:border-cyan-500/50'
            } ${type.disabled ? 'opacity-50 cursor-not-allowed' : ''}`}>
              <input
                type="checkbox"
                checked={scanTypes.includes(type.id)}
                onChange={(e) => {
                  if (e.target.checked) {
                    setScanTypes([...scanTypes, type.id]);
                  } else {
                    setScanTypes(scanTypes.filter(t => t !== type.id));
                  }
                }}
                disabled={type.disabled}
                className="hidden"
              />
              <type.icon size={20} className="text-cyan-400" />
              <span className="text-sm">{type.label}</span>
            </label>
          ))}
        </div>
      </div>

      {/* 远程主机配置 */}
      {targetType === 'remote' && (
        <div className="mb-6 p-4 bg-slate-800/50 rounded-lg border border-slate-700">
          <h4 className="text-sm text-slate-400 mb-3">远程主机配置</h4>
          <input
            type="text"
            placeholder="主机IP地址"
            className="w-full mb-2 px-3 py-2 bg-slate-900 border border-slate-700 rounded text-white"
          />
          <input
            type="number"
            placeholder="SSH端口 (默认22)"
            className="w-full mb-2 px-3 py-2 bg-slate-900 border border-slate-700 rounded text-white"
          />
          <input
            type="text"
            placeholder="用户名"
            className="w-full mb-2 px-3 py-2 bg-slate-900 border border-slate-700 rounded text-white"
          />
          <input
            type="password"
            placeholder="密码或密钥路径"
            className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded text-white"
          />
        </div>
      )}

      {/* 启动按钮 */}
      <button
        onClick={() => onStartScan({
          target: { type: targetType, os: osType },
          scanTypes,
          duration: 60
        })}
        className="w-full py-4 bg-gradient-to-r from-cyan-500 to-purple-500 rounded-lg text-white font-bold text-lg hover:shadow-lg hover:shadow-cyan-500/50 transition-all"
      >
        <Zap className="inline-block mr-2" />
        开始扫描
      </button>
    </div>
  );
};
```

---

## 四、技术难点与解决方案

### 4.1 Windows权限问题
**问题**：抓包和进程监控需要管理员权限

**解决方案**：
1. 提供安装脚本，自动请求管理员权限
2. 使用Windows服务方式运行Agent
3. 前端提示用户以管理员身份运行

### 4.2 跨平台兼容性
**问题**：Windows和Linux系统API差异大

**解决方案**：
1. 使用适配器模式，统一接口
2. 每个平台独立实现Agent
3. 后端API层屏蔽平台差异

### 4.3 实时数据传输
**问题**：扫描过程需要实时反馈

**解决方案**：
1. 使用WebSocket建立长连接
2. 前端显示实时扫描进度和发现
3. 支持暂停/恢复/停止扫描

### 4.4 性能优化
**问题**：大量数据包分析可能导致性能问题

**解决方案**：
1. 使用流式处理，避免内存溢出
2. 异步分析，不阻塞主线程
3. 可配置采样率，降低数据量
4. 使用Worker线程并行处理

---

## 五、开发计划

### 5.1 第一周：本地Windows扫描
- [ ] 实现Windows流量抓包模块
- [ ] 实现Windows进程监控模块
- [ ] 实现Windows注册表扫描模块
- [ ] 前端扫描控制界面

### 5.2 第二周：结果展示与分析
- [ ] 实时扫描结果展示
- [ ] 异常流量可视化
- [ ] 威胁等级评估
- [ ] 溯源图谱生成

### 5.3 第三周：远程Linux扫描
- [ ] SSH连接管理
- [ ] Linux流量抓包
- [ ] Linux进程监控
- [ ] 统一API接口

### 5.4 第四周：优化与测试
- [ ] 性能优化
- [ ] 错误处理
- [ ] 单元测试
- [ ] 集成测试

---

## 六、部署方案

### 6.1 开发环境（Windows）
```bash
# 安装依赖
npm install pcap regedit node-windows

# 以管理员权限启动
npm run dev:admin

# 前端访问
http://localhost:3002
```

### 6.2 生产环境（Linux）
```bash
# 安装系统依赖
sudo apt-get install libpcap-dev tcpdump

# 部署后端
pm2 start backend/server.js

# 部署前端
npm run build
nginx -c nginx.conf
```

---

## 七、安全考虑

### 7.1 权限控制
- 扫描操作需要身份验证
- 敏感数据加密传输
- 审计日志记录所有操作

### 7.2 数据隐私
- 不存储完整数据包内容
- 只保留异常特征和元数据
- 支持数据脱敏

### 7.3 防护措施
- 限制扫描频率，防止滥用
- 监控Agent资源占用
- 异常自动停止扫描

---

## 八、总结

这套方案可以实现：
✅ **开发阶段**：直接在Windows本地扫描，快速验证功能
✅ **部署阶段**：无缝切换到Linux服务器扫描
✅ **灵活配置**：前端界面选择扫描目标和类型
✅ **统一体验**：无论本地还是远程，界面和流程一致

**核心优势**：
1. 提高开发效率，无需频繁部署
2. 支持多平台，适应不同场景
3. 架构清晰，易于扩展维护
4. 用户体验好，操作简单直观
