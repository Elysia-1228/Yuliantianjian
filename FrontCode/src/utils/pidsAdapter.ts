/**
 * PIDS Adapter - 电影级KAIROS攻击图谱推演引擎
 * 实现复杂攻击树逻辑：分支、多进程协作、文件读写扩散
 * 
 * KAIROS论文规范:
 * - Diamond (菱形): Socket/网络连接节点
 * - Rect (矩形): Process/进程节点
 * - Ellipse (椭圆): File/文件节点
 */

export interface AlertData {
  id: number | string;
  sourceIp?: string;
  targetIp?: string;
  attackType?: string;
  severity?: string;
  payload?: string;
  detectedTime?: string;
  maliciousIp?: string;
  malwareOrigin?: string;
  threatType?: string;
}

export interface G6Node {
  id: string;
  label: string;
  type: 'rect' | 'ellipse' | 'diamond';
  nodeType?: 'process' | 'file' | 'socket';
  state?: 'benign' | 'compromised' | 'malicious' | 'critical';
  style?: Record<string, any>;
  size?: number | [number, number];
}

export interface G6Edge {
  source: string;
  target: string;
  label?: string;
  style?: Record<string, any>;
}

export interface G6GraphData {
  nodes: G6Node[];
  edges: G6Edge[];
}

// 确定性PID生成：基于服务名的哈希值
const deterministicPID = (serviceName: string): number => {
  let hash = 0;
  for (let i = 0; i < serviceName.length; i++) {
    hash = ((hash << 5) - hash) + serviceName.charCodeAt(i);
    hash = hash & hash;
  }
  return Math.abs(hash % 20000) + 1000;
};

/**
 * 核心函数：电影级攻击树推演引擎
 * 根据攻击类型生成带有分支和上下文的复杂拓扑结构
 */
export function alertToGraphData(alert: AlertData): G6GraphData {
  const { sourceIp, targetIp, attackType, maliciousIp, threatType } = alert;
  const realSourceIp = sourceIp || maliciousIp || '未知来源';
  const realTargetIp = targetIp || '192.168.1.100';
  const attackTypeStr = (attackType || threatType || '').toLowerCase();
  
  let nodes: G6Node[] = [];
  let edges: G6Edge[] = [];

  // 基础节点：攻击者与入口
  nodes.push(
    { 
      id: 'attacker', 
      type: 'diamond', 
      label: `${realSourceIp}\n(Attacker)`, 
      style: { fill: '#3a0000', stroke: '#ff4d4f', lineWidth: 3, shadowBlur: 15, shadowColor: '#ff4d4f' }, 
      state: 'malicious',
      size: 70
    },
    { 
      id: 'firewall', 
      type: 'rect', 
      label: `Firewall\n(Allow)`, 
      style: { fill: '#162438', stroke: '#00e5ff', lineWidth: 2, lineDash: [4,2] }, 
      state: 'benign',
      size: [100, 45]
    }
  );
  edges.push({ source: 'attacker', target: 'firewall', label: 'TCP/SYN', style: { stroke: '#ff4d4f', lineWidth: 2 } });

  // 根据攻击类型生成复杂的"攻击树"
  if (attackTypeStr.includes('sql') || attackTypeStr.includes('injection')) {
    // === SQL注入场景 (复杂分支) ===
    nodes.push(
      { id: 'nginx', type: 'rect', label: `nginx\n(PID: ${deterministicPID('nginx')})`, style: { fill: '#162438', stroke: '#ff4d4f', lineWidth: 2 }, state: 'compromised', size: [110, 45] },
      { id: 'access_log', type: 'ellipse', label: '/var/log/nginx/\naccess.log', style: { fill: '#162438', stroke: '#5c6b7f', lineWidth: 1.5 }, state: 'benign', size: [130, 50] }
    );
    edges.push(
      { source: 'firewall', target: 'nginx', label: 'Fwd: 80', style: { stroke: '#00e5ff', lineWidth: 2 } },
      { source: 'nginx', target: 'access_log', label: 'Write', style: { stroke: '#5c6b7f', lineWidth: 1.5 } }
    );

    // 数据库层
    nodes.push(
      { id: 'mysqld', type: 'rect', label: `mysqld\n(PID: ${deterministicPID('mysqld')})`, style: { fill: '#3a0000', stroke: '#ff4d4f', lineWidth: 3, shadowBlur: 20, shadowColor: '#f00' }, state: 'critical', size: [120, 50] },
      { id: 'users_ibd', type: 'ellipse', label: 'users.ibd\n(Sensitive)', style: { fill: '#3a0000', stroke: '#ff4d4f', lineWidth: 2 }, state: 'critical', size: [120, 50] },
      { id: 'schema_frm', type: 'ellipse', label: 'schema.frm', style: { fill: '#162438', stroke: '#5c6b7f', lineWidth: 1.5 }, state: 'benign', size: [110, 45] }
    );
    edges.push(
      { source: 'nginx', target: 'mysqld', label: 'SQL Query', style: { stroke: '#ff4d4f', lineWidth: 2.5 } },
      { source: 'mysqld', target: 'users_ibd', label: 'Full Scan', style: { stroke: '#ff4d4f', lineWidth: 2 } },
      { source: 'mysqld', target: 'schema_frm', label: 'Read', style: { stroke: '#5c6b7f', lineWidth: 1.5 } }
    );

    // 提权/落马尝试
    nodes.push(
      { id: 'cmd_sh', type: 'rect', label: `sh -c\n(PID: ${deterministicPID('sh')})`, style: { fill: '#3a0000', stroke: '#ff4d4f', lineWidth: 2 }, state: 'malicious', size: [100, 45] },
      { id: 'backdoor', type: 'ellipse', label: '/tmp/kworker_u', style: { fill: '#3a0000', stroke: '#ff4d4f', lineWidth: 2 }, state: 'malicious', size: [130, 50] }
    );
    edges.push(
      { source: 'mysqld', target: 'cmd_sh', label: 'UDF::Exec', style: { stroke: '#ff4d4f', lineWidth: 2, lineDash: [5,3] } },
      { source: 'cmd_sh', target: 'backdoor', label: 'Write', style: { stroke: '#ff4d4f', lineWidth: 2 } }
    );

    // 背景噪音节点（良性邻居）- 增加视觉密度
    nodes.push(
      { id: 'mysql_conf', type: 'ellipse', label: 'my.cnf\n(Config)', style: { fill: '#0a1929', stroke: '#00e5ff', lineWidth: 1, opacity: 0.5 }, state: 'benign', size: [100, 40] },
      { id: 'error_log', type: 'ellipse', label: 'error.log', style: { fill: '#0a1929', stroke: '#00e5ff', lineWidth: 1, opacity: 0.5 }, state: 'benign', size: [90, 40] }
    );
    edges.push(
      { source: 'mysqld', target: 'mysql_conf', label: 'Read', style: { stroke: '#00e5ff', lineWidth: 1, lineDash: [2,2], opacity: 0.4 } },
      { source: 'nginx', target: 'error_log', label: 'Write', style: { stroke: '#00e5ff', lineWidth: 1, lineDash: [2,2], opacity: 0.4 } }
    );

  } else if (attackTypeStr.includes('xss') || attackTypeStr.includes('web') || attackTypeStr.includes('script')) {
    // === WebShell / RCE场景 ===
    nodes.push(
      { id: 'tomcat', type: 'rect', label: `java (Tomcat)\n(PID: ${deterministicPID('tomcat')})`, style: { fill: '#3a0000', stroke: '#ff4d4f', lineWidth: 2 }, state: 'compromised', size: [130, 50] },
      { id: 'jsp_file', type: 'ellipse', label: 'upload.jsp', style: { fill: '#3a0000', stroke: '#ff4d4f', lineWidth: 2 }, state: 'malicious', size: [110, 45] },
      { id: 'bash', type: 'rect', label: `bash\n(PID: ${deterministicPID('bash')})`, style: { fill: '#3a0000', stroke: '#ff4d4f', lineWidth: 3, shadowBlur: 15 }, state: 'critical', size: [100, 45] },
      { id: 'curl', type: 'rect', label: `curl`, style: { fill: '#162438', stroke: '#ff4d4f', lineWidth: 2 }, state: 'malicious', size: [80, 40] },
      { id: 'external_c2', type: 'diamond', label: '104.21.xx.xx\n(C2 Server)', style: { fill: '#3a0000', stroke: '#ff4d4f', lineWidth: 3, shadowBlur: 20, shadowColor: '#f00' }, state: 'malicious', size: 70 }
    );
    edges.push(
      { source: 'firewall', target: 'tomcat', label: 'HTTP POST', style: { stroke: '#ff4d4f', lineWidth: 2 } },
      { source: 'tomcat', target: 'jsp_file', label: 'Write', style: { stroke: '#ff4d4f', lineWidth: 2 } },
      { source: 'tomcat', target: 'bash', label: 'Exec', style: { stroke: '#ff4d4f', lineWidth: 2.5 } },
      { source: 'bash', target: 'curl', label: 'Spawn', style: { stroke: '#ff4d4f', lineWidth: 2 } },
      { source: 'curl', target: 'external_c2', label: 'Connect', style: { stroke: '#ff4d4f', lineWidth: 2.5, lineDash: [5,3] } }
    );

    // 背景噪音节点（良性邻居）
    nodes.push(
      { id: 'catalina_out', type: 'ellipse', label: 'catalina.out', style: { fill: '#0a1929', stroke: '#00e5ff', lineWidth: 1, opacity: 0.5 }, state: 'benign', size: [100, 40] },
      { id: 'bashrc', type: 'ellipse', label: '.bashrc', style: { fill: '#0a1929', stroke: '#00e5ff', lineWidth: 1, opacity: 0.5 }, state: 'benign', size: [80, 40] }
    );
    edges.push(
      { source: 'tomcat', target: 'catalina_out', label: 'Write', style: { stroke: '#00e5ff', lineWidth: 1, lineDash: [2,2], opacity: 0.4 } },
      { source: 'bash', target: 'bashrc', label: 'Read', style: { stroke: '#00e5ff', lineWidth: 1, lineDash: [2,2], opacity: 0.4 } }
    );

  } else {
    // === 默认场景：暴力破解/通用攻击 ===
    nodes.push(
      { id: 'sshd', type: 'rect', label: `sshd\n(PID: ${deterministicPID('sshd')})`, style: { fill: '#3a0000', stroke: '#ff4d4f', lineWidth: 2 }, state: 'compromised', size: [100, 45] },
      { id: 'auth_log', type: 'ellipse', label: '/var/log/auth.log', style: { fill: '#162438', stroke: '#5c6b7f', lineWidth: 1.5 }, state: 'benign', size: [130, 50] },
      { id: 'root_bash', type: 'rect', label: `bash (root)\n(PID: ${deterministicPID('bash_root')})`, style: { fill: '#3a0000', stroke: '#ff4d4f', lineWidth: 3, shadowBlur: 20, shadowColor: '#f00' }, state: 'critical', size: [120, 50] },
      { id: 'history', type: 'ellipse', label: '.bash_history', style: { fill: '#162438', stroke: '#ff4d4f', lineWidth: 2 }, state: 'malicious', size: [120, 50] }
    );
    edges.push(
      { source: 'firewall', target: 'sshd', label: 'Port 22', style: { stroke: '#00e5ff', lineWidth: 2 } },
      { source: 'sshd', target: 'auth_log', label: 'Write (Fail)', style: { stroke: '#5c6b7f', lineWidth: 1.5 } },
      { source: 'sshd', target: 'root_bash', label: 'Spawn (Success)', style: { stroke: '#ff4d4f', lineWidth: 2.5 } },
      { source: 'root_bash', target: 'history', label: 'Truncate', style: { stroke: '#ff4d4f', lineWidth: 2 } }
    );

    // 背景噪音节点（良性邻居）
    nodes.push(
      { id: 'sshd_config', type: 'ellipse', label: 'sshd_config', style: { fill: '#0a1929', stroke: '#00e5ff', lineWidth: 1, opacity: 0.5 }, state: 'benign', size: [100, 40] },
      { id: 'profile', type: 'ellipse', label: '.profile', style: { fill: '#0a1929', stroke: '#00e5ff', lineWidth: 1, opacity: 0.5 }, state: 'benign', size: [80, 40] }
    );
    edges.push(
      { source: 'sshd', target: 'sshd_config', label: 'Read', style: { stroke: '#00e5ff', lineWidth: 1, lineDash: [2,2], opacity: 0.4 } },
      { source: 'root_bash', target: 'profile', label: 'Load', style: { stroke: '#00e5ff', lineWidth: 1, lineDash: [2,2], opacity: 0.4 } }
    );
  }

  return { nodes, edges };
}

/**
 * 生成聚合风险球数据
 */
export function generateRiskBallData(alerts: AlertData[]): G6GraphData {
  const highRiskCount = alerts.filter(a => 
    a.severity === 'high' || a.severity === 'critical' || a.severity === '高危'
  ).length;
  
  const mediumRiskCount = alerts.filter(a => 
    a.severity === 'medium' || a.severity === '中危'
  ).length;

  return {
    nodes: [
      {
        id: 'risk_group',
        label: `风险聚合\n${alerts.length} 事件`,
        type: 'diamond',
        nodeType: 'socket',
        style: {
          fill: highRiskCount > 0 ? 'rgba(255, 77, 79, 0.8)' : 'rgba(255, 193, 7, 0.8)',
          stroke: highRiskCount > 0 ? '#ff4d4f' : '#ffc107',
          lineWidth: 3,
          shadowColor: highRiskCount > 0 ? '#ff4d4f' : '#ffc107',
          shadowBlur: 20,
        },
      },
    ],
    edges: [],
  };
}

/**
 * 合并多个告警为完整攻击图谱
 */
export function mergeAlertsToGraph(alerts: AlertData[]): G6GraphData {
  const allNodes: G6Node[] = [];
  const allEdges: G6Edge[] = [];
  const nodeIdSet = new Set<string>();

  alerts.forEach((alert, alertIdx) => {
    const graphData = alertToGraphData(alert);
    
    // 为每个告警的节点添加唯一前缀
    graphData.nodes.forEach(node => {
      const newId = `${alertIdx}_${node.id}`;
      if (!nodeIdSet.has(newId)) {
        nodeIdSet.add(newId);
        allNodes.push({
          ...node,
          id: newId,
        });
      }
    });

    graphData.edges.forEach(edge => {
      allEdges.push({
        ...edge,
        source: `${alertIdx}_${edge.source}`,
        target: `${alertIdx}_${edge.target}`,
      });
    });
  });

  return { nodes: allNodes, edges: allEdges };
}

export default {
  alertToGraphData,
  generateRiskBallData,
  mergeAlertsToGraph,
};
