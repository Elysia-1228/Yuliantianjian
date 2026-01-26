/**
 * alertAggregator.ts - 告警数据聚合工具
 * 用于将海量告警（700+）按IP聚合，实现高密度展示
 */

export interface AlertData {
  id?: number | string;
  maliciousIp?: string;
  sourceIp?: string;
  targetIp?: string;
  threatType?: string;
  attackType?: string;
  severity?: string;
  detectedTime?: string;
  eventTime?: string;
  malwareOrigin?: string;
  [key: string]: any;
}

export interface AggregatedAlert {
  sourceIp: string;
  count: number;
  threatTypes: string[];
  primaryThreatType: string;
  severity: string;
  latestTime: string;
  earliestTime: string;
  alerts: AlertData[];
  targetIps: string[];
}

/**
 * 按source_ip聚合告警数据
 * @param alerts 原始告警数组
 * @returns 聚合后的告警数组
 */
export function aggregateAlertsByIP(alerts: AlertData[]): AggregatedAlert[] {
  const aggregationMap = new Map<string, AggregatedAlert>();

  alerts.forEach(alert => {
    const sourceIp = alert.maliciousIp || alert.sourceIp || 'Unknown';
    
    if (!aggregationMap.has(sourceIp)) {
      aggregationMap.set(sourceIp, {
        sourceIp,
        count: 0,
        threatTypes: [],
        primaryThreatType: '',
        severity: 'low',
        latestTime: '',
        earliestTime: '',
        alerts: [],
        targetIps: [],
      });
    }

    const agg = aggregationMap.get(sourceIp)!;
    agg.count++;
    agg.alerts.push(alert);

    // 收集威胁类型
    const threatType = alert.threatType || alert.attackType || '未知威胁';
    if (!agg.threatTypes.includes(threatType)) {
      agg.threatTypes.push(threatType);
    }

    // 收集目标IP
    if (alert.targetIp && !agg.targetIps.includes(alert.targetIp)) {
      agg.targetIps.push(alert.targetIp);
    }

    // 更新时间范围
    const currentTime = alert.detectedTime || alert.eventTime || new Date().toISOString();
    if (!agg.latestTime || currentTime > agg.latestTime) {
      agg.latestTime = currentTime;
    }
    if (!agg.earliestTime || currentTime < agg.earliestTime) {
      agg.earliestTime = currentTime;
    }

    // 更新严重程度（取最高级别）
    const severityLevel = getSeverityLevel(alert.severity || 'low');
    const currentSeverityLevel = getSeverityLevel(agg.severity);
    if (severityLevel > currentSeverityLevel) {
      agg.severity = alert.severity || 'low';
    }
  });

  // 确定主要威胁类型（出现次数最多的）
  aggregationMap.forEach(agg => {
    const typeCount = new Map<string, number>();
    agg.alerts.forEach(alert => {
      const type = alert.threatType || alert.attackType || '未知威胁';
      typeCount.set(type, (typeCount.get(type) || 0) + 1);
    });

    let maxCount = 0;
    let primaryType = agg.threatTypes[0] || '未知威胁';
    typeCount.forEach((count, type) => {
      if (count > maxCount) {
        maxCount = count;
        primaryType = type;
      }
    });
    agg.primaryThreatType = primaryType;
  });

  // 转换为数组并按count降序排序
  return Array.from(aggregationMap.values()).sort((a, b) => b.count - a.count);
}

/**
 * 获取严重程度级别（用于比较）
 */
function getSeverityLevel(severity: string): number {
  const normalized = severity.toLowerCase();
  if (normalized === 'critical' || normalized === '严重' || normalized === '高危') return 4;
  if (normalized === 'high' || normalized === '高') return 3;
  if (normalized === 'medium' || normalized === '中' || normalized === '中危') return 2;
  if (normalized === 'low' || normalized === '低' || normalized === '低危') return 1;
  return 0;
}

/**
 * 搜索过滤聚合数据
 */
export function filterAggregatedAlerts(
  alerts: AggregatedAlert[],
  searchTerm: string
): AggregatedAlert[] {
  if (!searchTerm.trim()) return alerts;

  const term = searchTerm.toLowerCase();
  return alerts.filter(agg => 
    agg.sourceIp.toLowerCase().includes(term) ||
    agg.primaryThreatType.toLowerCase().includes(term) ||
    agg.threatTypes.some(t => t.toLowerCase().includes(term))
  );
}

/**
 * 获取Top N攻击者
 */
export function getTopAttackers(alerts: AggregatedAlert[], topN: number = 5): AggregatedAlert[] {
  return alerts.slice(0, topN);
}

/**
 * 计算威胁雷达数据
 */
export interface ThreatRadarData {
  attackFrequency: number;  // 攻击频率 (0-100)
  destructiveness: number;  // 破坏力 (0-100)
  stealth: number;          // 隐蔽性 (0-100)
  assetImportance: number;  // 资产重要性 (0-100)
  confidence: number;       // 置信度 (0-100)
}

export function calculateThreatRadar(aggregated: AggregatedAlert[]): ThreatRadarData {
  if (aggregated.length === 0) {
    return {
      attackFrequency: 0,
      destructiveness: 0,
      stealth: 0,
      assetImportance: 0,
      confidence: 0,
    };
  }

  const totalAlerts = aggregated.reduce((sum, agg) => sum + agg.count, 0);
  const maxCount = Math.max(...aggregated.map(agg => agg.count));
  const criticalCount = aggregated.filter(agg => 
    agg.severity === 'critical' || agg.severity === '严重' || agg.severity === '高危'
  ).length;

  return {
    attackFrequency: Math.min(100, (totalAlerts / 10) * 10), // 每10个告警增加10分
    destructiveness: Math.min(100, (criticalCount / aggregated.length) * 100),
    stealth: Math.min(100, (aggregated.length / 20) * 100), // 攻击源越多越隐蔽
    assetImportance: 75, // 默认资产重要性
    confidence: Math.min(100, (maxCount / 50) * 100), // 单一IP攻击次数越多置信度越高
  };
}
