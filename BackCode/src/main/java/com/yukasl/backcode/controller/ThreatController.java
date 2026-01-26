package com.yukasl.backcode.controller;

import com.yukasl.backcode.pojo.entity.potentialThreatAlert;
import com.yukasl.backcode.result.Result;
import com.yukasl.backcode.service.AnalysisService;
import com.yukasl.backcode.service.CommandQueueService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/threats")
@Slf4j
public class ThreatController {

    @Autowired
    private AnalysisService analysisService;

    @Autowired
    private CommandQueueService commandQueueService;

    /**
     * 下发 IP 阻断指令
     * @param id 威胁ID (可能是 Integer id 或 String threatId)
     */
    @PostMapping("/{id}/block")
    public Result<String> blockIp(@PathVariable String id) {
        log.info("收到阻断请求，威胁ID: {}", id);
        
        // 尝试通过 UUID 查询
        potentialThreatAlert alert = analysisService.queryAlertByThreatId(id);
        
        // 如果未找到，且 id 是数字，尝试通过主键 ID 查询
        if (alert == null && id.matches("\\d+")) {
             try {
                 alert = analysisService.queryAlertById(Integer.parseInt(id));
             } catch (NumberFormatException e) {
                 // ignore
             }
        }

        if (alert == null) {
            return Result.error("Threat event not found");
        }

        // 解析攻击源 IP 和 受害主机 IP
        // 假设 impactScope 格式: "192.168.1.5:1234 -> 192.168.1.100:80 | SQL Injection"
        String scope = alert.getImpactScope();
        if (scope == null || !scope.contains("->")) {
            return Result.error("Cannot parse IPs from impact scope");
        }

        try {
            String[] parts = scope.split("\\|");
            String flow = parts[0].trim(); // "192.168.1.5:1234 -> 192.168.1.100:80"
            String[] ips = flow.split("->");
            
            String srcIp = ips[0].trim().split(":")[0]; // 攻击者
            String dstIp = ips[1].trim().split(":")[0]; // 受害者 (Host)

            // 生成阻断指令
            // 格式: BLOCK_IP <ip>
            String command = "BLOCK_IP " + srcIp;
            
            // 将指令放入受害主机的队列
            commandQueueService.addCommand(dstIp, command);
            
            log.info("已生成阻断指令 '{}' 给主机 {}", command, dstIp);
            return Result.success("Block command queued for host " + dstIp);

        } catch (Exception e) {
            log.error("解析 IP 失败", e);
            return Result.error("Failed to parse IP addresses");
        }
    }
    
    /**
     * 下发 IP 解封指令
     * @param id 威胁ID (可能是 Integer id 或 String threatId)
     */
    @PostMapping("/{id}/unblock")
    public Result<String> unblockIp(@PathVariable String id) {
        log.info("收到解封请求，威胁ID: {}", id);
        
        // 尝试通过 UUID 查询
        potentialThreatAlert alert = analysisService.queryAlertByThreatId(id);
        
        // 如果未找到，且 id 是数字，尝试通过主键 ID 查询
        if (alert == null && id.matches("\\d+")) {
             try {
                 alert = analysisService.queryAlertById(Integer.parseInt(id));
             } catch (NumberFormatException e) {
                 // ignore
             }
        }

        if (alert == null) {
            return Result.error("Threat event not found");
        }

        String scope = alert.getImpactScope();
        if (scope == null || !scope.contains("->")) {
            return Result.error("Cannot parse IPs from impact scope");
        }

        try {
            String[] parts = scope.split("\\|");
            String flow = parts[0].trim();
            String[] ips = flow.split("->");

            String srcIp = ips[0].trim().split(":")[0];
            String dstIp = ips[1].trim().split(":")[0];

            // 生成解封指令
            String command = "UNBLOCK_IP " + srcIp;

            commandQueueService.addCommand(dstIp, command);

            log.info("已生成解封指令 '{}' 给主机 {}", command, dstIp);
            return Result.success("Unblock command queued for host " + dstIp);

        } catch (Exception e) {
            log.error("解析 IP 失败", e);
            return Result.error("Failed to parse IP addresses");
        }
    }

    /**
     * 获取当前所有被封禁的 IP 列表
     * (从项目根目录 blocked_ips.json 读取)
     */
    @GetMapping("/blocked-ips")
    public Result<java.util.List<String>> getBlockedIps() {
        try {
            // 假设 blocked_ips.json 位于项目根目录
            // 在 IDEA/开发环境中，System.getProperty("user.dir") 通常是项目根目录
            // 注意：这里需要处理文件路径，可能需要回退一级目录，取决于启动目录
            
            // 尝试多个可能的路径
            java.io.File file = new java.io.File("blocked_ips.json");
            if (!file.exists()) {
                file = new java.io.File("../blocked_ips.json");
            }
            if (!file.exists()) {
                // 再试一下绝对路径（硬编码，仅作为最后的兜底，或者根据 user.dir 动态构建）
                String userDir = System.getProperty("user.dir");
                file = new java.io.File(userDir + "/../blocked_ips.json"); 
            }
            
            // 如果还是找不到，返回空列表
            if (!file.exists()) {
                log.warn("blocked_ips.json not found");
                return Result.success(new java.util.ArrayList<>());
            }

            // 读取 JSON
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            java.util.List<String> blockedIps = mapper.readValue(file, new com.fasterxml.jackson.core.type.TypeReference<java.util.List<String>>(){});
            
            return Result.success(blockedIps);

        } catch (Exception e) {
            log.error("Failed to read blocked_ips.json", e);
            return Result.error("Failed to read blocked IPs: " + e.getMessage());
        }
    }

    /**
     * 手动封禁指定 IP (不关联具体告警)
     * @param ip 目标IP
     * @param hostIp 执行命令的主机IP (Agent IP)，如果是单机部署通常是 127.0.0.1 或者本机真实IP
     */
    @PostMapping("/manual-block")
    public Result<String> manualBlock(@RequestParam String ip, @RequestParam(defaultValue = "127.0.0.1") String hostIp) {
        if (ip == null || ip.isEmpty()) {
            return Result.error("IP cannot be empty");
        }
        String command = "BLOCK_IP " + ip;
        // 如果 hostIp 是默认值，且有真实 Agent 连上来，可能需要广播或者发给特定的。
        // 简化处理：发给 127.0.0.1 和 实际连接的 IP (如果能获取到)
        // 目前 CommandQueueService 是按 hostIp 存队列的。Agent 上报时用的 HOST_ID。
        // Agent.py: HOST_ID = os.environ.get("HOST_IP", get_local_ip())
        // 如果 Agent 自动获取了局域网 IP (如 192.168.31.87)，那么队列也必须用这个 IP。
        
        // 为了确保命令能被执行，我们尝试发给 hostIp。
        // 前端调用时最好能选择主机，或者我们遍历所有在线主机？
        // 暂时简单点，由前端传，默认发给 "127.0.0.1" (Agent 如果获取失败会用这个) 
        // 或者我们改进一下 Agent，让它轮询时携带自己的 ID，后端记录活跃主机。
        
        commandQueueService.addCommand(hostIp, command);
        
        // 同时也尝试发给本机实际 IP (暴力一点，发给所有已知可能)
        // 但这里我们只发给参数指定的。
        
        log.info("手动封禁指令 '{}' 发送给 {}", command, hostIp);
        return Result.success("Manual block command queued for " + hostIp);
    }

    /**
     * 手动解封指定 IP
     */
    @PostMapping("/manual-unblock")
    public Result<String> manualUnblock(@RequestParam String ip, @RequestParam(defaultValue = "127.0.0.1") String hostIp) {
        if (ip == null || ip.isEmpty()) {
            return Result.error("IP cannot be empty");
        }
        String command = "UNBLOCK_IP " + ip;
        commandQueueService.addCommand(hostIp, command);
        log.info("手动解封指令 '{}' 发送给 {}", command, hostIp);
        return Result.success("Manual unblock command queued for " + hostIp);
    }

    /**
     * 标记误报/已解决
     */
    @PostMapping("/{id}/resolve")
    public Result<String> resolveThreat(@PathVariable String id) {
        log.info("标记威胁已解决: {}", id);
        // 这里应该调用 service 更新状态，暂时仅返回成功
        return Result.success("Threat marked as resolved");
    }
}
