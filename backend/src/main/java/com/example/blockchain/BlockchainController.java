package com.example.blockchain;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.example.blockchain.dto.*;
import com.example.blockchain.service.AsyncService;
import com.example.blockchain.util.AESUtil;
import org.hyperledger.fabric.gateway.Contract;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.HashMap;

@RestController
@RequestMapping("/api")
public class BlockchainController {

    @Autowired
    private Contract contract;

    @Autowired
    private AsyncService asyncService;

    // 1. 提交接口 (保持不变)
    @PostMapping("/evidence")
    public Map<String, Object> submitEvidence(@RequestBody Map<String, String> payload) {
        Map<String, Object> response = new HashMap<>();
        if (!payload.containsKey("eventID") || !payload.containsKey("dataHash")) {
            response.put("status", "error");
            response.put("message", "缺少必要参数");
            return response;
        }
        asyncService.addToQueue(payload);
        response.put("status", "success");
        response.put("message", "已加入后台队列");
        return response;
    }

    @GetMapping("/evidence/{id}")
    public Map<String, Object> getEvidence(@PathVariable String id) {
        Map<String, Object> response = new HashMap<>();
        try {
            System.out.println(">>> 正在查询: " + id);
            byte[] result = contract.evaluateTransaction("getEvidenceByEventID", id);
            String jsonStr = new String(result, StandardCharsets.UTF_8);

            JSONObject data = JSON.parseObject(jsonStr);
            String metadataStr = data.getString("metadata");
            if (metadataStr != null) {
                JSONObject meta = JSON.parseObject(metadataStr);
                decryptField(meta, "orgName");
                decryptField(meta, "sourceIp");
                decryptField(meta, "reportUrl");
                decryptField(meta, "impactScope");
                data.put("metadata", meta);
            }

            response.put("status", "success");
            response.put("data", data);
            return response;
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "未找到: " + e.getMessage());
            return response;
        }
    }
    
    // 3. 验证接口 (保持不变)
    @PostMapping("/verify")
    public Map<String, Object> verifyEvidence(@RequestBody Map<String, String> payload) {
        Map<String, Object> response = new HashMap<>();
        try {
            String id = payload.get("eventID");
            String clientHash = payload.get("dataHash"); // 前端传来的“本地”哈希

            // 查链上数据
            byte[] result = contract.evaluateTransaction("getEvidenceByEventID", id);
            JSONObject chainData = JSON.parseObject(new String(result, StandardCharsets.UTF_8));
            
            // 拿到链上哈希
            String chainHash = chainData.getString("dataHash");

            boolean isMatch = chainHash.equals(clientHash);
            
            response.put("status", "success");
            response.put("isMatch", isMatch);
            
            response.put("chainHash", chainHash); 
            response.put("localHash", clientHash);
            
            return response;
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "校验失败: " + e.getMessage());
            return response;
        }
    }

    // --- 新增业务接口 ---

    @PostMapping("/chain/org")
    public Map<String, Object> submitOrg(@RequestBody OrgInfoDTO dto) {
        try {
            // 加密敏感字段
            if (dto.getOrgName() != null) {
                dto.setOrgName(AESUtil.encrypt(dto.getOrgName()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        String rawId = dto.getOrgId() != null ? dto.getOrgId() : String.valueOf(dto.getId());
        return processDto(rawId, dto, "ORG");
    }

    @PostMapping("/chain/alert")
    public Map<String, Object> submitAlert(@RequestBody ThreatAlertDTO dto) {
        try {
            // 加密敏感字段
            if (dto.getImpactScope() != null) {
                dto.setImpactScope(AESUtil.encrypt(dto.getImpactScope()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        String rawId = dto.getThreatId() != null ? dto.getThreatId() : String.valueOf(dto.getId());
        return processDto(rawId, dto, "ALERT");
    }

    @PostMapping("/chain/traffic")
    public Map<String, Object> submitTraffic(@RequestBody TrafficStatDTO dto) {
        String rawId = String.valueOf(dto.getId());
        return processDto(rawId, dto, "TRAFFIC");
    }

    @PostMapping("/chain/report")
    public Map<String, Object> submitReport(@RequestBody ReportConfigDTO dto) {
        try {
            // 加密敏感字段
            if (dto.getReportUrl() != null) {
                dto.setReportUrl(AESUtil.encrypt(dto.getReportUrl()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        String rawId = String.valueOf(dto.getId());
        return processDto(rawId, dto, "REPORT");
    }

    @PostMapping("/chain/trace")
    public Map<String, Object> submitTrace(@RequestBody SourceTracingDTO dto) {
        String rawId = String.valueOf(dto.getId());
        return processDto(rawId, dto, "TRACE");
    }

    // 新增：按类型批量查询 (Rich Query)
    @GetMapping("/chain/list/{type}")
    public Map<String, Object> queryByType(@PathVariable String type) {
        Map<String, Object> response = new HashMap<>();
        try {
            // 需要合约支持 queryEvidenceByType 方法 (Range Query实现)
            byte[] result = contract.evaluateTransaction("queryEvidenceByType", type);
            String jsonStr = new String(result, StandardCharsets.UTF_8);
            response.put("status", "success");
            response.put("data", JSON.parseArray(jsonStr));
        } catch (Exception e) {
            response.put("status", "error");
            String msg = e.getMessage();
            if (msg.contains("Transaction function") && msg.contains("not found")) {
                response.put("message", "查询失败: 智能合约未升级，缺少 queryEvidenceByType 方法。请修改合约并升级链码。");
            } else {
                response.put("message", "查询失败: " + msg);
            }
        }
        return response;
    }

    private Map<String, Object> processDto(String eventId, Object dto, String typeCode) {
        Map<String, Object> response = new HashMap<>();
        try {
            String prefix = typeCode + "_";
            String prefixedId = eventId != null && eventId.startsWith(prefix) ? eventId : (prefix + eventId);
            
            String metadata = JSON.toJSONString(dto);
            String dataHash = String.valueOf(metadata.hashCode());

            Map<String, String> payload = new HashMap<>();
            payload.put("eventID", prefixedId); // 使用带前缀的 ID
            payload.put("dataHash", dataHash);
            payload.put("metadata", metadata);

            asyncService.addToQueue(payload);

            response.put("status", "success");
            response.put("message", typeCode + "已入队");
            response.put("txId", prefixedId); // 返回给前端的是带前缀的 ID
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }

    private void decryptField(JSONObject json, String key) {
        if (json.containsKey(key)) {
            try {
                String val = json.getString(key);
                if (val != null && val.length() > 10 && !val.contains(" ")) {
                    String plain = AESUtil.decrypt(val);
                    if (plain != null) {
                        json.put(key, plain);
                    }
                }
            } catch (Exception ignored) {}
        }
    }

}
