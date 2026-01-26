package com.yukasl.backcode.controller;

import com.yukasl.backcode.pojo.DTO.collectionHostPageDTO;
import com.yukasl.backcode.result.Result;
import com.yukasl.backcode.service.AnalysisService;
import com.yukasl.backcode.service.CollectionHostService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/dashboard")
public class DashBoardController {

    @Autowired
    private AnalysisService analysisService;

    @Autowired
    private CollectionHostService collectionHostService;

    @GetMapping("/summary")
    public Result<Map<String, Object>> getSummary() {
        Map<String, Object> data = new HashMap<>();

        // 1. Calculate Today's Attacks (Total from 24h trend)
        List<Map<String, Object>> trend = analysisService.getTrendStats("24h");
        long todayAttacks = 0;
        if (trend != null) {
            for (Map<String, Object> point : trend) {
                Object countObj = point.get("count");
                if (countObj instanceof Number) {
                    todayAttacks += ((Number) countObj).longValue();
                }
            }
        }
        data.put("totalAttacksToday", todayAttacks);

        // 2. Calculate Active Threats (Placeholder logic: 20% of today's attacks are active/unresolved)
        // Ideally this should query the database for status != 'Resolved'
        data.put("activeThreats", Math.max(0, (int)(todayAttacks * 0.2)));

        // 3. Protected Assets (Total configured hosts)
        long protectedAssets = 0;
        try {
            collectionHostPageDTO dto = new collectionHostPageDTO();
            dto.setPageNum(1);
            dto.setPageSize(1);
            // Assuming page() returns a PageResult with total count
            protectedAssets = collectionHostService.page(dto).getTotal();
        } catch (Exception e) {
            // ignore if service fails
        }
        data.put("protectedAssets", protectedAssets);

        // 4. Security Score Calculation
        // Base Score: 100
        // Deduction: 5 points per attack
        // Floor: 0
        long score = Math.max(0, 100 - (todayAttacks * 5));
        
        // If there are no protected assets, maybe score shouldn't be 100? 
        // But for now, let's keep it simple. If 0 attacks, score 100.
        
        //目前写死100
        data.put("securityScore", 100);

        return Result.success(data);
    }
}
