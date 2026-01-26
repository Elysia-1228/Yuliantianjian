package com.yukasl.backcode.service.impl;

import com.yukasl.backcode.mapper.DashBoardMapper;
import com.yukasl.backcode.pojo.VO.DashBoardVO;
import com.yukasl.backcode.service.DashBoardService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class DashBoardServiceImpl implements DashBoardService {

    @Autowired
    private DashBoardMapper dashBoardMapper;

    @Override
    public DashBoardVO getInfo() {
        Integer totalAttacksToday = dashBoardMapper.getTotalAttacksToday();
        Integer activeThreats =  dashBoardMapper.getactiveThreats();
        Integer protectedAssets = dashBoardMapper.getProtectedAssets();
        Integer securityScore  =  (protectedAssets/totalAttacksToday)*100;
        DashBoardVO dashBoardVO = new DashBoardVO();
        dashBoardVO.setActiveThreats(activeThreats);
        dashBoardVO.setIdsStatus("暂时不做判断"); //TODO 和IDS交流判断是否启动
        dashBoardVO.setProtectedAssets(protectedAssets);
        dashBoardVO.setSecurityScore(securityScore);
        return dashBoardVO;
    }
}
