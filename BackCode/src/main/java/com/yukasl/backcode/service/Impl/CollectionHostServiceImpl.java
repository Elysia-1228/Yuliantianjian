package com.yukasl.backcode.service.impl;

import com.github.pagehelper.Page;
import com.github.pagehelper.PageHelper;
import com.yukasl.backcode.mapper.CollectionHostMapper;
import com.yukasl.backcode.pojo.DTO.collectionApiDTO;
import com.yukasl.backcode.pojo.DTO.collectionHostDTO;
import com.yukasl.backcode.pojo.DTO.collectionHostPageDTO;
import com.yukasl.backcode.pojo.entity.networkThreatCollectionApi;
import com.yukasl.backcode.pojo.entity.networkThreatCollectionHost;
import com.yukasl.backcode.result.PageResult;
import com.yukasl.backcode.service.CollectionHostService;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class CollectionHostServiceImpl implements CollectionHostService {

    @Autowired
    private CollectionHostMapper collectionHostMapper;

    @Autowired
    private com.yukasl.backcode.mapper.MonitorMapper monitorMapper;

    /**
     * 查询云外主机采集配置列表，支持条件筛选
     *
     * @param collectionHostDTO
     * @return
     */
    @Override
    public PageResult page(collectionHostPageDTO collectionHostDTO) {
        PageHelper.startPage(collectionHostDTO.getPageNum(), collectionHostDTO.getPageSize());
        networkThreatCollectionHost collectionHost = new networkThreatCollectionHost();
        collectionHost.setCollectStatus(collectionHostDTO.getCollectStatus());
        collectionHost.setHostIp(collectionHostDTO.getHostIp());
        List<networkThreatCollectionHost> collectionHostList = collectionHostMapper.getByCollectionHost(collectionHost);
        Page<networkThreatCollectionHost> p = (Page<networkThreatCollectionHost>) collectionHostList;
        return new PageResult(p.getTotal(), p.getResult());
    }

    /**
     * 新增云外主机采集配置
     *
     * @param collectionHostDTO
     * @return
     */
    @Override
    public Integer addHost(collectionHostDTO collectionHostDTO) {
        if (collectionHostDTO == null) {
            throw new RuntimeException("新增主机传入数据为空");
        }

        if (collectionHostDTO.getHostIp() == null) {
            throw new RuntimeException("HostIp不存在");
        }
        if (collectionHostDTO.getCollectFreq() == null) {
            throw new RuntimeException("采集频率未设置");
        }
        if (collectionHostDTO.getCollectStatus() == null) {
            collectionHostDTO.setCollectStatus(0);
        }
        networkThreatCollectionHost collectionHost = new networkThreatCollectionHost();
        BeanUtils.copyProperties(collectionHostDTO, collectionHost);
        collectionHost.setCreateTime(LocalDateTime.now());
        collectionHost.setUpdateTime(LocalDateTime.now());
        collectionHostMapper.addHostByCollectionHost(collectionHost);
        return collectionHost.getId();
    }

    /**
     * 修改云外主机采集配置
     *
     * @param id
     * @param collectionHostDTO
     */
    @Override
    public void updateHost(Integer id, collectionHostDTO collectionHostDTO) {
        if (id == null) {
            throw new RuntimeException("要修改的主机Id为空");
        }
        if (collectionHostDTO == null) {
            throw new RuntimeException("修改云主机参数为空");
        }
        networkThreatCollectionHost collectionHost = new networkThreatCollectionHost();
        BeanUtils.copyProperties(collectionHostDTO, collectionHost);
        collectionHost.setUpdateTime(LocalDateTime.now());
        collectionHostMapper.updateByCollectionHost(id, collectionHost);
    }

    @Override
    public void deleteHost(Integer id) {
        if (id == null) {
            throw new RuntimeException("删除云外主机采集配置的参数为空");
        }
        // 级联删除：先获取主机IP，然后删除相关的监控历史数据
        networkThreatCollectionHost host = collectionHostMapper.getById(id);
        if (host != null && host.getHostIp() != null) {
             monitorMapper.deleteByHostId(host.getHostIp());
        }
        collectionHostMapper.deleteById(id);
    }

    /**
     * 查询移动云 API 配置详情
     *
     * @param id
     * @return
     */
    @Override
    public networkThreatCollectionApi queryApi(Integer id) {
        if (id == null) {
            throw new RuntimeException("查询移动云 API 配置详情Id为空`");
        }
        networkThreatCollectionApi collectionApi = collectionHostMapper.queryApiById(id);
        return collectionApi;
    }

    /**
     * 修改移动云 API 配置
     *
     * @param collectionApiDTO
     */
    @Override
    public void updateApi(collectionApiDTO collectionApiDTO) {
        if (collectionApiDTO == null || collectionApiDTO.getId() == null) {
            throw new RuntimeException("请求参数为空");
        }
        networkThreatCollectionApi collectionApi = new networkThreatCollectionApi();
        BeanUtils.copyProperties(collectionApiDTO, collectionApi);
        collectionHostMapper.updateApi(collectionApi);
    }
}