package com.yukasl.backcode.service;

import com.yukasl.backcode.pojo.DTO.collectionApiDTO;
import com.yukasl.backcode.pojo.DTO.collectionHostDTO;
import com.yukasl.backcode.pojo.DTO.collectionHostPageDTO;
import com.yukasl.backcode.pojo.entity.networkThreatCollectionApi;
import com.yukasl.backcode.result.PageResult;

public interface CollectionHostService {
    /**
     * 查询云外主机采集配置列表，支持条件筛选
     *
     * @param collectionHostDTO
     * @return
     */
    PageResult page(collectionHostPageDTO collectionHostDTO);

    /**
     * 新增主机
     *
     * @param collectionHostDTO
     * @return
     */
    Integer addHost(collectionHostDTO collectionHostDTO);

    /**
     * 修改云外主机采集配置
     */
    void updateHost(Integer id, collectionHostDTO collectionHostDTO);

    /**
     * 删除云外主机采集配置
     */
    void deleteHost(Integer id);

    /**
     * 查询移动云 API 配置详情
     *
     * @return
     */
    networkThreatCollectionApi queryApi(Integer id);

    /**
     * 修改移动云 API 配置
     *
     * @param collectionApiDTO
     */
    void updateApi(collectionApiDTO collectionApiDTO);
}