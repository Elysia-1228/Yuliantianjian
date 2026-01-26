package com.yukasl.backcode.mapper;

import com.yukasl.backcode.pojo.entity.networkThreatCollectionApi;
import com.yukasl.backcode.pojo.entity.networkThreatCollectionHost;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface CollectionHostMapper {
    /**
     * 查询云外主机采集配置列表
     *
     * @param collectionHost
     * @return
     */
    List<networkThreatCollectionHost> getByCollectionHost(networkThreatCollectionHost collectionHost);

    /**
     * 新增云外主机采集配置
     *
     * @param collectionHost
     */
    void addHostByCollectionHost(networkThreatCollectionHost collectionHost);

    /**
     * 修改云外主机采集配置
     *
     * @param id
     * @param collectionHost
     */
    void updateByCollectionHost(Integer id, networkThreatCollectionHost collectionHost);

    /**
     * 删除云外主机采集配置
     */
    void deleteById(Integer id);

    @org.apache.ibatis.annotations.Select("select * from network_threat_collection_host where id = #{id}")
    networkThreatCollectionHost getById(Integer id);

    /**
     * 查询移动云 API 配置详情
     *
     * @param id
     * @return
     */
    networkThreatCollectionApi queryApiById(Integer id);

    /**
     * 修改移动云 API 配置
     *
     * @param collectionApi
     */
    void updateApi(networkThreatCollectionApi collectionApi);
}