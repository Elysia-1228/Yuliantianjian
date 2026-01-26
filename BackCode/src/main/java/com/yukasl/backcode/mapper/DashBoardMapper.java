package com.yukasl.backcode.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface DashBoardMapper {
    @Select("select count(*) from threat_traffic_stat")
    Integer getTotalAttacksToday();

    @Select("select count(*) from potential_threat_alert where status = 'Pending'")
    Integer getactiveThreats();

    @Select("select count(*) from network_threat_collection_host")
    Integer getProtectedAssets();

}
