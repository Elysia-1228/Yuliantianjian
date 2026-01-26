package com.yukasl.backcode.mapper;

import com.yukasl.backcode.pojo.DTO.alertPageDTO;
import com.yukasl.backcode.pojo.DTO.pageTrafficDateDTO;
import com.yukasl.backcode.pojo.entity.potentialThreatAlert;
import com.yukasl.backcode.pojo.entity.threatTrafficStat;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface AnalysisMapper {

    /**
     * 新增潜在威胁预警
     * 🔥 修复：包含所有字段（attack_type, affected_process, affected_file, message）
     */
    @Insert("insert into potential_threat_alert (threat_id, threat_level, impact_scope, occur_time, create_time, " +
            "source_ip, target_ip, attack_type, affected_process, affected_file, message, status) " +
            "values (#{threatId}, #{threatLevel}, #{impactScope}, #{occurTime}, #{createTime}, " +
            "#{sourceIp}, #{targetIp}, #{attackType}, #{affectedProcess}, #{affectedFile}, #{message}, #{status})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void insert(potentialThreatAlert alert);

    /**
     * 查询威胁流量统计数据
     *
     * @param pageTrafficDateDTO
     * @return
     */
    List<threatTrafficStat> page(pageTrafficDateDTO pageTrafficDateDTO);

    /**
     * 查询潜在威胁预警列表
     *
     * @param alertPageDTO
     * @return
     */
    List<potentialThreatAlert> queryAlertPage(alertPageDTO alertPageDTO);

    /**
     * 查看潜在威胁预警详情
     *
     * @param id
     * @return
     */
    @Select("select * from potential_threat_alert where id = #{id}")
    potentialThreatAlert queryAlertById(Integer id);

    /**
     * 根据 UUID 查询潜在威胁
     */
    @Select("select * from potential_threat_alert where threat_id = #{threatId}")
    potentialThreatAlert queryAlertByThreatId(String threatId);

    /**
     * 按时间范围统计攻击趋势 (按小时聚合)
     */
    @Select("SELECT DATE_FORMAT(occur_time, '%Y-%m-%d %H:00:00') as time_bucket, COUNT(*) as count " +
            "FROM potential_threat_alert " +
            "WHERE occur_time >= #{startTime} AND occur_time <= #{endTime} " +
            "GROUP BY time_bucket " +
            "ORDER BY time_bucket")
    List<java.util.Map<String, Object>> countAlertsByHour(@org.apache.ibatis.annotations.Param("startTime") java.time.LocalDateTime startTime, 
                                                          @org.apache.ibatis.annotations.Param("endTime") java.time.LocalDateTime endTime);

    /**
     * 按时间范围统计攻击趋势 (按天聚合)
     */
    @Select("SELECT DATE_FORMAT(occur_time, '%Y-%m-%d') as time_bucket, COUNT(*) as count " +
            "FROM potential_threat_alert " +
            "WHERE occur_time >= #{startTime} AND occur_time <= #{endTime} " +
            "GROUP BY time_bucket " +
            "ORDER BY time_bucket")
    List<java.util.Map<String, Object>> countAlertsByDay(@org.apache.ibatis.annotations.Param("startTime") java.time.LocalDateTime startTime, 
                                                         @org.apache.ibatis.annotations.Param("endTime") java.time.LocalDateTime endTime);
    
    /**
     * 查询最近的告警记录（用于获取 affectedProcess 和 affectedFile）
     * 🔥 修复：只根据 source_ip 查询，忽略 target_ip（因为 target_ip 可能为空或 '-'）
     */
    @Select("SELECT * FROM potential_threat_alert " +
            "WHERE source_ip = #{sourceIp} " +
            "ORDER BY occur_time DESC " +
            "LIMIT #{limit}")
    List<potentialThreatAlert> queryRecentAlerts(@org.apache.ibatis.annotations.Param("sourceIp") String sourceIp,
                                                  @org.apache.ibatis.annotations.Param("targetIp") String targetIp,
                                                  @org.apache.ibatis.annotations.Param("limit") int limit);
    
    /**
     * 🔥 根据目标IP查询所有告警记录（用于增量溯源）
     * 查询针对特定目标IP的所有攻击源的告警记录
     */
    @Select("SELECT * FROM potential_threat_alert " +
            "WHERE target_ip = #{targetIp} " +
            "ORDER BY occur_time DESC " +
            "LIMIT #{limit}")
    List<potentialThreatAlert> queryAlertsByTargetIp(@org.apache.ibatis.annotations.Param("targetIp") String targetIp,
                                                      @org.apache.ibatis.annotations.Param("limit") int limit);
}