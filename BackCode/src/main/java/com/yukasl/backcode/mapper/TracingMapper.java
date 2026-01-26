package com.yukasl.backcode.mapper;

import com.yukasl.backcode.pojo.DTO.tracingPageDTO;
import com.yukasl.backcode.pojo.entity.threatSourceTracing;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Insert;

import java.util.List;

@Mapper
public interface TracingMapper {

    /**
     * 根据DTO查询
     * @param tracingPageDTO
     * @return
     */
    List<threatSourceTracing> query(tracingPageDTO tracingPageDTO);

    /**
     * 查询威胁溯源详细
     * @param id
     * @return
     */
    @Select("select id, threat_source, malicious_ip, attack_cmd, malware_origin, attack_path from threat_source_tracing where id =#{id}")
    threatSourceTracing queryById(Integer id);

    void insert(threatSourceTracing sourceTracing);
}
