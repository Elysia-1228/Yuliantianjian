package com.yukasl.backcode.mapper;

import com.yukasl.backcode.pojo.DTO.OrgInfoDTO;
import com.yukasl.backcode.pojo.entity.orgInfo;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Options;

@Mapper
public interface OrgInfoMapper {
    List<orgInfo> queryOrgInfo(OrgInfoDTO orgInfoDTO);

    @Insert("insert into org_info (org_id, org_name, max_member_count, admin_permission) VALUES (#{orgId}, #{orgName}, #{maxMemberCount}, #{adminPermission})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    void insertOrgInfo(OrgInfoDTO orgInfoDTO);

    void updateOrgInfo(String id, OrgInfoDTO orgInfoDTO);

    @Delete("delete from org_info where id = #{id}")
    void deleteOrgInfo(String id);

    orgInfo queryLatestOrgInfo();
    
    @Select("select * from org_info where id = #{id}")
    orgInfo getById(String id);
}