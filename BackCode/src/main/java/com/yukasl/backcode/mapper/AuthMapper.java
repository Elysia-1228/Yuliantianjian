package com.yukasl.backcode.mapper;

import com.yukasl.backcode.pojo.entity.sysUser;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface AuthMapper {

    /**
     * 根据username查询
     * @param username
     * @return
     */
    sysUser getByUsername(String username);



}
