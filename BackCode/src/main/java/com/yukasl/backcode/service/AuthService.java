package com.yukasl.backcode.service;

import com.yukasl.backcode.pojo.entity.sysUser;

public interface AuthService {
    /**
     * 登录接口
     * @param sysUser
     * @return
     */
    sysUser login(sysUser sysUser);
}
