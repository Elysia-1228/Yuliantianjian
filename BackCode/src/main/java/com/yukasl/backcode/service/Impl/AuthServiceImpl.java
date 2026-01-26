package com.yukasl.backcode.service.impl;

import com.yukasl.backcode.mapper.AuthMapper;
import com.yukasl.backcode.pojo.entity.sysUser;
import com.yukasl.backcode.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private AuthMapper authMapper;

    @Override
    public sysUser login(sysUser sysUser) {
        String username = sysUser.getUsername();
        String password = sysUser.getPassword();
        sysUser user =  authMapper.getByUsername(username);

        if (user == null) {
            throw new RuntimeException("账号不存在");
        }

        if (!password.equals(user.getPassword())) {
            throw new RuntimeException("密码错误");
        }
        if (user.getStatus() == 0){
            throw new RuntimeException("账号被禁用");
        }




        return user;
    }
}
