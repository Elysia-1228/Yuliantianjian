package com.yukasl.backcode.controller;

import com.yukasl.backcode.pojo.VO.sysUserVO;
import com.yukasl.backcode.pojo.entity.sysUser;
import com.yukasl.backcode.pojo.entity.userinfo;
import com.yukasl.backcode.properties.JwtProperties;
import com.yukasl.backcode.result.Result;
import com.yukasl.backcode.service.AuthService;
import com.yukasl.backcode.utils.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@Slf4j
@RequestMapping("/api/auth")
/**
 * 认证模块 (Auth)
 */
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtProperties jwtProperties;

    @PostMapping("/login")
    public Result Login(@RequestBody sysUser sysUser){
        log.info("登录信息 -> {}",sysUser);
        sysUser user =  authService.login(sysUser);

        Map<String, Object> claims = new HashMap<>();

        claims.put("id",user.getId());

        String token = JwtUtil.createJWT(
                jwtProperties.getAdminSecretKey(),
                jwtProperties.getAdminTtl(),
                claims
        );
        sysUserVO sysUserVO = new sysUserVO();
        sysUserVO.setUserInfo(new userinfo(user.getId(), user.getUsername(),user.getRole()));
        sysUserVO.setToken(token);

        return Result.success(sysUserVO);
    }

}
