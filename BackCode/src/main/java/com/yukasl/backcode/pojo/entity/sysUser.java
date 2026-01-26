package com.yukasl.backcode.pojo.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class sysUser {
    private Integer id;
    private String username;
    private String password;
    private Integer role;  //1 管理员 2普通用户
    private Integer status; // 0 禁用 1 启用
    private LocalDateTime createTime;
    private LocalDateTime updateTime;

}
