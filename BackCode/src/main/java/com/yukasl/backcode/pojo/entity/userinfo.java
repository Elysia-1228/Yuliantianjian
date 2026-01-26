package com.yukasl.backcode.pojo.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class userinfo {
    private Integer id;
    private String username;
    private Integer role;  //1 管理员 2普通用户
}
