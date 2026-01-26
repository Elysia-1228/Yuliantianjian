package com.yukasl.backcode.pojo.VO;

import com.yukasl.backcode.pojo.entity.userinfo;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class sysUserVO {
    private String token;
    private userinfo userInfo;
}
