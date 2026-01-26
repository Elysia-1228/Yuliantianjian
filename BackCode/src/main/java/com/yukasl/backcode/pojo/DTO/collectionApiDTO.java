package com.yukasl.backcode.pojo.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class collectionApiDTO {
    private Integer id;
    private String ApiKey;
    private String ApiSecret;
    private Integer syncStatus;
}