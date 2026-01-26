package com.yukasl.backcode.pojo.VO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class QueryUploadVO {
    private String reportFile;
    private Integer collectedDataId;
    private Integer uploadProgress;
    private Integer uploadResult;
}