package com.yukasl.backcode.service;

import com.yukasl.backcode.pojo.VO.QueryUploadVO;
import com.yukasl.backcode.pojo.VO.UploadVO;
import org.springframework.web.multipart.MultipartFile;

public interface UploadService {
    /**
     * 文件上传接口
     *
     * @param file
     * @param collectedDataId
     * @return
     */
    UploadVO uploadSingleFile(MultipartFile file, Integer collectedDataId);

    /**
     * 查询数据上报进度
     *
     * @return
     */
    QueryUploadVO queryUpload(Integer id);
}