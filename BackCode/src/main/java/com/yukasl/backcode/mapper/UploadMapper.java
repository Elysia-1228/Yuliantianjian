package com.yukasl.backcode.mapper;

import com.yukasl.backcode.pojo.VO.QueryUploadVO;
import com.yukasl.backcode.pojo.entity.networkThreatUpload;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UploadMapper {
    /**
     * 上传文件插入数据
     *
     * @param upload
     */
    void Insert(networkThreatUpload upload);

    /**
     * 查询数据上报进度
     *
     * @param id
     * @return
     */
    QueryUploadVO queryById(Integer id);
}