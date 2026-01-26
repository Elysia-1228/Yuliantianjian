package com.yukasl.backcode.controller;

import com.yukasl.backcode.pojo.VO.QueryUploadVO;
import com.yukasl.backcode.pojo.VO.UploadVO;
import com.yukasl.backcode.result.Result;
import com.yukasl.backcode.service.UploadService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@Slf4j
@RestController
@RequestMapping("/api/upload/data")
public class UploadController {
    @Autowired
    private UploadService uploadService;

    /**
     * 上传威胁数据文件
     *
     * @param file
     * @param collectedDataId
     * @return
     */
    @PostMapping
    public Result<UploadVO> uploadFile(@RequestParam("reportFile") MultipartFile file, Integer collectedDataId) {
        log.info("接收文件上传请求：文件名={},collectedDataId={}", file.getOriginalFilename(), collectedDataId);
        // 调用Service层处理核心业务，异常由全局异常处理器捕获
        UploadVO UploadVO = uploadService.uploadSingleFile(file, collectedDataId);
        return Result.success(UploadVO);
    }

    /**
     * 查询数据上报进度
     */
    @GetMapping("/{id}")
    public Result<QueryUploadVO> queryUpload(@PathVariable Integer id) {
        log.info("查询Id -> {} 数据上报进度", id);
        QueryUploadVO queryUploadVO = uploadService.queryUpload(id);
        return Result.success(queryUploadVO);
    }
}