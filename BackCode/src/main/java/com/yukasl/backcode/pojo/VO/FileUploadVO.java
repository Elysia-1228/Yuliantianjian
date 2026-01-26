package com.yukasl.backcode.pojo.VO;

import lombok.Data;

@Data
public class FileUploadVO {
    private String originalFileName; // 原始文件名
    private String uniqueFileName; // 服务器保存的唯一文件名
    private String saveFilePath; // 服务器完整保存路径
    private String fileSize; // 文件大小（KB）
    private String relativePath; // 相对路径（用于前端下载/预览）
}