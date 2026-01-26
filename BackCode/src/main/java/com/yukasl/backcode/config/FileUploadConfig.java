package com.yukasl.backcode.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 文件上传配置类
 */
@Data
@Component
@ConfigurationProperties(prefix = "file.upload")
public class FileUploadConfig {
    /**
     * 上传文件根路径
     */
    private String basePath;

    /**
     * 允许的文件扩展名（小写）
     */
    private List<String> allowedExtensions;

    /**
     * 允许的Content-Type
     */
    private List<String> allowedContentTypes;
}