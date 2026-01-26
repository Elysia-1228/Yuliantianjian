package com.yukasl.backcode.utils;

import org.springframework.util.StringUtils;

public class FileUtils {
    public static String getFileExtension(String originalFilename) {
        if (!StringUtils.hasText(originalFilename) || !originalFilename.contains(".")) {
            return "";
        }
        // 从最后一个"."截取到末尾
        return originalFilename.substring(originalFilename.lastIndexOf(".") + 1).toLowerCase();
    }

    /**
     * 字节转KB（保留1位小数）
     */
    public static String bytesToKb(long bytes) {
        return String.format("%.1f", bytes / 1024.0) + "KB";
    }
}