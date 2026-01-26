package com.yukasl.backcode.exception;

import lombok.Getter;

@Getter
public class BusinessException extends RuntimeException {
    private final String message; // 异常信息
    private final int code; // 响应码（默认500）

    public BusinessException(String message) {
        this.message = message;
        this.code = 500;
    }

    public BusinessException(String message, int code) {
        this.message = message;
        this.code = code;
    }
}