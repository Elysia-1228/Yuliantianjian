package com.yukasl.backcode.config;

import com.yukasl.backcode.interceptor.JwtTokenAdminInterceptor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 配置类，注册web层相关组件
 */
@Configuration
@Slf4j
public class WebMvcConfiguration implements WebMvcConfigurer {

    @Autowired
    private JwtTokenAdminInterceptor jwtTokenAdminInterceptor;

    /**
     * 注册自定义拦截器
     *
     * @param registry
     */
    public void addInterceptors(InterceptorRegistry registry) {
        log.info("开始注册自定义拦截器...");
        registry.addInterceptor(jwtTokenAdminInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns("/api/auth/login")
                .excludePathPatterns("/api/analysis/alert") // 放行模拟攻击接口
                .excludePathPatterns("/api/host/monitor/report") // 放行HIDS上报接口
                .excludePathPatterns("/api/tracing/result/generate-graph") // 放行AI图谱生成接口
                .excludePathPatterns("/api/tracing/list") // 放行溯源列表接口
                .excludePathPatterns("/ids/stream") // 放行WebSocket接口
                .excludePathPatterns("/error"); // 放行错误页面，避免404变为401
    }
}
