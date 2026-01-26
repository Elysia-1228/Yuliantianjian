package com.example.blockchain.interceptor;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class AuthInterceptor implements HandlerInterceptor {

    private static final String API_KEY_HEADER = "X-API-KEY";
    // In production, this should be in config/env
    private static final String VALID_API_KEY = "secret-api-key";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // Allow OPTIONS requests for CORS preflight
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }

        String apiKey = request.getHeader(API_KEY_HEADER);
        if (VALID_API_KEY.equals(apiKey)) {
            return true;
        }
        
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("Unauthorized: Invalid or missing API Key");
        return false;
    }
}
