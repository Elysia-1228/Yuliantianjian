package com.example.blockchain.aspect;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;

@Aspect
@Component
public class AuditLogAspect {

    private static final Logger logger = LoggerFactory.getLogger(AuditLogAspect.class);

    @Pointcut("execution(public * com.example.blockchain.BlockchainController.*(..))")
    public void controllerLog() {}

    @Before("controllerLog()")
    public void doBefore(JoinPoint joinPoint) {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            HttpServletRequest request = attributes.getRequest();
            logger.info("AUDIT LOG - Request URL: {}, IP: {}, Method: {}, Args: {}",
                    request.getRequestURL().toString(),
                    request.getRemoteAddr(),
                    joinPoint.getSignature().getName(),
                    Arrays.toString(joinPoint.getArgs()));
        }
    }

    @AfterReturning(returning = "ret", pointcut = "controllerLog()")
    public void doAfterReturning(Object ret) {
        logger.info("AUDIT LOG - Response: {}", ret);
    }
}
