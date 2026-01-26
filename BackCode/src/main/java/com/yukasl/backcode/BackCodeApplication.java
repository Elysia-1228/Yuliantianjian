package com.yukasl.backcode;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class BackCodeApplication {
    public static void main(String[] args) {
        SpringApplication.run(BackCodeApplication.class, args);
    }
}