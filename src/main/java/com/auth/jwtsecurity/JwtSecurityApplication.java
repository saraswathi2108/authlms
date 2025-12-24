package com.auth.jwtsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients
public class    JwtSecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(JwtSecurityApplication.class, args);
    }

}
