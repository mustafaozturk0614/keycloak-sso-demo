package com.example.hrportal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * HR Portal uygulamasının ana sınıfı
 * Bu sınıf, Spring Boot uygulamasını başlatır ve temel konfigürasyonu sağlar
 */
@SpringBootApplication
public class HrPortalApplication {

    public static void main(String[] args) {
        SpringApplication.run(HrPortalApplication.class, args);
    }
} 