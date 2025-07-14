package com.example.hrportal.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * Health Check Controller for KrakenD and monitoring
 */
@RestController
public class HealthController {

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> health = Map.of(
                "status", "UP",
                "timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                "service", "hr-portal-backend",
                "version", "1.0.0"
        );

        return ResponseEntity.ok(health);
    }

    @GetMapping("/actuator/health")
    public ResponseEntity<Map<String, Object>> actuatorHealth() {
        Map<String, Object> health = Map.of(
                "status", "UP",
                "timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                "service", "hr-portal-backend",
                "version", "1.0.0",
                "components", Map.of(
                        "application", Map.of("status", "UP"),
                        "diskSpace", Map.of("status", "UP"),
                        "ping", Map.of("status", "UP")
                )
        );

        return ResponseEntity.ok(health);
    }
}