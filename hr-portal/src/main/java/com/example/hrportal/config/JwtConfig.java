package com.example.hrportal.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.Duration;

/**
 * 🔐 JWT Configuration for Keycloak Integration
 * Creates JwtDecoder bean for parsing JWT tokens from Authorization headers
 */
@Configuration
public class JwtConfig {

    private static final Logger logger = LoggerFactory.getLogger(JwtConfig.class);

    @Value("${spring.security.oauth2.client.provider.keycloak.jwk-set-uri}")
    private String jwkSetUri;

    @Bean
    public JwtDecoder jwtDecoder() {
        logger.info("🔧 Configuring JwtDecoder with JWK Set URI: {}", jwkSetUri);

        try {
            // Keycloak JWK endpoint'inden public key'leri al
            NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder
                    .withJwkSetUri(jwkSetUri)
                    .build();

            logger.info("✅ JwtDecoder successfully configured for Keycloak realm");
            return jwtDecoder;

        } catch (Exception e) {
            logger.error("❌ Error configuring JwtDecoder", e);
            throw new RuntimeException("Failed to configure JwtDecoder for Keycloak", e);
        }
    }
}