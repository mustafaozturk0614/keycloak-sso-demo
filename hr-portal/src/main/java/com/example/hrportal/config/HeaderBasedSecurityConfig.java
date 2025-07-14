package com.example.hrportal.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 🔐 KrakenD Header-based Security Configuration
 * JWT doğrulaması tamamen KrakenD tarafından yapılır.
 * Spring Boot sadece gelen header’ları okur.
 */
@Configuration
@EnableWebSecurity
public class HeaderBasedSecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(HeaderBasedSecurityConfig.class);

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF disable – stateless API
                .csrf(csrf -> csrf.disable())

                // Session yaratma yok
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Yetkilendirme kuralları
                .authorizeHttpRequests(auth -> auth
                        // Public endpoint’ler
                        .requestMatchers("/", "/health", "/actuator/health",
                                "/css/**", "/js/**", "/images/**", "/webjars/**",
                                "/favicon.ico", "/error").permitAll()

                        // Keycloak callback’i de public (KrakenD kullanmıyor)
                        .requestMatchers("/login/oauth2/**", "/oauth2/**", "/oauth/callback",
                                "/login", "/logout","/oauth-callback").permitAll()
                        .requestMatchers("/oauth/callback").permitAll()
                        // Geri kalan her şey authenticated
                        .anyRequest().authenticated()
                )

                // ✅ OAuth2 login tamamen kaldırıldı
                // .oauth2Login(...)

                // Header bazlı authentication filter
                .addFilterBefore(headerAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)

                // Hata yönetimi – sadece header eksikse gateway’e yönlendir
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, ex) -> {
                            String uri = request.getRequestURI();
                            logger.warn("🚫 Authentication failed for URI: {}", uri);

                            // Header yoksa KrakenD’ye yönlendir
                            String gatewaySource = request.getHeader("X-Gateway-Source");
                            if (gatewaySource == null || !gatewaySource.equals("KrakenD")) {
                                response.sendRedirect("http://localhost:8000/?error=auth_required");
                                return;
                            }

                            // API isteği ise JSON hata
                            if (uri.startsWith("/api/")) {
                                response.setStatus(401);
                                response.setContentType("application/json");
                                response.getWriter().write("{\"error\":\"Authentication required\"}");
                                return;
                            }

                            // Diğer durumda ana sayfa
                            response.sendRedirect("http://localhost:8000/?error=auth_required");
                        })
                        .accessDeniedHandler((request, response, ex) -> {
                            String uri = request.getRequestURI();
                            logger.warn("⛔ Access denied for URI: {}", uri);

                            if (uri.startsWith("/api/")) {
                                response.setStatus(403);
                                response.setContentType("application/json");
                                response.getWriter().write("{\"error\":\"Access denied\"}");
                            } else {
                                response.sendRedirect("http://localhost:8000/?error=access_denied");
                            }
                        })
                );

        logger.info("🔐 Header-only Security configuration activated");
        return http.build();
    }

    @Bean
    public HeaderAuthenticationFilter headerAuthenticationFilter() {
        return new HeaderAuthenticationFilter();
    }
}