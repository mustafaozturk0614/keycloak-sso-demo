package com.example.hrportal.config;

import com.example.hrportal.security.UserPrincipal;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 🔍 KrakenD Header Authentication Filter
 * KrakenD'den gelen header'ları okuyarak UserPrincipal ile Spring Security context'ini oluşturur
 * JWT validation KrakenD'de yapıldığı için burada sadece header parsing
 */
public class HeaderAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(HeaderAuthenticationFilter.class);

    // KrakenD'den gelen header'lar
    private static final String USER_ID_HEADER = "X-User-ID";
    private static final String USERNAME_HEADER = "X-Username";
    private static final String USER_EMAIL_HEADER = "X-User-Email";
    private static final String USER_NAME_HEADER = "X-User-Name";
    private static final String USER_ROLES_HEADER = "X-User-Roles";
    // private static final String GATEWAY_SOURCE_HEADER = "X-Gateway-Source"; // <-- BU SATIRI YORUM SATIRI YAPIN VEYA SİLİN

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String requestURI = request.getRequestURI();

        // Public endpoint'ler ve OAuth2 endpoint'ler için auth gerekmez
        if (isPublicEndpoint(requestURI)) {
            logger.debug("🔓 Public/OAuth2 endpoint accessed: {}", requestURI);
            filterChain.doFilter(request, response);
            return;
        }

        try {

            // KrakenD'den gelen header'ları oku
            String userId = request.getHeader(USER_ID_HEADER);
            String username = request.getHeader(USERNAME_HEADER);
            String userEmail = request.getHeader(USER_EMAIL_HEADER);
            String userName = request.getHeader(USER_NAME_HEADER);
            String userRoles = request.getHeader(USER_ROLES_HEADER);
            // String gatewaySource = request.getHeader(GATEWAY_SOURCE_HEADER); // <-- BU SATIRI YORUM SATIRI YAPIN VEYA SİLİN

            logger.debug("🔍 Headers - UserId: {}, Username: {}, Roles: {}",
                    userId, username, userRoles); // <-- LOG MESAJINI DA GÜNCELLEYİN

            // KrakenD'den gelmeyen request'leri kontrol et
            // if (gatewaySource == null || !gatewaySource.equals("KrakenD")) { // <-- BU BLOĞU KOMPLE YORUM SATIRI YAPIN VEYA SİLİN
            //     logger.warn("⚠️ Direct access detected for URI: {} from IP: {}",
            //             requestURI, getClientIP(request));
            //
            //     // Gateway'e yönlendir (exception handler'da yapılacak)
            //     filterChain.doFilter(request, response);
            //     return;
            // }

            // User bilgileri varsa authentication context oluştur
            if (userId != null && username != null) {
                // Role'ları parse et - realm ve client roles ayrı ayrı
                RoleParseResult roleResult = parseRolesFromHeader(userRoles);

                // UserPrincipal oluştur (sizin sınıfınız)
                UserPrincipal userPrincipal = new UserPrincipal(
                        userId,
                        username,
                        userEmail,
                        userName,
                        roleResult.realmRoles,
                        roleResult.clientRoles
                );

                // Spring Security authorities oluştur
                List<SimpleGrantedAuthority> authorities = createAuthorities(roleResult.allRoles);

                // Authentication token oluştur
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userPrincipal, null, authorities);

                // Security context'e set et
                SecurityContextHolder.getContext().setAuthentication(authToken);

                logger.debug("✅ Authentication successful for user: {} with roles: {} (realm: {}, client: {})",
                        username,
                        roleResult.allRoles,
                        roleResult.realmRoles,
                        roleResult.clientRoles);

                logger.info("🔐 User authenticated via KrakenD: {} with {} roles", username, roleResult.allRoles.size());

            } else {
                logger.warn("⚠️ Missing required user headers (X-User-ID or X-Username) for endpoint: {}", requestURI);
            }

        } catch (Exception e) {
            logger.error("❌ Error processing authentication headers for URI: {}", requestURI, e);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private boolean isPublicEndpoint(String uri) {
        return uri.equals("/") ||
                // OAuth2 Endpoints - BYPASS header authentication ✅
                uri.startsWith("/login/oauth2/") ||
                uri.startsWith("/oauth2/") ||
                uri.equals("/login") ||
                uri.equals("/logout") ||
                uri.equals("/login/oauth2/code/keycloak") ||

                uri.equals("/oauth/callback") || // ✅ CRITICAL: OAuth callback public
                uri.equals("/oauth-callback") || // ✅ CRITICAL: OAuth callback public
                // Static Resources
                uri.startsWith("/css/") ||
                uri.startsWith("/js/") ||
                uri.startsWith("/images/") ||
                uri.startsWith("/webjars/") ||
                uri.equals("/favicon.ico") ||
                uri.equals("/error") ||
                // Health Endpoints
                uri.equals("/health") ||
                uri.startsWith("/actuator/");
    }
    /**
     * KrakenD'den gelen role header'ını parse eder
     * Format örnekleri:
     * - "hr_user,hr_admin"
     * - "[\"hr_user\",\"hr_admin\"]"
     * - "realm_access.roles=[hr_user],resource_access.hr-portal.roles=[hr_admin]"
     */
    private RoleParseResult parseRolesFromHeader(String rolesHeader) {
        List<String> realmRoles = new ArrayList<>();
        List<String> clientRoles = new ArrayList<>();
        List<String> allRoles = new ArrayList<>();

        if (rolesHeader != null && !rolesHeader.trim().isEmpty()) {
            try {
                // JSON array format: ["hr_user","hr_admin"]
                if (rolesHeader.startsWith("[") && rolesHeader.endsWith("]")) {
                    String cleanRoles = rolesHeader.replaceAll("[\\[\\]\"]", "").trim();
                    allRoles.addAll(Arrays.asList(cleanRoles.split(",")));
                }
                // Comma separated: hr_user,hr_admin
                else if (rolesHeader.contains(",")) {
                    allRoles.addAll(Arrays.asList(rolesHeader.split(",")));
                }
                // Single role: hr_user
                else {
                    allRoles.add(rolesHeader);
                }

                // Clean up roles
                allRoles = allRoles.stream()
                        .map(String::trim)
                        .filter(role -> !role.isEmpty())
                        .distinct()
                        .collect(Collectors.toList());

                // Realm vs Client role classification
                for (String role : allRoles) {
                    if (role.startsWith("hr_") || role.equals("admin") || role.equals("user")) {
                        clientRoles.add(role);  // HR Portal specific roles
                    } else {
                        realmRoles.add(role);   // Keycloak realm roles
                    }
                }

            } catch (Exception e) {
                logger.warn("⚠️ Error parsing roles header: '{}', using default roles", rolesHeader, e);
                allRoles.add("user"); // Default role
                realmRoles.add("user");
            }
        }

        // Default role if empty
        if (allRoles.isEmpty()) {
            allRoles.add("user");
            realmRoles.add("user");
        }

        return new RoleParseResult(realmRoles, clientRoles, allRoles);
    }

    private List<SimpleGrantedAuthority> createAuthorities(List<String> roles) {
        return roles.stream()
                .map(role -> {
                    // ROLE_ prefix ekle eğer yoksa
                    String authority = role.startsWith("ROLE_") ? role : "ROLE_" + role.toUpperCase();
                    return new SimpleGrantedAuthority(authority);
                })
                .collect(Collectors.toList());
    }

    private String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIP = request.getHeader("X-Real-IP");
        if (xRealIP != null && !xRealIP.isEmpty()) {
            return xRealIP;
        }
        return request.getRemoteAddr();
    }

    /**
     * Role parsing result holder
     */
    private static class RoleParseResult {
        final List<String> realmRoles;
        final List<String> clientRoles;
        final List<String> allRoles;

        RoleParseResult(List<String> realmRoles, List<String> clientRoles, List<String> allRoles) {
            this.realmRoles = realmRoles;
            this.clientRoles = clientRoles;
            this.allRoles = allRoles;
        }
    }
}