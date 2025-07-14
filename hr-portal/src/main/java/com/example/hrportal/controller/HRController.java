package com.example.hrportal.controller;

import com.example.hrportal.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 🏢 HR Portal Ana Controller - KrakenD + JWT SSO Integration
 * KrakenD Gateway ile Header-based Authentication
 */
@Controller
@RequiredArgsConstructor
public class HRController {
    private static final Logger logger = LoggerFactory.getLogger(HRController.class);


    private final JwtDecoder jwtDecoder;

    /**
     * 🏠 Landing Page - Ana Giriş Sayfası (Public)
     */
    @GetMapping("/")
    public String landing(Model model, HttpServletRequest request,
                          @RequestParam(value = "error", required = false) String error,
                          @RequestParam(value = "logout", required = false) String logout) {

        logger.info("🏠 Landing page accessed from IP: {}", getClientIP(request));

        // Error/Success mesajları
        addStatusMessages(model, error, logout);

        // System info
        model.addAttribute("currentTime", LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")));
        model.addAttribute("systemVersion", "HR Portal v2.0 - KrakenD Optimized");

        return "landing";
    }

    /**
     * 📊 Dashboard - Ana Kontrol Paneli (Header Authentication Required)
     */
    /**
     * 📊 Dashboard - Ana Kontrol Paneli (Header Authentication Required)
     */
    @GetMapping("/dashboard")
    public String dashboard(Model model, HttpServletRequest request) {
        try {
            UserPrincipal user = null;

            // 1. ✅ KrakenD'den gelen propagated header'ları kontrol et (en hızlı)
            user = getUserFromKrakendHeaders(request);
            if (user != null) {
                setSecurityContext(user);
                addUserToModel(model, user);
                addDashboardStats(model);
                addQuickActions(model, user);
                addRecentActivities(model);
                addPerformanceMetrics(model);

                logger.info("✅ Dashboard loaded via KrakenD headers for: {} with roles: {}",
                        user.getUsername(), user.getAllRoles());
                return "dashboard";
            }

            // 2. 🔄 Fallback: Authorization header'ından JWT parse et
            String jwtToken = getJwtFromHeaders(request);
            if (jwtToken != null) {
                Jwt jwt = jwtDecoder.decode(jwtToken);
                user = createUserFromJWT(jwt);
                setSecurityContext(user);
                addUserToModel(model, user);
                addDashboardStats(model);
                addQuickActions(model, user);
                addRecentActivities(model);
                addPerformanceMetrics(model);

                logger.info("✅ Dashboard loaded via JWT parsing for: {} with roles: {}",
                        user.getUsername(), user.getAllRoles());
                return "dashboard";
            }

            // 3. ❌ Hiçbiri yoksa auth gerekli
            logger.warn("⚠️ No authentication found for dashboard access");
            return "redirect:http://localhost:8000/?error=auth_required";

        } catch (Exception e) {
            logger.error("❌ Error loading dashboard", e);
            return "redirect:http://localhost:8000/?error=dashboard_error";
        }
    }
    @SuppressWarnings("unchecked")
    private List<String> extractRealmRoles(Jwt jwt) {
        try {
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                return (List<String>) realmAccess.get("roles");
            }
        } catch (Exception e) {
            logger.warn("Error extracting realm roles", e);
        }
        return List.of("user"); // Default role
    }
    /**
     * KrakenD'den gelen propagated header'lardan user oluştur (birincil yöntem)
     */
    private UserPrincipal getUserFromKrakendHeaders(HttpServletRequest request) {
        String userId = request.getHeader("X-User-ID");
        String username = request.getHeader("X-Username");
        String email = request.getHeader("X-User-Email");
        String fullName = request.getHeader("X-User-Name");
        String rolesHeader = request.getHeader("X-User-Roles");

        logger.debug("🔍 KrakenD Headers - UserId: {}, Username: {}, Email: {}, Roles: {}",
                userId, username, email, rolesHeader);

        if (userId != null && username != null) {
            List<String> realmRoles = parseRolesFromHeader(rolesHeader);

            UserPrincipal user = UserPrincipal.builder()
                    .userId(userId)
                    .username(username)
                    .email(email)
                    .fullName(fullName)
                    .realmRoles(realmRoles)
                    .clientRoles(List.of()) // Client roles boş bırakabilirsiniz
                    .build();

            logger.debug("✅ User created from KrakenD headers: {}", user);
            return user;
        }

        logger.debug("❌ Insufficient KrakenD headers for user creation");
        return null;
    }

    /**
     * Authorization header'larından JWT token'ı al (ikincil yöntem)
     */
    private String getJwtFromHeaders(HttpServletRequest request) {
        // 1. Authorization: Bearer header'ından al
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            logger.debug("🎯 JWT found in Authorization header");
            return token;
        }

        // 2. Backup: X-JWT-Token header'ından al
        String jwtHeader = request.getHeader("X-JWT-Token");
        if (jwtHeader != null && !jwtHeader.trim().isEmpty()) {
            logger.debug("🎯 JWT found in X-JWT-Token header");
            return jwtHeader;
        }

        logger.debug("❌ No JWT token found in headers");
        return null;
    }

    /**
     * JWT'den UserPrincipal oluştur
     */
    private UserPrincipal createUserFromJWT(Jwt jwt) {
        List<String> realmRoles = extractRealmRoles(jwt);

        return UserPrincipal.builder()
                .userId(jwt.getClaimAsString("sub"))
                .username(jwt.getClaimAsString("preferred_username"))
                .email(jwt.getClaimAsString("email"))
                .fullName(jwt.getClaimAsString("name"))
                .realmRoles(realmRoles)
                .clientRoles(List.of())
                .build();
    }

    /**
     * Role header'ını parse et
     */
    private List<String> parseRolesFromHeader(String rolesHeader) {
        if (rolesHeader == null || rolesHeader.trim().isEmpty()) {
            return List.of("user"); // Default role
        }

        try {
            // Comma separated roles: "hr_user,HR_ACCESS,hr_admin"
            List<String> roles = Arrays.stream(rolesHeader.split(","))
                    .map(String::trim)
                    .filter(role -> !role.isEmpty())
                    .distinct()
                    .collect(Collectors.toList());

            return roles.isEmpty() ? List.of("user") : roles;
        } catch (Exception e) {
            logger.warn("⚠️ Error parsing roles header: '{}', using default", rolesHeader, e);
            return List.of("user");
        }
    }

    /**
     * SecurityContext'e user'ı set et
     */
    private void setSecurityContext(UserPrincipal user) {
        List<SimpleGrantedAuthority> authorities = user.getAllRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .collect(Collectors.toList());

        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(user, null, authorities);

        SecurityContextHolder.getContext().setAuthentication(authToken);
        logger.debug("✅ SecurityContext set for user: {} with authorities: {}",
                user.getUsername(), authorities);
    }

    /**
     * Model'e user bilgilerini ekle
     */
    private void addUserToModel(Model model, UserPrincipal user) {
        model.addAttribute("userName", user.getUsername());
        model.addAttribute("userEmail", user.getEmail());
        model.addAttribute("fullName", user.getFullName());
        model.addAttribute("userId", user.getUserId());
        model.addAttribute("userRoles", user.getAllRoles());
    }
    /**
     * 👥 Employees - Personel Listesi (HR Access Required)
     */
    @GetMapping("/employees")
    public String employees(Model model, HttpServletRequest request,
                            @RequestParam(value = "search", required = false) String search,
                            @RequestParam(value = "department", required = false) String department,
                            @RequestParam(value = "page", defaultValue = "0") int page) {

        logger.info("👥 Employees page accessed from IP: {} - search: {}, dept: {}",
                getClientIP(request), search, department);

        UserPrincipal user = getCurrentUser();
        if (user == null) {
            return "redirect:http://localhost:8000/?error=auth_required";
        }

        // Role-based access control - HR_ACCESS minimum seviye için employees görüntüleme
        if (!user.canViewEmployees()) {
            logger.warn("⚠️ Unauthorized employees access by user: {} with roles: {}",
                    user.getUsername(), user.getAllRoles());
            return "redirect:http://localhost:8000/?error=access_denied";
        }

        // 📋 Employee data with filtering
        List<Map<String, Object>> employees = getFilteredEmployees(search, department);

        model.addAttribute("employees", employees);
        model.addAttribute("totalEmployees", employees.size());
        model.addAttribute("searchTerm", search != null ? search : "");
        model.addAttribute("selectedDepartment", department != null ? department : "");
        model.addAttribute("departments", getDepartments());
        model.addAttribute("currentUser", user.getUsername());
        model.addAttribute("userRoles", user.getAllRoles());

        return "employees/list";
    }

    /**
     * ➕ Add Employee - Yeni Personel Ekleme (Admin Access Required)
     */
    @GetMapping("/employees/add")
    public String addEmployee(Model model, HttpServletRequest request) {
        logger.info("➕ Add employee page accessed from IP: {}", getClientIP(request));

        UserPrincipal user = getCurrentUser();
        if (user == null) {
            return "redirect:http://localhost:8000/?error=auth_required";
        }

        // Admin access required for adding employees
        if (!user.canAddEmployees()) {
            logger.warn("⚠️ Unauthorized add employee access by user: {} with roles: {}",
                    user.getUsername(), user.getAllRoles());
            return "redirect:http://localhost:8000/?error=access_denied";
        }

        // 📝 Form data
        model.addAttribute("departments", getDepartments());
        model.addAttribute("positions", getPositions());
        model.addAttribute("locations", getLocations());
        model.addAttribute("currentUser", user.getUsername());

        return "employees/add";
    }

    /**
     * 🏖️ Leave Requests - İzin Talepleri (HR Access Required)
     */
    @GetMapping("/leave/requests")
    public String leaveRequests(Model model, HttpServletRequest request,
                                @RequestParam(value = "status", required = false) String status) {

        logger.info("🏖️ Leave requests page accessed from IP: {} - status: {}",
                getClientIP(request), status);

        UserPrincipal user = getCurrentUser();
        if (user == null) {
            return "redirect:http://localhost:8000/?error=auth_required";
        }

        if (!user.hasBasicHRAccess()) {
            return "redirect:http://localhost:8000/?error=access_denied";
        }

        // 📋 Leave requests (role-based filtering)
        List<Map<String, Object>> leaveRequests = getLeaveRequests(user, status);

        model.addAttribute("leaveRequests", leaveRequests);
        model.addAttribute("selectedStatus", status != null ? status : "");
        model.addAttribute("statusCounts", getLeaveStatusCounts(leaveRequests));
        model.addAttribute("canApprove", user.hasFullHRAccess());
        model.addAttribute("canEdit", user.canEditEmployees());
        model.addAttribute("currentUser", user.getUsername());

        return "leave/requests";
    }

    /**
     * ⚙️ Settings - Sistem Ayarları (Authenticated Required)
     */
    @GetMapping("/settings")
    public String settings(Model model, HttpServletRequest request) {
        logger.info("⚙️ Settings page accessed from IP: {}", getClientIP(request));

        UserPrincipal user = getCurrentUser();
        if (user == null) {
            return "redirect:http://localhost:8000/?error=auth_required";
        }

        // ⚙️ User settings
        model.addAttribute("currentUser", user.getUsername());
        model.addAttribute("userEmail", user.getEmail());
        model.addAttribute("fullName", user.getFullName());
        model.addAttribute("userRoles", user.getAllRoles());
        model.addAttribute("isAdmin", user.hasAdminAccess());

        return "settings/index";
    }

    // 🛠️ Helper Methods

    /**
     * KrakenD header'larından user context al - NO JWT PARSING!
     */
    private UserPrincipal getCurrentUser() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null && authentication.getPrincipal() instanceof UserPrincipal) {
                return (UserPrincipal) authentication.getPrincipal();
            }
        } catch (Exception e) {
            logger.error("❌ Error getting current user from security context", e);
        }

        return null;
    }

    private String getClientIP(HttpServletRequest request) {
        // KrakenD'den gelen real IP
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

    private void addStatusMessages(Model model, String error, String logout) {
        if ("auth_failed".equals(error)) {
            model.addAttribute("errorMessage", "🚫 Giriş başarısız. Lütfen tekrar deneyin.");
        } else if ("auth_required".equals(error)) {
            model.addAttribute("errorMessage", "🔐 Bu sayfaya erişim için giriş yapmanız gerekiyor.");
        } else if ("access_denied".equals(error)) {
            model.addAttribute("errorMessage", "⛔ Bu sayfaya erişim yetkiniz yok.");
        }

        if ("true".equals(logout)) {
            model.addAttribute("successMessage", "✅ Başarıyla çıkış yaptınız.");
        }
    }

    private void addDashboardStats(Model model) {
        model.addAttribute("totalEmployees", 245);
        model.addAttribute("activeEmployees", 238);
        model.addAttribute("pendingLeaves", 12);
        model.addAttribute("openPositions", 8);
        model.addAttribute("newApplications", 34);
        model.addAttribute("averageSalary", "₺15,450");
        model.addAttribute("lastUpdated", LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm")));
    }

    private void addQuickActions(Model model, UserPrincipal user) {
        List<Map<String, Object>> actions = new ArrayList<>();

        if (user.hasAdminAccess()) {
            actions.add(Map.of("id", "add_employee", "title", "Yeni Personel",
                    "icon", "user-plus", "url", "/employees/add"));
            actions.add(Map.of("id", "system_settings", "title", "Sistem Ayarları",
                    "icon", "settings", "url", "/settings"));
        }

        if (user.hasHRAccess()) {
            actions.add(Map.of("id", "leave_requests", "title", "İzin Talepleri",
                    "icon", "calendar", "url", "/leave/requests"));
            actions.add(Map.of("id", "employees", "title", "Personel Listesi",
                    "icon", "users", "url", "/employees"));
        }

        actions.add(Map.of("id", "my_profile", "title", "Profilim",
                "icon", "user", "url", "/settings"));

        model.addAttribute("quickActions", actions);
    }

    private void addRecentActivities(Model model) {
        List<Map<String, Object>> activities = List.of(
                Map.of("action", "Header authentication successful", "user", "KrakenD Gateway",
                        "time", "1 dakika önce", "type", "success"),
                Map.of("action", "JWT validation completed", "user", "API Gateway",
                        "time", "2 dakika önce", "type", "info"),
                Map.of("action", "User roles propagated", "user", "Security Filter",
                        "time", "3 dakika önce", "type", "success")
        );
        model.addAttribute("recentActivities", activities);
    }

    private void addPerformanceMetrics(Model model) {
        model.addAttribute("cpuUsage", 35); // Daha düşük - JWT duplikasyonu yok
        model.addAttribute("memoryUsage", 45); // Daha düşük - JWT parsing yok
        model.addAttribute("responseTime", "85ms"); // Daha hızlı
        model.addAttribute("uptime", "99.9%");
    }

    // 📋 Mock Data Methods (unchanged)
    private List<Map<String, Object>> getFilteredEmployees(String search, String department) {
        // Existing implementation...
        return createMockEmployees();
    }

    private List<Map<String, Object>> createMockEmployees() {
        // Existing implementation...
        return List.of();
    }

    private List<String> getDepartments() {
        return List.of("İnsan Kaynakları", "Bilgi İşlem", "Muhasebe", "Pazarlama", "Satış");
    }

    private List<String> getPositions() {
        return List.of("Uzman", "Kıdemli Uzman", "Supervisor", "Müdür", "Direktör");
    }

    private List<String> getLocations() {
        return List.of("İstanbul", "Ankara", "İzmir", "Bursa", "Antalya");
    }

    private List<Map<String, Object>> getLeaveRequests(UserPrincipal user, String status) {
        // Existing implementation...
        return List.of();
    }

    private Map<String, Integer> getLeaveStatusCounts(List<Map<String, Object>> requests) {
        // Existing implementation...
        return Map.of("PENDING", 3, "APPROVED", 5, "REJECTED", 1);
    }
}