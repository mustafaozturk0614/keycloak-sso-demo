package com.example.hrportal.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.access.prepost.PreAuthorize;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.HttpServletRequest;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 🚀 HR Portal REST API Controller - Modern JWT SSO
 * KrakenD Gateway entegrasyonu için RESTful endpoints
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = {"http://localhost:8000", "http://localhost:8081"})
public class HRRestController {

    private static final Logger logger = LoggerFactory.getLogger(HRRestController.class);

    /**
     * 📊 Dashboard API - Ana dashboard verileri
     */
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, Object>> getDashboard(HttpServletRequest request) {
        logger.info("📊 Dashboard API called from IP: {}", getClientIP(request));

        try {
            UserContext userContext = getUserContext();

            Map<String, Object> dashboardData = new HashMap<>();

            // 👤 User info
            dashboardData.put("user", Map.of(
                    "id", userContext.getUserId(),
                    "username", userContext.getUsername(),
                    "email", userContext.getEmail(),
                    "fullName", userContext.getFullName(),
                    "roles", userContext.getRoles()
            ));

            // 📈 Dashboard statistics
            dashboardData.put("stats", getDashboardStats());

            // 🎯 Quick actions
            dashboardData.put("quickActions", getQuickActions(userContext.getRoles()));

            // 📱 Recent activities
            dashboardData.put("activities", getRecentActivities());

            // ⚡ Performance metrics
            dashboardData.put("performance", getPerformanceMetrics());

            dashboardData.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

            logger.info("✅ Dashboard data prepared for user: {}", userContext.getUsername());
            return ResponseEntity.ok(dashboardData);

        } catch (Exception e) {
            logger.error("❌ Error preparing dashboard data", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Dashboard data preparation failed", "message", e.getMessage()));
        }
    }

    /**
     * 👥 Employees API - Personel listesi
     */
    @GetMapping("/employees")
    @PreAuthorize("hasAnyRole('hr_admin', 'hr_user', 'admin')")
    public ResponseEntity<Map<String, Object>> getEmployees(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String department,
            HttpServletRequest request) {

        logger.info("👥 Employees API called - page: {}, size: {}, search: {}, department: {}",
                page, size, search, department);

        try {
            UserContext userContext = getUserContext();

            List<Map<String, Object>> employees = getFilteredEmployees(search, department);

            // Pagination
            int total = employees.size();
            int startIndex = Math.min(page * size, total);
            int endIndex = Math.min(startIndex + size, total);
            List<Map<String, Object>> paginatedEmployees = employees.subList(startIndex, endIndex);

            Map<String, Object> response = Map.of(
                    "employees", paginatedEmployees,
                    "pagination", Map.of(
                            "page", page,
                            "size", size,
                            "total", total,
                            "totalPages", (int) Math.ceil((double) total / size)
                    ),
                    "filters", Map.of(
                            "search", search != null ? search : "",
                            "department", department != null ? department : ""
                    ),
                    "metadata", Map.of(
                            "requestedBy", userContext.getUsername(),
                            "timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                    )
            );

            logger.info("✅ Employees data returned: {} records", paginatedEmployees.size());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("❌ Error fetching employees", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to fetch employees", "message", e.getMessage()));
        }
    }

    /**
     * ➕ Add Employee API - Yeni personel ekleme
     */
    @PostMapping("/employees")
    @PreAuthorize("hasAnyRole('hr_admin', 'admin')")
    public ResponseEntity<Map<String, Object>> addEmployee(
            @RequestBody Map<String, Object> employeeData,
            HttpServletRequest request) {

        logger.info("➕ Add employee API called");

        try {
            UserContext userContext = getUserContext();

            // Validation
            List<String> validationErrors = validateEmployeeData(employeeData);
            if (!validationErrors.isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", "Validation failed", "details", validationErrors));
            }

            // Mock save operation
            Map<String, Object> savedEmployee = new HashMap<>(employeeData);
            savedEmployee.put("id", UUID.randomUUID().toString());
            savedEmployee.put("createdAt", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            savedEmployee.put("createdBy", userContext.getUsername());
            savedEmployee.put("status", "ACTIVE");

            logger.info("✅ Employee added successfully: {}", savedEmployee.get("name"));

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of(
                            "message", "Employee added successfully",
                            "employee", savedEmployee,
                            "addedBy", userContext.getUsername()
                    ));

        } catch (Exception e) {
            logger.error("❌ Error adding employee", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to add employee", "message", e.getMessage()));
        }
    }

    /**
     * 🏖️ Leave Requests API - İzin talepleri
     */
    @GetMapping("/leave/requests")
    public ResponseEntity<Map<String, Object>> getLeaveRequests(
            @RequestParam(required = false) String userId,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            HttpServletRequest request) {

        logger.info("🏖️ Leave requests API called - userId: {}, status: {}", userId, status);

        try {
            UserContext userContext = getUserContext();

            List<Map<String, Object>> leaveRequests = getLeaveRequests(userContext, status);

            // Role-based filtering
            if (!hasHRAccess(userContext.getRoles())) {
                // Employee can only see their own requests
                String currentUserId = userContext.getUserId();
                leaveRequests = leaveRequests.stream()
                        .filter(req -> currentUserId.equals(req.get("userId")))
                        .toList();
            } else if (userId != null && !userId.trim().isEmpty()) {
                // HR can filter by specific user
                leaveRequests = leaveRequests.stream()
                        .filter(req -> userId.equals(req.get("userId")))
                        .toList();
            }

            // Pagination
            int total = leaveRequests.size();
            int startIndex = Math.min(page * size, total);
            int endIndex = Math.min(startIndex + size, total);
            List<Map<String, Object>> paginatedRequests = leaveRequests.subList(startIndex, endIndex);

            Map<String, Object> response = Map.of(
                    "requests", paginatedRequests,
                    "pagination", Map.of(
                            "page", page,
                            "size", size,
                            "total", total,
                            "totalPages", (int) Math.ceil((double) total / size)
                    ),
                    "summary", Map.of(
                            "pending", leaveRequests.stream().mapToInt(req -> "PENDING".equals(req.get("status")) ? 1 : 0).sum(),
                            "approved", leaveRequests.stream().mapToInt(req -> "APPROVED".equals(req.get("status")) ? 1 : 0).sum(),
                            "rejected", leaveRequests.stream().mapToInt(req -> "REJECTED".equals(req.get("status")) ? 1 : 0).sum()
                    ),
                    "permissions", Map.of(
                            "canApprove", hasHRAccess(userContext.getRoles()),
                            "canReject", hasHRAccess(userContext.getRoles()),
                            "canCreate", true
                    )
            );

            logger.info("✅ Leave requests returned: {} records", paginatedRequests.size());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("❌ Error fetching leave requests", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to fetch leave requests", "message", e.getMessage()));
        }
    }

    /**
     * 💼 Job Postings API - İş ilanları
     */
    @GetMapping("/recruitment/jobs")
    @PreAuthorize("hasAnyRole('hr_admin', 'hr_user', 'admin')")
    public ResponseEntity<Map<String, Object>> getJobPostings(HttpServletRequest request) {
        logger.info("💼 Job postings API called");

        try {
            UserContext userContext = getUserContext();

            List<Map<String, Object>> jobPostings = getJobPostings();

            Map<String, Object> response = Map.of(
                    "jobs", jobPostings,
                    "summary", Map.of(
                            "total", jobPostings.size(),
                            "active", jobPostings.stream().mapToInt(job -> "ACTIVE".equals(job.get("status")) ? 1 : 0).sum(),
                            "closed", jobPostings.stream().mapToInt(job -> "CLOSED".equals(job.get("status")) ? 1 : 0).sum()
                    ),
                    "permissions", Map.of(
                            "canCreate", hasAdminAccess(userContext.getRoles()),
                            "canEdit", hasHRAccess(userContext.getRoles()),
                            "canDelete", hasAdminAccess(userContext.getRoles())
                    )
            );

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("❌ Error fetching job postings", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to fetch job postings", "message", e.getMessage()));
        }
    }

    /**
     * 👤 User Profile API - Kullanıcı profili
     */
    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getUserProfile() {
        logger.info("👤 User profile API called");

        try {
            UserContext userContext = getUserContext();

            Map<String, Object> profile = Map.of(
                    "id", userContext.getUserId(),
                    "username", userContext.getUsername(),
                    "email", userContext.getEmail(),
                    "fullName", userContext.getFullName(),
                    "roles", userContext.getRoles(),
                    "permissions", Map.of(
                            "hasHRAccess", hasHRAccess(userContext.getRoles()),
                            "hasAdminAccess", hasAdminAccess(userContext.getRoles())
                    ),
                    "preferences", Map.of(
                            "language", "tr",
                            "timezone", "Europe/Istanbul",
                            "theme", "light"
                    ),
                    "lastLogin", LocalDateTime.now().minusHours(2).format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                    "accountStatus", "ACTIVE"
            );

            return ResponseEntity.ok(profile);

        } catch (Exception e) {
            logger.error("❌ Error fetching user profile", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to fetch profile", "message", e.getMessage()));
        }
    }

    /**
     * 📊 Analytics API - Analitik veriler
     */
    @GetMapping("/analytics")
    @PreAuthorize("hasAnyRole('hr_admin', 'admin')")
    public ResponseEntity<Map<String, Object>> getAnalytics(
            @RequestParam(defaultValue = "30") int days,
            HttpServletRequest request) {

        logger.info("📊 Analytics API called for {} days", days);

        try {
            Map<String, Object> analytics = Map.of(
                    "employeeMetrics", Map.of(
                            "totalEmployees", 245,
                            "newHires", 8,
                            "turnoverRate", 3.2,
                            "averageTenure", "3.5 years"
                    ),
                    "leaveMetrics", Map.of(
                            "totalLeaveRequests", 156,
                            "approvedLeaves", 142,
                            "pendingLeaves", 12,
                            "averageLeaveDays", 15.3
                    ),
                    "recruitmentMetrics", Map.of(
                            "openPositions", 8,
                            "applications", 234,
                            "interviewsScheduled", 45,
                            "offersMade", 12
                    ),
                    "performanceMetrics", Map.of(
                            "averageRating", 4.2,
                            "completedEvaluations", 89,
                            "pendingEvaluations", 15
                    ),
                    "trends", generateTrendData(days),
                    "generatedAt", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
            );

            return ResponseEntity.ok(analytics);

        } catch (Exception e) {
            logger.error("❌ Error generating analytics", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Failed to generate analytics", "message", e.getMessage()));
        }
    }

    /**
     * 🔍 Search API - Global arama
     */
    @GetMapping("/search")
    public ResponseEntity<Map<String, Object>> search(
            @RequestParam String query,
            @RequestParam(defaultValue = "all") String type,
            @RequestParam(defaultValue = "10") int limit,
            HttpServletRequest request) {

        logger.info("🔍 Search API called - query: {}, type: {}", query, type);

        try {
            UserContext userContext = getUserContext();

            Map<String, Object> searchResults = new HashMap<>();

            if ("all".equals(type) || "employees".equals(type)) {
                searchResults.put("employees", searchEmployees(query, limit, userContext));
            }

            if ("all".equals(type) || "leaves".equals(type)) {
                searchResults.put("leaves", searchLeaveRequests(query, limit, userContext));
            }

            if ("all".equals(type) || "jobs".equals(type) && hasHRAccess(userContext.getRoles())) {
                searchResults.put("jobs", searchJobPostings(query, limit));
            }

            searchResults.put("query", query);
            searchResults.put("type", type);
            searchResults.put("searchedBy", userContext.getUsername());
            searchResults.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));

            return ResponseEntity.ok(searchResults);

        } catch (Exception e) {
            logger.error("❌ Error performing search", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Search failed", "message", e.getMessage()));
        }
    }

    /**
     * ❤️ Health Check API - Sistem durumu
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> health = Map.of(
                "status", "UP",
                "timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
                "service", "hr-portal-backend",
                "version", "2.0.0-JWT",
                "environment", "development",
                "uptime", getUptime(),
                "checks", Map.of(
                        "database", "UP",
                        "jwt", "UP",
                        "keycloak", "UP"
                )
        );

        return ResponseEntity.ok(health);
    }

    // 🛠️ Helper Methods

    private UserContext getUserContext() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();

            return new UserContext(
                    jwt.getSubject(),
                    jwt.getClaimAsString("preferred_username"),
                    jwt.getClaimAsString("email"),
                    jwt.getClaimAsString("name"),
                    extractRoles(jwt)
            );
        }

        throw new SecurityException("No valid JWT token found");
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Jwt jwt) {
        List<String> roles = new ArrayList<>();

        // Realm roles
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess != null && realmAccess.get("roles") instanceof List) {
            roles.addAll((List<String>) realmAccess.get("roles"));
        }

        // Resource roles
        Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
        if (resourceAccess != null) {
            Map<String, Object> hrPortal = (Map<String, Object>) resourceAccess.get("hr-portal");
            if (hrPortal != null && hrPortal.get("roles") instanceof List) {
                roles.addAll((List<String>) hrPortal.get("roles"));
            }
        }

        return roles;
    }

    private boolean hasHRAccess(List<String> roles) {
        return roles.contains("hr_admin") || roles.contains("hr_user") || roles.contains("admin");
    }

    private boolean hasAdminAccess(List<String> roles) {
        return roles.contains("hr_admin") || roles.contains("admin");
    }

    private String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    // 📊 Data Helper Methods

    private Map<String, Object> getDashboardStats() {
        return Map.of(
                "totalEmployees", 245,
                "activeEmployees", 238,
                "pendingLeaves", 12,
                "openPositions", 8,
                "newApplications", 34,
                "averageSalary", 15450,
                "lastUpdated", LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm"))
        );
    }

    private List<Map<String, Object>> getQuickActions(List<String> roles) {
        List<Map<String, Object>> actions = new ArrayList<>();

        if (hasAdminAccess(roles)) {
            actions.add(Map.of("id", "add_employee", "title", "Yeni Personel", "icon", "user-plus", "url", "/employees/add"));
            actions.add(Map.of("id", "system_settings", "title", "Sistem Ayarları", "icon", "settings", "url", "/settings"));
        }

        if (hasHRAccess(roles)) {
            actions.add(Map.of("id", "leave_requests", "title", "İzin Talepleri", "icon", "calendar", "url", "/leave/requests"));
            actions.add(Map.of("id", "recruitment", "title", "İşe Alım", "icon", "briefcase", "url", "/recruitment/jobs"));
        }

        actions.add(Map.of("id", "my_profile", "title", "Profilim", "icon", "user", "url", "/settings"));

        return actions;
    }

    private List<Map<String, Object>> getRecentActivities() {
        return List.of(
                Map.of("id", 1, "action", "Yeni personel eklendi", "user", "HR Admin", "time", "2 dakika önce", "type", "success"),
                Map.of("id", 2, "action", "İzin talebi onaylandı", "user", "Ahmet Yılmaz", "time", "15 dakika önce", "type", "info"),
                Map.of("id", 3, "action", "Performans değerlendirmesi", "user", "Ayşe Demir", "time", "1 saat önce", "type", "warning"),
                Map.of("id", 4, "action", "Yeni iş ilanı yayınlandı", "user", "İK Uzmanı", "time", "2 saat önce", "type", "success")
        );
    }

    private Map<String, Object> getPerformanceMetrics() {
        return Map.of(
                "responseTime", "95ms",
                "uptime", "99.9%",
                "activeUsers", 23,
                "systemLoad", "45%"
        );
    }

    // Mock data methods implementation...
    private List<Map<String, Object>> getFilteredEmployees(String search, String department) {
        // Implementation from previous controller
        return new ArrayList<>();
    }

    private List<Map<String, Object>> getLeaveRequests(UserContext userContext, String status) {
        // Implementation from previous controller
        return new ArrayList<>();
    }

    private List<Map<String, Object>> getJobPostings() {
        // Implementation from previous controller
        return new ArrayList<>();
    }

    private List<String> validateEmployeeData(Map<String, Object> data) {
        List<String> errors = new ArrayList<>();

        if (data.get("name") == null || data.get("name").toString().trim().isEmpty()) {
            errors.add("İsim gerekli");
        }

        if (data.get("email") == null || !data.get("email").toString().contains("@")) {
            errors.add("Geçerli email gerekli");
        }

        if (data.get("department") == null || data.get("department").toString().trim().isEmpty()) {
            errors.add("Departman gerekli");
        }

        return errors;
    }

    private List<Map<String, Object>> generateTrendData(int days) {
        List<Map<String, Object>> trends = new ArrayList<>();
        for (int i = days; i >= 0; i--) {
            trends.add(Map.of(
                    "date", LocalDateTime.now().minusDays(i).format(DateTimeFormatter.ofPattern("yyyy-MM-dd")),
                    "employees", 240 + (int)(Math.random() * 10),
                    "leaves", (int)(Math.random() * 5),
                    "applications", (int)(Math.random() * 15)
            ));
        }
        return trends;
    }

    private List<Map<String, Object>> searchEmployees(String query, int limit, UserContext userContext) {
        if (!hasHRAccess(userContext.getRoles())) {
            return new ArrayList<>();
        }
        // Mock implementation
        return new ArrayList<>();
    }

    private List<Map<String, Object>> searchLeaveRequests(String query, int limit, UserContext userContext) {
        // Mock implementation
        return new ArrayList<>();
    }

    private List<Map<String, Object>> searchJobPostings(String query, int limit) {
        // Mock implementation
        return new ArrayList<>();
    }

    private String getUptime() {
        return "2h 15m";
    }

    // 👤 UserContext Inner Class
    private static class UserContext {
        private final String userId;
        private final String username;
        private final String email;
        private final String fullName;
        private final List<String> roles;

        public UserContext(String userId, String username, String email, String fullName, List<String> roles) {
            this.userId = userId;
            this.username = username;
            this.email = email;
            this.fullName = fullName;
            this.roles = roles != null ? roles : new ArrayList<>();
        }

        public String getUserId() { return userId; }
        public String getUsername() { return username; }
        public String getEmail() { return email; }
        public String getFullName() { return fullName; }
        public List<String> getRoles() { return roles; }
    }
}