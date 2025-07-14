package com.example.hrportal.security;

import lombok.Builder;

import java.util.ArrayList;
import java.util.List;

/**
 * 👤 User Principal Class
 * KrakenD header'larından oluşturulan user context
 */
@Builder
public class UserPrincipal {

    private final String userId;
    private final String username;
    private final String email;
    private final String fullName;
    private final List<String> realmRoles;
    private final List<String> clientRoles;

    public UserPrincipal(String userId, String username, String email, String fullName,
                         List<String> realmRoles, List<String> clientRoles) {
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.fullName = fullName;
        this.realmRoles = realmRoles != null ? realmRoles : List.of();
        this.clientRoles = clientRoles != null ? clientRoles : List.of();
    }

    // Getters
    public String getUserId() { return userId; }
    public String getUsername() { return username; }
    public String getEmail() { return email; }
    public String getFullName() { return fullName; }
    public List<String> getRealmRoles() { return realmRoles; }
    public List<String> getClientRoles() { return clientRoles; }

    // Combined roles
    public List<String> getAllRoles() {
        List<String> allRoles = new ArrayList<>();
        allRoles.addAll(realmRoles);
        allRoles.addAll(clientRoles);
        return allRoles;
    }

    // Role checking methods
    public boolean hasRole(String role) {
        return getAllRoles().contains(role);
    }

    public boolean hasAnyRole(String... roles) {
        List<String> userRoles = getAllRoles();
        for (String role : roles) {
            if (userRoles.contains(role)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasHRAccess() {
        return hasAnyRole("hr_admin", "hr_user", "HR_ACCESS", "admin");
    }

    public boolean hasAdminAccess() {
        return hasAnyRole("hr_admin", "admin");
    }

    public boolean hasBasicHRAccess() {
        return hasAnyRole("HR_ACCESS", "hr_user", "hr_admin", "admin");
    }

    public boolean hasFullHRAccess() {
        return hasAnyRole("hr_user", "hr_admin", "admin");
    }

    public boolean hasManagerAccess() {
        return hasAnyRole("MANAGER", "hr_admin", "admin");
    }

    public boolean canViewEmployees() {
        return hasBasicHRAccess();
    }

    public boolean canEditEmployees() {
        return hasFullHRAccess();
    }

    public boolean canAddEmployees() {
        return hasAdminAccess();
    }

    @Override
    public String toString() {
        return String.format("UserPrincipal{userId='%s', username='%s', email='%s', roles=%s}",
                userId, username, email, getAllRoles());
    }
}
