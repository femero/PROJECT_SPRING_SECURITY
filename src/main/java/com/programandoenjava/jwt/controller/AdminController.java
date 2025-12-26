package com.programandoenjava.jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {

    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getDashboard(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Admin Dashboard - Only ADMIN role can access");
        response.put("user", auth.getName());
        response.put("authorities", auth.getAuthorities());
        response.put("timestamp", String.valueOf(System.currentTimeMillis()));
        return ResponseEntity.ok(response);
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getAllUsers(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "List of all users - Admin only");
        response.put("user", auth.getName());
        response.put("data", "User list would be here");
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> deleteUser(@PathVariable Integer id, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "User deleted successfully - Admin only");
        response.put("deletedUserId", id);
        response.put("deletedBy", auth.getName());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/settings")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> updateSettings(@RequestBody Map<String, Object> settings, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Settings updated - Admin only");
        response.put("updatedBy", auth.getName());
        response.put("settings", settings);
        return ResponseEntity.ok(response);
    }

    // Endpoints adicionales que demuestran el uso de scopes
    @GetMapping("/beneficiaries/all")
    @PreAuthorize("hasAuthority('beneficiaries:manage')")
    public ResponseEntity<Map<String, Object>> getAllBeneficiaries(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "All beneficiaries - Requires beneficiaries:manage");
        response.put("user", auth.getName());
        response.put("data", "Complete beneficiaries list");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/transfers/all")
    @PreAuthorize("hasAuthority('transfers:create')")
    public ResponseEntity<Map<String, Object>> getAllTransfers(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "All transfers - Requires transfers:create");
        response.put("user", auth.getName());
        response.put("data", "Complete transfers list");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/accounts/all")
    @PreAuthorize("hasAuthority('accounts:write')")
    public ResponseEntity<Map<String, Object>> getAllAccounts(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "All accounts with write access - Requires accounts:write");
        response.put("user", auth.getName());
        response.put("data", "Complete accounts list");
        return ResponseEntity.ok(response);
    }
}