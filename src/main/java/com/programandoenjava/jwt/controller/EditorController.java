package com.programandoenjava.jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/teller")
public class EditorController {

    @GetMapping("/accounts")
    @PreAuthorize("hasAnyRole('ADMIN', 'TELLER')")
    public ResponseEntity<Map<String, Object>> getAccounts(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Account list - ADMIN or TELLER can access");
        response.put("user", auth.getName());
        response.put("authorities", auth.getAuthorities());
        response.put("data", "Account list would be here");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/accounts")
    @PreAuthorize("hasAuthority('accounts:write')")
    public ResponseEntity<Map<String, Object>> createAccount(@RequestBody Map<String, Object> account, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Account created successfully - Requires accounts:write");
        response.put("createdBy", auth.getName());
        response.put("account", account);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/accounts/{id}")
    @PreAuthorize("hasAuthority('accounts:write')")
    public ResponseEntity<Map<String, Object>> updateAccount(@PathVariable Integer id, @RequestBody Map<String, Object> account, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Account updated successfully - Requires accounts:write");
        response.put("accountId", id);
        response.put("updatedBy", auth.getName());
        response.put("account", account);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/accounts/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> deleteAccount(@PathVariable Integer id, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Account deleted - Only ADMIN can delete");
        response.put("accountId", id);
        response.put("deletedBy", auth.getName());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/transfers")
    @PreAuthorize("hasAuthority('transfers:create')")
    public ResponseEntity<Map<String, Object>> createTransfer(@RequestBody Map<String, Object> transfer, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Transfer created successfully - Requires transfers:create");
        response.put("createdBy", auth.getName());
        response.put("transfer", transfer);
        return ResponseEntity.ok(response);
    }
}