package com.programandoenjava.jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class ResourceController {

    // Endpoints que requieren permiso accounts:read
    @GetMapping("/accounts/data")
    @PreAuthorize("hasAuthority('accounts:read')")
    public ResponseEntity<Map<String, Object>> readAccountData(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Reading account data - Requires accounts:read permission");
        response.put("user", auth.getName());
        response.put("authorities", auth.getAuthorities());
        response.put("data", "Sample account data for reading");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/accounts/reports")
    @PreAuthorize("hasAuthority('accounts:read')")
    public ResponseEntity<Map<String, Object>> readAccountReports(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Reading account reports - Requires accounts:read permission");
        response.put("user", auth.getName());
        response.put("reports", "List of account reports");
        return ResponseEntity.ok(response);
    }

    // Endpoints que requieren permiso accounts:write
    @PostMapping("/accounts/create")
    @PreAuthorize("hasAuthority('accounts:write')")
    public ResponseEntity<Map<String, Object>> createAccount(@RequestBody Map<String, Object> data, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Creating account - Requires accounts:write permission");
        response.put("user", auth.getName());
        response.put("createdAccount", data);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/accounts/update/{id}")
    @PreAuthorize("hasAuthority('accounts:write')")
    public ResponseEntity<Map<String, Object>> updateAccount(@PathVariable Integer id, @RequestBody Map<String, Object> data, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Updating account - Requires accounts:write permission");
        response.put("accountId", id);
        response.put("updatedBy", auth.getName());
        response.put("updatedData", data);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/accounts/delete/{id}")
    @PreAuthorize("hasAuthority('accounts:write')")
    public ResponseEntity<Map<String, Object>> deleteAccount(@PathVariable Integer id, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Deleting account - Requires accounts:write permission");
        response.put("accountId", id);
        response.put("deletedBy", auth.getName());
        return ResponseEntity.ok(response);
    }

    // Endpoints que requieren permiso transfers:create
    @PostMapping("/transfers/create")
    @PreAuthorize("hasAuthority('transfers:create')")
    public ResponseEntity<Map<String, Object>> createTransfer(@RequestBody Map<String, Object> transferData, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Creating transfer - Requires transfers:create permission");
        response.put("user", auth.getName());
        response.put("transfer", transferData);
        return ResponseEntity.ok(response);
    }

    // Endpoints que requieren permiso beneficiaries:manage
    @PostMapping("/beneficiaries/add")
    @PreAuthorize("hasAuthority('beneficiaries:manage')")
    public ResponseEntity<Map<String, Object>> addBeneficiary(@RequestBody Map<String, Object> beneficiaryData, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Adding beneficiary - Requires beneficiaries:manage permission");
        response.put("user", auth.getName());
        response.put("beneficiary", beneficiaryData);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/beneficiaries/update/{id}")
    @PreAuthorize("hasAuthority('beneficiaries:manage')")
    public ResponseEntity<Map<String, Object>> updateBeneficiary(@PathVariable Integer id, @RequestBody Map<String, Object> data, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Updating beneficiary - Requires beneficiaries:manage permission");
        response.put("beneficiaryId", id);
        response.put("updatedBy", auth.getName());
        response.put("updatedData", data);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/beneficiaries/delete/{id}")
    @PreAuthorize("hasAuthority('beneficiaries:manage')")
    public ResponseEntity<Map<String, Object>> deleteBeneficiary(@PathVariable Integer id, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Deleting beneficiary - Requires beneficiaries:manage permission");
        response.put("beneficiaryId", id);
        response.put("deletedBy", auth.getName());
        return ResponseEntity.ok(response);
    }
}