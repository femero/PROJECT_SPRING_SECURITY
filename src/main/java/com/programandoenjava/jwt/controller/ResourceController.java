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

    // Endpoints que requieren permiso READ
    @GetMapping("/read/data")
    @PreAuthorize("hasAuthority('READ')")
    public ResponseEntity<Map<String, Object>> readData(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Reading data - Requires READ permission");
        response.put("user", auth.getName());
        response.put("authorities", auth.getAuthorities());
        response.put("data", "Sample data for reading");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/read/reports")
    @PreAuthorize("hasAuthority('READ')")
    public ResponseEntity<Map<String, Object>> readReports(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Reading reports - Requires READ permission");
        response.put("user", auth.getName());
        response.put("reports", "List of reports");
        return ResponseEntity.ok(response);
    }

    // Endpoints que requieren permiso WRITE
    @PostMapping("/write/data")
    @PreAuthorize("hasAuthority('WRITE')")
    public ResponseEntity<Map<String, Object>> writeData(@RequestBody Map<String, Object> data, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Writing data - Requires WRITE permission");
        response.put("user", auth.getName());
        response.put("writtenData", data);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/write/update/{id}")
    @PreAuthorize("hasAuthority('WRITE')")
    public ResponseEntity<Map<String, Object>> updateData(@PathVariable Integer id, @RequestBody Map<String, Object> data, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Updating data - Requires WRITE permission");
        response.put("dataId", id);
        response.put("updatedBy", auth.getName());
        response.put("updatedData", data);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/write/delete/{id}")
    @PreAuthorize("hasAuthority('WRITE')")
    public ResponseEntity<Map<String, Object>> deleteData(@PathVariable Integer id, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Deleting data - Requires WRITE permission");
        response.put("dataId", id);
        response.put("deletedBy", auth.getName());
        return ResponseEntity.ok(response);
    }
}