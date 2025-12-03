package com.programandoenjava.jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/editor")
public class EditorController {

    @GetMapping("/content")
    @PreAuthorize("hasAnyRole('ADMIN', 'EDITOR')")
    public ResponseEntity<Map<String, Object>> getContent(Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Content list - ADMIN or EDITOR can access");
        response.put("user", auth.getName());
        response.put("authorities", auth.getAuthorities());
        response.put("data", "Content list would be here");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/content")
    @PreAuthorize("hasAnyRole('ADMIN', 'EDITOR')")
    public ResponseEntity<Map<String, Object>> createContent(@RequestBody Map<String, Object> content, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Content created successfully");
        response.put("createdBy", auth.getName());
        response.put("content", content);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/content/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'EDITOR')")
    public ResponseEntity<Map<String, Object>> updateContent(@PathVariable Integer id, @RequestBody Map<String, Object> content, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Content updated successfully");
        response.put("contentId", id);
        response.put("updatedBy", auth.getName());
        response.put("content", content);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/content/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> deleteContent(@PathVariable Integer id, Authentication auth) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Content deleted - Only ADMIN can delete");
        response.put("contentId", id);
        response.put("deletedBy", auth.getName());
        return ResponseEntity.ok(response);
    }
}