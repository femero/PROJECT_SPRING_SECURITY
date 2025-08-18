package com.programandoenjava.jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/test")
public class TestController {

    @GetMapping("/public")
    public ResponseEntity<Map<String, Object>> publicEndpoint() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is a public endpoint - no authentication required");
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/protected")
    public ResponseEntity<Map<String, Object>> protectedEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is a protected endpoint");
        response.put("authenticated", auth != null && auth.isAuthenticated());
        response.put("user", auth != null ? auth.getName() : "anonymous");
        response.put("authorities", auth != null ? auth.getAuthorities() : null);

        // DEBUG adicional
        if (auth != null && auth.getPrincipal() instanceof com.programandoenjava.jwt.user.User) {
            com.programandoenjava.jwt.user.User user = (com.programandoenjava.jwt.user.User) auth.getPrincipal();
            response.put("userRole", user.getRole());
            response.put("userAuthorities", user.getAuthorities());
            response.put("principalClass", user.getClass().getName());
        }

        response.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.ok(response);
    }
}