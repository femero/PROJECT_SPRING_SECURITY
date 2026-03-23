package com.programandoenjava.jwt.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

@Service
@Slf4j
public class InputValidationService {

    // Patrones de validación
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );

    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            ".*(union|select|insert|update|delete|drop|create|alter|exec|script|javascript|<script|--|;|\\bor\\b|\\band\\b).*",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern XSS_PATTERN = Pattern.compile(
            ".*(<script|javascript:|onerror=|onload=|<iframe|<object|<embed).*",
            Pattern.CASE_INSENSITIVE
    );

    public boolean isValidEmail (String email) {
        if (email == null || email.trim ()
                .isEmpty ()) {
            return false;
        }
        return EMAIL_PATTERN.matcher (email)
                .matches ();
    }

    public boolean containsSQLInjection (String input) {
        if (input == null) {
            return false;
        }
        return SQL_INJECTION_PATTERN.matcher (input)
                .find ();
    }

    public boolean containsXSS (String input) {
        if (input == null) {
            return false;
        }
        return XSS_PATTERN.matcher (input)
                .find ();
    }

    public String sanitizeInput (String input) {
        if (input == null) {
            return null;
        }

        // Remover caracteres peligrosos
        String sanitized = input.replace ("<", "&lt;")
                .replace (">", "&gt;")
                .replace ("\"", "&quot;")
                .replace ("'", "&#x27;")
                .replace ("/", "&#x2F;");

        return sanitized.trim ();
    }

    public void validateInput (String input, String fieldName) {
        if (input == null || input.trim ()
                .isEmpty ()) {
            throw new IllegalArgumentException (fieldName + " cannot be empty");
        }

        if (containsSQLInjection (input)) {
            log.error ("SQL Injection attempt detected in field: {}", fieldName);
            throw new SecurityException ("Invalid input detected in " + fieldName);
        }

        if (containsXSS (input)) {
            log.error ("XSS attempt detected in field: {}", fieldName);
            throw new SecurityException ("Invalid input detected in " + fieldName);
        }
    }
}