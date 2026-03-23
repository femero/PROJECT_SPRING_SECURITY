package com.programandoenjava.jwt.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Input Validation Service Tests")
class InputValidationServiceTest {

    private InputValidationService validationService;

    @BeforeEach
    void setUp() {
        validationService = new InputValidationService();
    }

    // ===== EMAIL VALIDATION =====

    @ParameterizedTest
    @ValueSource(strings = {
            "test@example.com",
            "user.name@example.com",
            "user+tag@example.co.uk",
            "valid_email@test-domain.com"
    })
    @DisplayName("Should accept valid email addresses")
    void shouldAcceptValidEmails(String email) {
        assertThat(validationService.isValidEmail(email)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "invalid.email",
            "@example.com",
            "user@",
            "user name@example.com",
            "user@.com",
            ""
    })
    @DisplayName("Should reject invalid email addresses")
    void shouldRejectInvalidEmails(String email) {
        assertThat(validationService.isValidEmail(email)).isFalse();
    }

    @Test
    @DisplayName("Should reject null email")
    void shouldRejectNullEmail() {
        assertThat(validationService.isValidEmail(null)).isFalse();
    }

    // ===== SQL INJECTION DETECTION =====

    @ParameterizedTest
    @ValueSource(strings = {
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--",
            "'; DELETE FROM tokens WHERE '1'='1",
            "<script>alert('XSS')</script>"
    })
    @DisplayName("Should detect SQL injection attempts")
    void shouldDetectSQLInjection(String maliciousInput) {
        assertThat(validationService.containsSQLInjection(maliciousInput)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "normal text",
            "user@example.com",
            "John Doe",
            "123456"
    })
    @DisplayName("Should not flag safe input as SQL injection")
    void shouldNotFlagSafeInputAsSQLInjection(String safeInput) {
        assertThat(validationService.containsSQLInjection(safeInput)).isFalse();
    }

    // ===== XSS DETECTION =====

    @ParameterizedTest
    @ValueSource(strings = {
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<iframe src='malicious.com'></iframe>",
            "<object data='malicious.swf'></object>",
            "<body onload=alert('XSS')>"
    })
    @DisplayName("Should detect XSS attempts")
    void shouldDetectXSS(String maliciousInput) {
        assertThat(validationService.containsXSS(maliciousInput)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "normal text",
            "user@example.com",
            "This is a safe message",
            "Price: $100"
    })
    @DisplayName("Should not flag safe input as XSS")
    void shouldNotFlagSafeInputAsXSS(String safeInput) {
        assertThat(validationService.containsXSS(safeInput)).isFalse();
    }

    // ===== INPUT SANITIZATION =====

    @Test
    @DisplayName("Should sanitize dangerous characters")
    void shouldSanitizeDangerousCharacters() {
        String dangerous = "<script>alert('test')</script>";
        String sanitized = validationService.sanitizeInput(dangerous);

        assertThat(sanitized).doesNotContain("<");
        assertThat(sanitized).doesNotContain(">");
        assertThat(sanitized).contains("&");
    }

    @Test
    @DisplayName("Should handle null input in sanitization")
    void shouldHandleNullInSanitization() {
        String result = validationService.sanitizeInput(null);
        assertThat(result).isNull();
    }

    // ===== COMPREHENSIVE VALIDATION =====

    @Test
    @DisplayName("Should throw exception for empty input")
    void shouldThrowExceptionForEmptyInput() {
        assertThatThrownBy(() -> validationService.validateInput("", "testField"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cannot be empty");
    }

    @Test
    @DisplayName("Should throw exception for SQL injection in validation")
    void shouldThrowExceptionForSQLInjection() {
        String malicious = "'; DROP TABLE users; --";

        assertThatThrownBy(() -> validationService.validateInput(malicious, "username"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Invalid input detected");
    }

    @Test
    @DisplayName("Should throw exception for XSS in validation")
    void shouldThrowExceptionForXSS() {
        String malicious = "<script>alert('XSS')</script>";

        assertThatThrownBy(() -> validationService.validateInput(malicious, "message"))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Invalid input detected");
    }

    @Test
    @DisplayName("Should pass validation for safe input")
    void shouldPassValidationForSafeInput() {
        String safeInput = "John Doe";

        // No debería lanzar excepción
        validationService.validateInput(safeInput, "name");
    }
}