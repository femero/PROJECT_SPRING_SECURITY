package com.programandoenjava.jwt.auth.service;

import com.programandoenjava.jwt.auth.controller.AuthRequest;
import com.programandoenjava.jwt.auth.controller.RegisterRequest;
import com.programandoenjava.jwt.security.LoginAttemptService;
import com.programandoenjava.jwt.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
@DisplayName("Auth Service Security Integration Tests")
class AuthServiceSecurityIntegrationTest {

    @Autowired
    private AuthService authService;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private UserRepository userRepository;

    private static final String TEST_EMAIL = "security-test@example.com";
    private static final String TEST_PASSWORD = "SecurePassword123!";

    @BeforeEach
    void setUp() {
        // Limpiar intentos previos
        loginAttemptService.resetAttempts(TEST_EMAIL);

        // Limpiar usuario si existe
        userRepository.findByEmail(TEST_EMAIL).ifPresent(userRepository::delete);

        // Registrar usuario de prueba
        RegisterRequest registerRequest = new RegisterRequest(
                "Test User",
                TEST_EMAIL,
                TEST_PASSWORD,
                "CUSTOMER"
        );
        authService.register(registerRequest);
    }

    @Test
    @DisplayName("Should reject invalid email format")
    void shouldRejectInvalidEmailFormat() {
        AuthRequest request = new AuthRequest("invalid-email", TEST_PASSWORD);

        assertThatThrownBy(() -> authService.authenticate(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid email format");
    }

    @Test
    @DisplayName("Should block account after 5 failed login attempts")
    void shouldBlockAccountAfterMaxFailedAttempts() {
        // 5 intentos fallidos
        for (int i = 0; i < 5; i++) {
            try {
                authService.authenticate(new AuthRequest(TEST_EMAIL, "wrongpassword"));
            } catch (Exception e) {
                // Esperado
            }
        }

        // Verificar que está bloqueado
        assertThat(loginAttemptService.isBlocked(TEST_EMAIL)).isTrue();

        // El siguiente intento debe ser rechazado incluso con password correcto
        assertThatThrownBy(() -> authService.authenticate(new AuthRequest(TEST_EMAIL, TEST_PASSWORD)))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("temporarily locked");
    }

    @Test
    @DisplayName("Should reset attempts after successful login")
    void shouldResetAttemptsAfterSuccessfulLogin() {
        // 3 intentos fallidos
        for (int i = 0; i < 3; i++) {
            try {
                authService.authenticate(new AuthRequest(TEST_EMAIL, "wrongpassword"));
            } catch (Exception e) {
                // Esperado
            }
        }

        assertThat(loginAttemptService.getAttempts(TEST_EMAIL)).isEqualTo(3);

        // Login exitoso
        authService.authenticate(new AuthRequest(TEST_EMAIL, TEST_PASSWORD));

        // Intentos reseteados
        assertThat(loginAttemptService.getAttempts(TEST_EMAIL)).isEqualTo(0);
    }

    @Test
    @DisplayName("Should detect SQL injection in email field")
    void shouldDetectSQLInjectionInEmail() {
        String sqlInjection = "'; DROP TABLE users; --";
        AuthRequest request = new AuthRequest(sqlInjection, TEST_PASSWORD);

        assertThatThrownBy(() -> authService.authenticate(request))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Invalid input detected");
    }

    @Test
    @DisplayName("Should track failed attempts independently per user")
    void shouldTrackFailedAttemptsIndependently() {
        String email2 = "another-user@example.com";

        // Registrar segundo usuario
        RegisterRequest registerRequest = new RegisterRequest(
                "Another User",
                email2,
                TEST_PASSWORD,
                "CUSTOMER"
        );
        authService.register(registerRequest);

        // 4 intentos fallidos para TEST_EMAIL
        for (int i = 0; i < 4; i++) {
            try {
                authService.authenticate(new AuthRequest(TEST_EMAIL, "wrong"));
            } catch (Exception e) {
                // Esperado
            }
        }

        // 2 intentos fallidos para email2
        for (int i = 0; i < 2; i++) {
            try {
                authService.authenticate(new AuthRequest(email2, "wrong"));
            } catch (Exception e) {
                // Esperado
            }
        }

        assertThat(loginAttemptService.getAttempts(TEST_EMAIL)).isEqualTo(4);
        assertThat(loginAttemptService.getAttempts(email2)).isEqualTo(2);

        assertThat(loginAttemptService.isBlocked(TEST_EMAIL)).isFalse();
        assertThat(loginAttemptService.isBlocked(email2)).isFalse();
    }
}