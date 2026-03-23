package com.programandoenjava.jwt.security;

import com.programandoenjava.jwt.metrics.MetricsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Login Attempt Service Tests")
class LoginAttemptServiceTest {

    @Mock
    private MetricsService metricsService;

    private LoginAttemptService loginAttemptService;

    @BeforeEach
    void setUp() {
        loginAttemptService = new LoginAttemptService(metricsService);
    }

    @Test
    @DisplayName("Should not block account with less than max attempts")
    void shouldNotBlockAccountWithLessThanMaxAttempts() {
        String email = "test@example.com";

        // 4 intentos fallidos (menos del máximo de 5)
        for (int i = 0; i < 4; i++) {
            loginAttemptService.loginFailed(email);
        }

        assertThat(loginAttemptService.isBlocked(email)).isFalse();
        assertThat(loginAttemptService.getAttempts(email)).isEqualTo(4);
    }

    @Test
    @DisplayName("Should block account after max failed attempts")
    void shouldBlockAccountAfterMaxFailedAttempts() {
        String email = "blocked@example.com";

        // 5 intentos fallidos (máximo permitido)
        for (int i = 0; i < 5; i++) {
            loginAttemptService.loginFailed(email);
        }

        assertThat(loginAttemptService.isBlocked(email)).isTrue();
        verify(metricsService, times(1)).incrementAccountLockout();
    }

    @Test
    @DisplayName("Should reset attempts after successful login")
    void shouldResetAttemptsAfterSuccessfulLogin() {
        String email = "reset@example.com";

        // Varios intentos fallidos
        loginAttemptService.loginFailed(email);
        loginAttemptService.loginFailed(email);
        loginAttemptService.loginFailed(email);

        // Login exitoso
        loginAttemptService.loginSucceeded(email);

        assertThat(loginAttemptService.getAttempts(email)).isEqualTo(0);
        assertThat(loginAttemptService.isBlocked(email)).isFalse();
    }

    @Test
    @DisplayName("Should manually reset attempts")
    void shouldManuallyResetAttempts() {
        String email = "manual@example.com";

        // Bloquear cuenta
        for (int i = 0; i < 5; i++) {
            loginAttemptService.loginFailed(email);
        }

        // Reset manual
        loginAttemptService.resetAttempts(email);

        assertThat(loginAttemptService.isBlocked(email)).isFalse();
        assertThat(loginAttemptService.getAttempts(email)).isEqualTo(0);
    }

    @Test
    @DisplayName("Should track attempts independently for different users")
    void shouldTrackAttemptsIndependently() {
        String email1 = "user1@example.com";
        String email2 = "user2@example.com";

        // User1: 3 intentos
        for (int i = 0; i < 3; i++) {
            loginAttemptService.loginFailed(email1);
        }

        // User2: 5 intentos (bloqueado)
        for (int i = 0; i < 5; i++) {
            loginAttemptService.loginFailed(email2);
        }

        assertThat(loginAttemptService.getAttempts(email1)).isEqualTo(3);
        assertThat(loginAttemptService.isBlocked(email1)).isFalse();

        assertThat(loginAttemptService.getAttempts(email2)).isEqualTo(5);
        assertThat(loginAttemptService.isBlocked(email2)).isTrue();
    }
}