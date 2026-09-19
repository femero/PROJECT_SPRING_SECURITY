package com.programandoenjava.jwt.security;

import io.github.bucket4j.Bucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
@DisplayName("Rate Limiting Service Tests")
class RateLimitServiceTest {

    private RateLimitService rateLimitService;

    @BeforeEach
    void setUp() {
        rateLimitService = new RateLimitService();
    }

    @Test
    @DisplayName("Should allow requests within rate limit")
    void shouldAllowRequestsWithinLimit() {
        String testKey = "test-ip-1";

        // Login bucket permite 5 intentos por minuto
        for (int i = 0; i < 5; i++) {
            boolean consumed = rateLimitService.tryConsume(testKey, 1);
            assertThat(consumed).isTrue();
        }
    }

    @Test
    @DisplayName("Should block requests exceeding rate limit")
    void shouldBlockRequestsExceedingLimit() {
        String testKey = "test-ip-2";

        // Consumir los 5 tokens permitidos
        for (int i = 0; i < 5; i++) {
            rateLimitService.tryConsume(testKey, 1);
        }

        // El 6to intento debe ser bloqueado
        boolean consumed = rateLimitService.tryConsume(testKey, 1);
        assertThat(consumed).isFalse();
    }

    @Test
    @DisplayName("Should reset bucket for specific key")
    void shouldResetBucket() {
        String testKey = "test-ip-3";

        // Consumir todos los tokens
        for (int i = 0; i < 5; i++) {
            rateLimitService.tryConsume(testKey, 1);
        }

        // Reset
        rateLimitService.resetBucket(testKey);

        // Debe permitir nuevamente
        boolean consumed = rateLimitService.tryConsume(testKey, 1);
        assertThat(consumed).isTrue();
    }

    @Test
    @DisplayName("Should create separate buckets for different IPs")
    void shouldCreateSeparateBucketsForDifferentIPs() {
        String ip1 = "192.168.1.1";
        String ip2 = "192.168.1.2";

        // Consumir todos los tokens de IP1
        for (int i = 0; i < 5; i++) {
            rateLimitService.tryConsume(ip1, 1);
        }

        // IP2 debe seguir funcionando
        boolean consumed = rateLimitService.tryConsume(ip2, 1);
        assertThat(consumed).isTrue();
    }
}