package com.programandoenjava.jwt.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class RateLimitService {

    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();

    // 5 intentos por minuto por IP
    private static final int LOGIN_ATTEMPTS_PER_MINUTE = 5;

    // 10 requests por minuto para endpoints generales
    private static final int GENERAL_REQUESTS_PER_MINUTE = 60;

    public Bucket resolveLoginBucket(String key) {
        return cache.computeIfAbsent(key, k -> createLoginBucket());
    }

    public Bucket resolveGeneralBucket(String key) {
        return cache.computeIfAbsent(key, k -> createGeneralBucket());
    }

    private Bucket createLoginBucket() {
        Bandwidth limit = Bandwidth.classic(
                LOGIN_ATTEMPTS_PER_MINUTE,
                Refill.intervally(LOGIN_ATTEMPTS_PER_MINUTE, Duration.ofMinutes(1))
        );
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }

    private Bucket createGeneralBucket() {
        Bandwidth limit = Bandwidth.classic(
                GENERAL_REQUESTS_PER_MINUTE,
                Refill.intervally(GENERAL_REQUESTS_PER_MINUTE, Duration.ofMinutes(1))
        );
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }

    public boolean tryConsume(String key, int tokens) {
        Bucket bucket = resolveLoginBucket(key);
        return bucket.tryConsume(tokens);
    }

    public void resetBucket(String key) {
        cache.remove(key);
        log.info("Rate limit bucket reset for key: {}", key);
    }
}