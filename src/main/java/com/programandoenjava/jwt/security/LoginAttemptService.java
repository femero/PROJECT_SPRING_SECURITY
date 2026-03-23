package com.programandoenjava.jwt.security;

import com.programandoenjava.jwt.metrics.MetricsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class LoginAttemptService {

    private final MetricsService metricsService;

    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCKOUT_DURATION_MINUTES = 15;

    private final Map<String, Integer> attemptsCache = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> lockoutCache = new ConcurrentHashMap<>();

    public void loginSucceeded(String key) {
        attemptsCache.remove(key);
        lockoutCache.remove(key);
        log.debug("Login succeeded for: {}", key);
    }

    public void loginFailed(String key) {
        int attempts = attemptsCache.getOrDefault(key, 0) + 1;
        attemptsCache.put(key, attempts);

        log.warn("Login failed for: {}. Attempt {} of {}", key, attempts, MAX_ATTEMPTS);

        if (attempts >= MAX_ATTEMPTS) {
            lockoutCache.put(key, LocalDateTime.now().plusMinutes(LOCKOUT_DURATION_MINUTES));
            log.error("Account locked for: {} due to {} failed attempts", key, attempts);
            metricsService.incrementAccountLockout();
        }
    }

    public boolean isBlocked(String key) {
        LocalDateTime lockoutTime = lockoutCache.get(key);

        if (lockoutTime == null) {
            return false;
        }

        if (LocalDateTime.now().isAfter(lockoutTime)) {
            // Lockout period expired
            lockoutCache.remove(key);
            attemptsCache.remove(key);
            log.info("Lockout expired for: {}", key);
            return false;
        }

        log.warn("Account is locked for: {}", key);
        return true;
    }

    public int getAttempts(String key) {
        return attemptsCache.getOrDefault(key, 0);
    }

    public void resetAttempts(String key) {
        attemptsCache.remove(key);
        lockoutCache.remove(key);
        log.info("Login attempts reset for: {}", key);
    }
}