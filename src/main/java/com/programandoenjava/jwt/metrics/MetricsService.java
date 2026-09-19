package com.programandoenjava.jwt.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class MetricsService {

    // Agregar al inicio de la clase
    private final Counter accountLockoutCounter;

    private final MeterRegistry meterRegistry;

    // Contadores de Autenticación
    private final Counter loginSuccessCounter;
    private final Counter loginFailureCounter;
    private final Counter registrationSuccessCounter;
    private final Counter registrationFailureCounter;

    // Contadores de JWT
    private final Counter jwtGeneratedCounter;
    private final Counter jwtValidatedCounter;
    private final Counter jwtExpiredCounter;
    private final Counter jwtInvalidCounter;
    private final Counter jwtRevokedCounter;
    private final Counter refreshTokenGeneratedCounter;
    private final Counter refreshTokenUsedCounter;

    // Contadores de Seguridad
    private final Counter unauthorizedAccessCounter;
    private final Counter forbiddenAccessCounter;
    private final Counter invalidCredentialsCounter;

    // Timers para medir latencia
    private final Timer loginTimer;
    private final Timer registrationTimer;
    private final Timer jwtValidationTimer;

    public MetricsService (MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;

        // Inicializar contadores de autenticación
        this.loginSuccessCounter = Counter.builder ("auth.login.success")
                .description ("Total de logins exitosos")
                .tag ("type", "authentication")
                .register (meterRegistry);

        this.loginFailureCounter = Counter.builder ("auth.login.failure")
                .description ("Total de logins fallidos")
                .tag ("type", "authentication")
                .register (meterRegistry);

        this.registrationSuccessCounter = Counter.builder ("auth.registration.success")
                .description ("Total de registros exitosos")
                .tag ("type", "authentication")
                .register (meterRegistry);

        this.registrationFailureCounter = Counter.builder ("auth.registration.failure")
                .description ("Total de registros fallidos")
                .tag ("type", "authentication")
                .register (meterRegistry);

        // Inicializar contadores de JWT
        this.jwtGeneratedCounter = Counter.builder ("jwt.token.generated")
                .description ("Total de tokens JWT generados")
                .tag ("type", "jwt")
                .register (meterRegistry);

        this.jwtValidatedCounter = Counter.builder ("jwt.token.validated")
                .description ("Total de tokens JWT validados exitosamente")
                .tag ("type", "jwt")
                .register (meterRegistry);

        this.jwtExpiredCounter = Counter.builder ("jwt.token.expired")
                .description ("Total de tokens JWT expirados")
                .tag ("type", "jwt")
                .register (meterRegistry);

        this.jwtInvalidCounter = Counter.builder ("jwt.token.invalid")
                .description ("Total de tokens JWT inválidos")
                .tag ("type", "jwt")
                .register (meterRegistry);

        this.jwtRevokedCounter = Counter.builder ("jwt.token.revoked")
                .description ("Total de tokens JWT revocados")
                .tag ("type", "jwt")
                .register (meterRegistry);

        this.refreshTokenGeneratedCounter = Counter.builder ("jwt.refresh_token.generated")
                .description ("Total de refresh tokens generados")
                .tag ("type", "jwt")
                .register (meterRegistry);

        this.refreshTokenUsedCounter = Counter.builder ("jwt.refresh_token.used")
                .description ("Total de refresh tokens utilizados")
                .tag ("type", "jwt")
                .register (meterRegistry);

        // Inicializar contadores de seguridad
        this.unauthorizedAccessCounter = Counter.builder ("security.access.unauthorized")
                .description ("Total de intentos de acceso no autorizado (401)")
                .tag ("type", "security")
                .register (meterRegistry);

        this.forbiddenAccessCounter = Counter.builder ("security.access.forbidden")
                .description ("Total de intentos de acceso prohibido (403)")
                .tag ("type", "security")
                .register (meterRegistry);

        this.invalidCredentialsCounter = Counter.builder ("security.credentials.invalid")
                .description ("Total de credenciales inválidas")
                .tag ("type", "security")
                .register (meterRegistry);

        // Inicializar timers
        this.loginTimer = Timer.builder ("auth.login.duration")
                .description ("Duración de operaciones de login")
                .tag ("type", "authentication")
                .register (meterRegistry);

        this.registrationTimer = Timer.builder ("auth.registration.duration")
                .description ("Duración de operaciones de registro")
                .tag ("type", "authentication")
                .register (meterRegistry);

        this.jwtValidationTimer = Timer.builder ("jwt.validation.duration")
                .description ("Duración de validación de tokens JWT")
                .tag ("type", "jwt")
                .register (meterRegistry);

        // En el constructor
        this.accountLockoutCounter = Counter.builder("security.account.lockout")
                .description("Total de cuentas bloqueadas por intentos fallidos")
                .tag("type", "security")
                .register(meterRegistry);

        log.info ("📊 MetricsService initialized with custom business metrics");
    }

    // ============================================
    // Métodos de Autenticación
    // ============================================

    public void incrementLoginSuccess () {
        loginSuccessCounter.increment ();
        log.debug ("✅ Login success metric incremented");
    }

    public void incrementLoginFailure () {
        loginFailureCounter.increment ();
        log.debug ("❌ Login failure metric incremented");
    }

    public void incrementRegistrationSuccess () {
        registrationSuccessCounter.increment ();
        log.debug ("✅ Registration success metric incremented");
    }

    public void incrementRegistrationFailure () {
        registrationFailureCounter.increment ();
        log.debug ("❌ Registration failure metric incremented");
    }

    public <T> T recordLoginDuration (Timer.Sample sample, T result) {
        sample.stop (loginTimer);
        return result;
    }

    public <T> T recordRegistrationDuration (Timer.Sample sample, T result) {
        sample.stop (registrationTimer);
        return result;
    }

    // ============================================
    // Métodos de JWT
    // ============================================

    public void incrementJwtGenerated () {
        jwtGeneratedCounter.increment ();
        log.debug ("🔑 JWT generated metric incremented");
    }

    public void incrementJwtValidated () {
        jwtValidatedCounter.increment ();
        log.debug ("✅ JWT validated metric incremented");
    }

    public void incrementJwtExpired () {
        jwtExpiredCounter.increment ();
        log.debug ("⏰ JWT expired metric incremented");
    }

    public void incrementJwtInvalid () {
        jwtInvalidCounter.increment ();
        log.debug ("❌ JWT invalid metric incremented");
    }

    public void incrementJwtRevoked () {
        jwtRevokedCounter.increment ();
        log.debug ("🚫 JWT revoked metric incremented");
    }

    public void incrementRefreshTokenGenerated () {
        refreshTokenGeneratedCounter.increment ();
        log.debug ("🔄 Refresh token generated metric incremented");
    }

    public void incrementRefreshTokenUsed () {
        refreshTokenUsedCounter.increment ();
        log.debug ("🔄 Refresh token used metric incremented");
    }

    public void recordJwtValidationDuration (long durationMs) {
        jwtValidationTimer.record (durationMs, TimeUnit.MILLISECONDS);
        log.debug ("⏱️ JWT validation duration recorded: {}ms", durationMs);
    }

    // ============================================
    // Métodos de Seguridad
    // ============================================

    public void incrementUnauthorizedAccess () {
        unauthorizedAccessCounter.increment ();
        log.debug ("🚨 Unauthorized access metric incremented");
    }

    public void incrementForbiddenAccess () {
        forbiddenAccessCounter.increment ();
        log.debug ("🚨 Forbidden access metric incremented");
    }

    public void incrementInvalidCredentials () {
        invalidCredentialsCounter.increment ();
        log.debug ("🚨 Invalid credentials metric incremented");
    }

    // ============================================
    // Métodos de Utilidad
    // ============================================

    public Timer.Sample startTimer () {
        return Timer.start (meterRegistry);
    }

    // métrica de account lockout
    public void incrementAccountLockout() {
        accountLockoutCounter.increment();
        log.warn("🔒 Account lockout metric incremented");
    }
}