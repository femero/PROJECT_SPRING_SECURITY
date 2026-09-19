package com.programandoenjava.jwt.auth.service;

import com.programandoenjava.jwt.auth.controller.AuthRequest;
import com.programandoenjava.jwt.auth.controller.RegisterRequest;
import com.programandoenjava.jwt.auth.controller.TokenResponse;
import com.programandoenjava.jwt.auth.repository.Token;
import com.programandoenjava.jwt.auth.repository.TokenRepository;
import com.programandoenjava.jwt.metrics.MetricsService;
import com.programandoenjava.jwt.security.InputValidationService;
import com.programandoenjava.jwt.security.LoginAttemptService;
import com.programandoenjava.jwt.user.User;
import com.programandoenjava.jwt.user.UserRepository;
import com.programandoenjava.jwt.util.Role;
import io.micrometer.core.instrument.Timer;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    // Agregar al inicio de la clase (después de las otras dependencias)
    private final MetricsService metricsService;
    // Agregar dependencias
    private final InputValidationService inputValidationService;
    private final LoginAttemptService loginAttemptService;

    // Modificar el método register()
    public TokenResponse register (final RegisterRequest request) {
        Timer.Sample sample = metricsService.startTimer ();
        log.debug ("Attempting to register user with email: {}", request.email ());

        try {
            if (repository.findByEmail (request.email ())
                    .isPresent ()) {
                log.warn ("Registration failed: Email {} already exists", request.email ());
                metricsService.incrementRegistrationFailure ();
                throw new IllegalArgumentException ("Email already registered: " + request.email ());
            }

            final Role role = Role.valueOf (request.role ()
                                                    .toUpperCase ());
            final User user = User.builder ()
                    .name (request.name ())
                    .email (request.email ())
                    .password (passwordEncoder.encode (request.password ()))
                    .role (role)
                    .build ();

            log.debug ("Saving new user: {}", request.email ());
            final User savedUser = repository.save (user);

            final String jwtToken = jwtService.generateToken (savedUser);
            final String refreshToken = jwtService.generateRefreshToken (savedUser);

            // Métricas de JWT
            metricsService.incrementJwtGenerated ();
            metricsService.incrementRefreshTokenGenerated ();

            saveUserToken (savedUser, jwtToken, Token.TokenCategory.ACCESS);
            saveUserToken (savedUser, refreshToken, Token.TokenCategory.REFRESH);

            log.info ("User registered successfully: {}", request.email ());
            metricsService.incrementRegistrationSuccess ();

            return metricsService.recordRegistrationDuration (sample, new TokenResponse (jwtToken, refreshToken));

        } catch (DataIntegrityViolationException e) {
            log.error ("Database constraint violation during registration: {}", e.getMessage ());
            metricsService.incrementRegistrationFailure ();
            throw new IllegalArgumentException ("Email already registered: " + request.email ());

        } catch (IllegalArgumentException e) {
            log.error ("Invalid role provided: {}", request.role ());
            metricsService.incrementRegistrationFailure ();
            throw new IllegalArgumentException ("Invalid role: " + request.role () + ". Valid roles: CUSTOMER, ADMINISTRATOR");

        } catch (Exception e) {
            log.error ("Unexpected error during registration for email {}: {}", request.email (), e.getMessage (), e);
            metricsService.incrementRegistrationFailure ();
            throw new RuntimeException ("Registration failed due to internal error");
        }
    }

    // Modificar método authenticate()
    public TokenResponse authenticate(final AuthRequest request) {
        Timer.Sample sample = metricsService.startTimer();
        String email = request.email();

        log.debug("Attempting to authenticate user: {}", email);

        // Validar input
        inputValidationService.validateInput(email, "email");
        if (!inputValidationService.isValidEmail(email)) {
            log.warn("Invalid email format: {}", email);
            metricsService.incrementLoginFailure();
            throw new IllegalArgumentException("Invalid email format");
        }

        // Verificar si la cuenta está bloqueada
        if (loginAttemptService.isBlocked(email)) {
            log.warn("Login attempt for locked account: {}", email);
            metricsService.incrementLoginFailure();
            throw new SecurityException("Account is temporarily locked due to multiple failed login attempts");
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, request.password()));

            final User user = repository.findByEmail(email)
                    .orElseThrow(() -> new IllegalArgumentException("User not found: " + email));

            final String accessToken = jwtService.generateToken(user);
            final String refreshToken = jwtService.generateRefreshToken(user);

            metricsService.incrementJwtGenerated();
            metricsService.incrementRefreshTokenGenerated();

            revokeAllUserTokens(user);
            saveUserToken(user, accessToken, Token.TokenCategory.ACCESS);
            saveUserToken(user, refreshToken, Token.TokenCategory.REFRESH);

            log.info("User authenticated successfully: {}", email);
            loginAttemptService.loginSucceeded(email);  // Reset intentos
            metricsService.incrementLoginSuccess();

            return metricsService.recordLoginDuration(sample,
                                                      new TokenResponse(accessToken, refreshToken));

        } catch (Exception e) {
            log.error("Authentication failed for user {}: {}", email, e.getMessage());
            loginAttemptService.loginFailed(email);  // Incrementar intentos fallidos
            metricsService.incrementLoginFailure();
            metricsService.incrementInvalidCredentials();
            throw new IllegalArgumentException("Invalid credentials");
        }
    }
    // Modificar el método refreshToken()
    public TokenResponse refreshToken (@NotNull final String authentication) {
        log.debug ("Attempting to refresh token");

        if (authentication == null || !authentication.startsWith ("Bearer ")) {
            throw new IllegalArgumentException ("Invalid auth header format");
        }

        try {
            final String oldRefreshToken = authentication.substring (7);
            final String subject = jwtService.extractUsername (oldRefreshToken);

            if (subject == null) {
                throw new IllegalArgumentException ("Invalid refresh token - no subject found");
            }

            Integer userId = extractUserIdFromSubject (subject);
            if (userId == null) {
                throw new IllegalArgumentException ("Invalid subject format: " + subject);
            }

            final User user = repository.findById (userId)
                    .orElseThrow (() -> new IllegalArgumentException ("User not found with ID: " + userId));

            final boolean isTokenValid = jwtService.isTokenValid (oldRefreshToken, user);
            if (!isTokenValid) {
                metricsService.incrementJwtExpired ();
                throw new IllegalArgumentException ("Invalid or expired refresh token");
            }

            final Token storedToken = tokenRepository.findByToken (oldRefreshToken)
                    .orElseThrow (() -> new IllegalArgumentException ("Refresh token not found in database"));

            if (storedToken.getIsRevoked () || storedToken.getIsExpired ()) {
                metricsService.incrementJwtRevoked ();
                throw new IllegalArgumentException ("Refresh token has been revoked or expired");
            }

            // Métricas de refresh token usado
            metricsService.incrementRefreshTokenUsed ();

            final String newAccessToken = jwtService.generateToken (user);
            final String newRefreshToken = jwtService.generateRefreshToken (user);

            // Métricas de nuevos tokens generados
            metricsService.incrementJwtGenerated ();
            metricsService.incrementRefreshTokenGenerated ();

            storedToken.setIsRevoked (true);
            storedToken.setIsExpired (true);
            tokenRepository.save (storedToken);

            revokeAllUserAccessTokens (user);
            saveUserToken (user, newAccessToken, Token.TokenCategory.ACCESS);
            saveUserToken (user, newRefreshToken, Token.TokenCategory.REFRESH);

            log.info ("Token refreshed successfully for user: {}", user.getEmail ());
            return new TokenResponse (newAccessToken, newRefreshToken);

        } catch (Exception e) {
            log.error ("Token refresh failed: {}", e.getMessage ());
            throw new IllegalArgumentException ("Token refresh failed: " + e.getMessage ());
        }
    }

    private void saveUserToken (User user, String jwtToken, Token.TokenCategory category) {
        final Token token = Token.builder ()
                .user (user)
                .token (jwtToken)
                .tokenType (Token.TokenType.BEARER)
                .tokenCategory (category)
                .isExpired (false)
                .isRevoked (false)
                .build ();
        tokenRepository.save (token);
        log.debug ("{} token saved for user: {}", category, user.getEmail ());
    }

    private void revokeAllUserTokens (final User user) {
        final List <Token> validUserTokens = tokenRepository.findAllValidTokenByUser (user.getId ());
        if (!validUserTokens.isEmpty ()) {
            log.debug ("Revoking {} tokens for user: {}", validUserTokens.size (), user.getEmail ());
            validUserTokens.forEach (token -> {
                token.setIsExpired (true);
                token.setIsRevoked (true);
            });
            tokenRepository.saveAll (validUserTokens);
        }
    }

    private void revokeAllUserAccessTokens (final User user) {
        final List <Token> validUserTokens = tokenRepository.findAllValidTokenByUser (user.getId ());
        final List <Token> accessTokens = validUserTokens.stream ()
                .filter (token -> token.getTokenCategory () == Token.TokenCategory.ACCESS)
                .toList ();

        if (!accessTokens.isEmpty ()) {
            log.debug ("Revoking {} access tokens for user: {}", accessTokens.size (), user.getEmail ());
            accessTokens.forEach (token -> {
                token.setIsExpired (true);
                token.setIsRevoked (true);
            });
            tokenRepository.saveAll (accessTokens);
        }
    }

    private Integer extractUserIdFromSubject (String subject) {
        if (subject == null || !subject.startsWith ("user-")) {
            return null;
        }
        try {
            return Integer.parseInt (subject.substring (5));
        } catch (NumberFormatException e) {
            log.error ("Failed to parse user ID from subject: {}", subject);
            return null;
        }
    }
}