package com.programandoenjava.jwt.auth.service;

import com.programandoenjava.jwt.auth.controller.AuthRequest;
import com.programandoenjava.jwt.auth.controller.RegisterRequest;
import com.programandoenjava.jwt.auth.controller.TokenResponse;
import com.programandoenjava.jwt.auth.repository.Token;
import com.programandoenjava.jwt.auth.repository.TokenRepository;
import com.programandoenjava.jwt.user.User;
import com.programandoenjava.jwt.user.UserRepository;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.programandoenjava.jwt.util.Role;

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

    public TokenResponse register(final RegisterRequest request) {
        log.debug("Attempting to register user with email: {}", request.email());

        // ✅ VERIFICAR SI EL EMAIL YA EXISTE
        if (repository.findByEmail(request.email()).isPresent()) {
            log.warn("Registration failed: Email {} already exists", request.email());
            throw new IllegalArgumentException("Email already registered: " + request.email());
        }

        try {
            final Role role = Role.valueOf(request.role().toUpperCase());
            final User user = User.builder()
                    .name(request.name())
                    .email(request.email())
                    .password(passwordEncoder.encode(request.password()))
                    .role(role)
                    .build();

            log.debug("Saving new user: {}", request.email());
            final User savedUser = repository.save(user);

            final String jwtToken = jwtService.generateToken(savedUser);
            final String refreshToken = jwtService.generateRefreshToken(savedUser);

            saveUserToken(savedUser, jwtToken);

            log.info("User registered successfully: {}", request.email());
            return new TokenResponse(jwtToken, refreshToken);

        } catch (DataIntegrityViolationException e) {
            // ✅ MANEJO ESPECÍFICO PARA VIOLACIÓN DE CONSTRAINT UNIQUE
            log.error("Database constraint violation during registration: {}", e.getMessage());
            throw new IllegalArgumentException("Email already registered: " + request.email());

        } catch (IllegalArgumentException e) {
            // ✅ MANEJO PARA ROLES INVÁLIDOS
            log.error("Invalid role provided: {}", request.role());
            throw new IllegalArgumentException("Invalid role: " + request.role() + ". Valid roles: CUSTOMER, ADMINISTRATOR");

        } catch (Exception e) {
            // ✅ MANEJO GENERAL DE ERRORES
            log.error("Unexpected error during registration for email {}: {}", request.email(), e.getMessage(), e);
            throw new RuntimeException("Registration failed due to internal error");
        }
    }

    public TokenResponse authenticate(final AuthRequest request) {
        log.debug("Attempting to authenticate user: {}", request.email());

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.email(),
                            request.password()
                    )
            );

            final User user = repository.findByEmail(request.email())
                    .orElseThrow(() -> new IllegalArgumentException("User not found: " + request.email()));

            final String accessToken = jwtService.generateToken(user);
            final String refreshToken = jwtService.generateRefreshToken(user);

            revokeAllUserTokens(user);
            saveUserToken(user, accessToken);

            log.info("User authenticated successfully: {}", request.email());
            return new TokenResponse(accessToken, refreshToken);

        } catch (Exception e) {
            log.error("Authentication failed for user {}: {}", request.email(), e.getMessage());
            throw new IllegalArgumentException("Invalid credentials");
        }
    }

    public TokenResponse refreshToken(@NotNull final String authentication) {
        log.debug("Attempting to refresh token");

        if (authentication == null || !authentication.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Invalid auth header format");
        }

        try {
            final String refreshToken = authentication.substring(7);
            final String userEmail = jwtService.extractUsername(refreshToken);

            if (userEmail == null) {
                throw new IllegalArgumentException("Invalid refresh token - no user email found");
            }

            final User user = repository.findByEmail(userEmail)
                    .orElseThrow(() -> new IllegalArgumentException("User not found: " + userEmail));

            final boolean isTokenValid = jwtService.isTokenValid(refreshToken, user);
            if (!isTokenValid) {
                throw new IllegalArgumentException("Invalid or expired refresh token");
            }

            // ✅ CORRECCIÓN: Generar ACCESS TOKEN (no refresh token)
            final String accessToken = jwtService.generateToken(user);

            revokeAllUserTokens(user);
            saveUserToken(user, accessToken);

            log.info("Token refreshed successfully for user: {}", userEmail);
            return new TokenResponse(accessToken, refreshToken);

        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage());
            throw new IllegalArgumentException("Token refresh failed: " + e.getMessage());
        }
    }

    private void saveUserToken(User user, String jwtToken) {
        final Token token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(Token.TokenType.BEARER)
                .isExpired(false)
                .isRevoked(false)
                .build();
        tokenRepository.save(token);
        log.debug("Token saved for user: {}", user.getEmail());
    }

    private void revokeAllUserTokens(final User user) {
        final List<Token> validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (!validUserTokens.isEmpty()) {
            log.debug("Revoking {} tokens for user: {}", validUserTokens.size(), user.getEmail());
            validUserTokens.forEach(token -> {
                token.setIsExpired(true);
                token.setIsRevoked(true);
            });
            tokenRepository.saveAll(validUserTokens);
        }
    }
}