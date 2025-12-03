package com.programandoenjava.jwt.config;

import com.programandoenjava.jwt.auth.repository.TokenRepository;
import com.programandoenjava.jwt.auth.service.JwtService;
import com.programandoenjava.jwt.user.User;
import com.programandoenjava.jwt.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;

    // Configuración de validación de claims desde application.yml
    @Value("${application.security.jwt.validation.required-claims.roles.values:}")
    private List<String> requiredRoles;

    @Value("${application.security.jwt.validation.required-claims.roles.match:any}")
    private String rolesMatchType;

    @Value("${application.security.jwt.validation.required-claims.scopes.values:}")
    private List<String> requiredScopes;

    @Value("${application.security.jwt.validation.required-claims.scopes.match:all}")
    private String scopesMatchType;

    @Value("${application.security.jwt.validation.required-claims.department.values:}")
    private List<String> requiredDepartments;

    @Value("${application.security.jwt.validation.required-claims.department.match:any}")
    private String departmentMatchType;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String requestPath = request.getServletPath();
        final String requestURI = request.getRequestURI();
        log.debug("Processing request: {} {}", request.getMethod(), requestURI);

        // Skip JWT filter for PUBLIC endpoints ONLY (not refresh-token)
        if (shouldSkipJwtFilterCompletely(requestPath)) {
            log.debug("Skipping JWT filter completely for public path: {}", requestPath);
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.debug("No valid Authorization header found for: {}", requestURI);
            filterChain.doFilter(request, response);
            return;
        }

        try {
            final String jwt = authHeader.substring(7);
            final String userEmail = jwtService.extractUsername(jwt);
            final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            log.debug("Extracted email from JWT: {}", userEmail);

            // Si ya está autenticado o no hay email, continuar
            if (userEmail == null || authentication != null) {
                log.debug("User already authenticated or no email in token");
                filterChain.doFilter(request, response);
                return;
            }

            // Cargar los detalles del usuario
            final UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // LÓGICA ESPECIAL PARA REFRESH TOKEN
            if (isRefreshTokenEndpoint(requestPath)) {
                log.debug("Processing refresh token endpoint");

                final Optional<User> user = userRepository.findByEmail(userEmail);
                if (user.isPresent()) {
                    // Para refresh token, solo verificar la validez del JWT (no la BD de tokens)
                    final boolean isJwtValid = jwtService.isTokenValid(jwt, user.get());
                    log.debug("Refresh token JWT validity: {}", isJwtValid);

                    if (isJwtValid) {
                        log.debug("Authenticating user for refresh token: {}", userEmail);
                        authenticateUser(request, userDetails);
                    } else {
                        log.warn("Invalid refresh token JWT for user: {}", userEmail);
                    }
                }
            } else {
                // LÓGICA NORMAL PARA ACCESS TOKENS
                log.debug("Processing regular access token");

                // Verificar que el token NO esté expirado NI revocado en BD
                final boolean isTokenValid = tokenRepository.findByToken(jwt)
                        .map(token -> {
                            boolean isNotExpired = !token.getIsExpired();
                            boolean isNotRevoked = !token.getIsRevoked();
                            log.debug("Access token validation - Expired: {}, Revoked: {}", token.getIsExpired(), token.getIsRevoked());
                            return isNotExpired && isNotRevoked;
                        })
                        .orElse(false); // Si no encuentra el token en BD, es inválido

                log.debug("Access token valid in database: {}", isTokenValid);

                if (isTokenValid) {
                    final Optional<User> user = userRepository.findByEmail(userEmail);

                    if (user.isPresent()) {
                        // Verificar también la validez del JWT (firma, expiración, etc.)
                        final boolean isJwtValid = jwtService.isTokenValid(jwt, user.get());
                        log.debug("Access token JWT signature and expiration valid: {}", isJwtValid);

                        if (isJwtValid) {
                            // ✅ VALIDACIÓN DE CLAIMS PERSONALIZADOS
                            if (validateRequiredClaims(jwt)) {
                                log.debug("✅ Todos los claims requeridos son válidos");
                                log.debug("Authenticating user with access token: {}", userEmail);
                                authenticateUser(request, userDetails);
                            } else {
                                log.warn("❌ Validación de claims requeridos falló - No se autenticará al usuario");
                                // No autenticar - Spring Security lanzará 403 si intenta acceder a recurso protegido
                            }
                        } else {
                            log.warn("JWT token signature/expiration invalid for user: {}", userEmail);
                        }
                    } else {
                        log.warn("User not found in database: {}", userEmail);
                    }
                } else {
                    log.warn("Access token is expired, revoked, or not found in database");
                }
            }

        } catch (Exception e) {
            log.error("Error processing JWT authentication: {}", e.getMessage(), e);
            // No lanzar excepción, continuar sin autenticar
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Autentica al usuario en el contexto de seguridad
     */
    private void authenticateUser(HttpServletRequest request, UserDetails userDetails) {
        log.debug("User details class: {}", userDetails.getClass().getName());
        log.debug("User authorities before auth: {}", userDetails.getAuthorities());

        if (userDetails instanceof User) {
            User userEntity = (User) userDetails;
            log.debug("User role from entity: {}", userEntity.getRole());
            log.debug("User authorities from getAuthorities(): {}", userEntity.getAuthorities());
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);

        log.debug("User {} authenticated successfully with authorities: {}",
                  userDetails.getUsername(), userDetails.getAuthorities());
    }

    /**
     * Verifica si es el endpoint de refresh token
     */
    private boolean isRefreshTokenEndpoint(String requestPath) {
        return requestPath.contains("/auth/refresh-token");
    }

    /**
     * Determina si el filtro JWT debe ser omitido COMPLETAMENTE para endpoints públicos
     * (NO incluye refresh-token que necesita procesar el JWT)
     */
    private boolean shouldSkipJwtFilterCompletely(String requestPath) {
        return requestPath.contains("/auth/register") ||
                requestPath.contains("/auth/login") ||
                requestPath.contains("/h2-console") ||
                requestPath.startsWith("/error") ||
                requestPath.equals("/") ||
                requestPath.startsWith("/public");
    }

    /**
     * Valida todos los claims requeridos configurados en application.yml
     * @param jwt Token JWT
     * @return true si todas las validaciones pasan
     */
    private boolean validateRequiredClaims(String jwt) {
        try {
            log.debug("🔍 Iniciando validación de claims requeridos");

            // Validar roles si están configurados
            if (requiredRoles != null && !requiredRoles.isEmpty()) {
                if (!jwtService.validateRoles(jwt, requiredRoles, rolesMatchType)) {
                    log.warn("❌ Validación de roles falló");
                    return false;
                }
            }

            // Validar scopes si están configurados
            if (requiredScopes != null && !requiredScopes.isEmpty()) {
                if (!jwtService.validateScopes(jwt, requiredScopes, scopesMatchType)) {
                    log.warn("❌ Validación de scopes falló");
                    return false;
                }
            }

            // Validar department si está configurado
            if (requiredDepartments != null && !requiredDepartments.isEmpty()) {
                if (!jwtService.validateCustomClaim(jwt, "department", requiredDepartments, departmentMatchType)) {
                    log.warn("❌ Validación de department falló");
                    return false;
                }
            }

            log.info("✅ Todas las validaciones de claims pasaron exitosamente");
            return true;

        } catch (Exception e) {
            log.error("❌ Error al validar claims: {}", e.getMessage(), e);
            return false;
        }
    }
}