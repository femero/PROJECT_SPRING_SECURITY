package com.programandoenjava.jwt.config;

import com.programandoenjava.jwt.auth.repository.TokenRepository;
import com.programandoenjava.jwt.auth.service.JwtService;
import com.programandoenjava.jwt.metrics.MetricsService;
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
    // Agregar al inicio de la clase (después de las otras dependencias)
    private final MetricsService metricsService;

    // Configuración de validación de claims desde application.yml
    @Value("${application.security.jwt.validation.required-claims.roles.values:}")
    private List <String> requiredRoles;

    @Value("${application.security.jwt.validation.required-claims.roles.match:any}")
    private String rolesMatchType;

    @Value("${application.security.jwt.validation.required-claims.scopes.values:}")
    private List <String> requiredScopes;

    @Value("${application.security.jwt.validation.required-claims.scopes.match:all}")
    private String scopesMatchType;

    @Value("${application.security.jwt.validation.required-claims.department.values:}")
    private List <String> requiredDepartments;

    @Value("${application.security.jwt.validation.required-claims.department.match:any}")
    private String departmentMatchType;

    @Override
    protected void doFilterInternal (@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String requestPath = request.getServletPath ();
        final String requestURI = request.getRequestURI ();
        log.debug ("Processing request: {} {}", request.getMethod (), requestURI);

        // Skip JWT filter for PUBLIC endpoints ONLY (not refresh-token)
        if (shouldSkipJwtFilterCompletely (requestPath)) {
            log.debug ("Skipping JWT filter completely for public path: {}", requestPath);
            filterChain.doFilter (request, response);
            return;
        }

        final String authHeader = request.getHeader (HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith ("Bearer ")) {
            log.debug ("No valid Authorization header found for: {}", requestURI);
            filterChain.doFilter (request, response);
            return;
        }

        try {
            final String jwt = authHeader.substring (7);
            final String subject = jwtService.extractUsername (jwt);
            final Authentication authentication = SecurityContextHolder.getContext ()
                    .getAuthentication ();

            log.debug ("Extracted subject from JWT: {}", subject);

            // Si ya está autenticado o no hay subject, continuar
            if (subject == null || authentication != null) {
                log.debug ("User already authenticated or no subject in token");
                filterChain.doFilter (request, response);
                return;
            }

            // Extract user ID from subject (format: "user-{id}")
            Integer userId = extractUserIdFromSubject (subject);
            if (userId == null) {
                log.warn ("Invalid subject format: {}", subject);
                filterChain.doFilter (request, response);
                return;
            }

            // Cargar los detalles del usuario por ID
            final Optional <User> userOpt = userRepository.findById (userId);
            if (userOpt.isEmpty ()) {
                log.warn ("User not found with ID: {}", userId);
                filterChain.doFilter (request, response);
                return;
            }

            final User user = userOpt.get ();
            final UserDetails userDetails = user;

            // LÓGICA ESPECIAL PARA REFRESH TOKEN
            if (isRefreshTokenEndpoint (requestPath)) {
                log.debug ("Processing refresh token endpoint");

                final boolean isJwtValid = jwtService.isTokenValid (jwt, user);
                log.debug ("Refresh token JWT validity: {}", isJwtValid);

                if (isJwtValid) {
                    log.debug ("Authenticating user for refresh token: {}", user.getEmail ());
                    authenticateUser (request, userDetails);
                } else {
                    log.warn ("Invalid refresh token JWT for user: {}", user.getEmail ());
                }
            } else {
                long startTime = System.currentTimeMillis ();
                // LÓGICA NORMAL PARA ACCESS TOKENS
                log.debug ("Processing regular access token");

                final boolean isTokenValid = tokenRepository.findByToken (jwt)
                        .map (token -> {
                            boolean isNotExpired = !token.getIsExpired ();
                            boolean isNotRevoked = !token.getIsRevoked ();
                            log.debug ("Access token validation - Expired: {}, Revoked: {}", token.getIsExpired (), token.getIsRevoked ());
                            return isNotExpired && isNotRevoked;
                        })
                        .orElse (false);

                log.debug ("Access token valid in database: {}", isTokenValid);

                if (isTokenValid) {
                    final boolean isJwtValid = jwtService.isTokenValid (jwt, user);
                    log.debug ("Access token JWT signature and expiration valid: {}", isJwtValid);

                    if (isJwtValid) {
                        metricsService.incrementJwtValidated ();
                        metricsService.recordJwtValidationDuration (System.currentTimeMillis () - startTime);

                        if (validateRequiredClaims (jwt)) {
                            log.debug ("✅ Todos los claims requeridos son válidos");
                            log.debug ("Authenticating user with access token: {}", user.getEmail ());
                            authenticateUser (request, userDetails);
                        } else {
                            log.warn ("❌ Validación de claims requeridos falló");
                            metricsService.incrementJwtInvalid ();
                        }
                    } else {
                        log.warn ("JWT token signature/expiration invalid for user: {}", user.getEmail ());
                        metricsService.incrementJwtInvalid ();
                    }
                } else {
                    log.warn ("Access token is expired, revoked, or not found in database");
                    metricsService.incrementJwtExpired ();
                }
            }

        } catch (Exception e) {
            log.error ("Error processing JWT authentication: {}", e.getMessage (), e);
            // No lanzar excepción, continuar sin autenticar
        }

        filterChain.doFilter (request, response);
    }

    /**
     * Autentica al usuario en el contexto de seguridad
     */
    private void authenticateUser (HttpServletRequest request, UserDetails userDetails) {
        log.debug ("User details class: {}", userDetails.getClass ()
                .getName ());
        log.debug ("User authorities before auth: {}", userDetails.getAuthorities ());

        if (userDetails instanceof User userEntity) {
            log.debug ("User role from entity: {}", userEntity.getRole ());
            log.debug ("User authorities from getAuthorities(): {}", userEntity.getAuthorities ());
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken (userDetails, null, userDetails.getAuthorities ());
        authToken.setDetails (new WebAuthenticationDetailsSource ().buildDetails (request));
        SecurityContextHolder.getContext ()
                .setAuthentication (authToken);

        log.debug ("User {} authenticated successfully with authorities: {}", userDetails.getUsername (), userDetails.getAuthorities ());
    }

    /**
     * Verifica si es el endpoint de refresh token
     */
    private boolean isRefreshTokenEndpoint (String requestPath) {
        return requestPath.contains ("/auth/refresh-token");
    }

    /**
     * Determina si el filtro JWT debe ser omitido COMPLETAMENTE para endpoints públicos
     * (NO incluye refresh-token que necesita procesar el JWT)
     */
    private boolean shouldSkipJwtFilterCompletely (String requestPath) {
        return requestPath.contains ("/auth/register") || requestPath.contains ("/auth/login") || requestPath.contains ("/h2-console") || requestPath.startsWith ("/error") || requestPath.equals ("/") || requestPath.startsWith ("/public") || requestPath.startsWith ("/actuator");
    }

    /**
     * Valida todos los claims requeridos configurados en application.yml
     *
     * @param jwt Token JWT
     * @return true si todas las validaciones pasan
     */
    private boolean validateRequiredClaims (String jwt) {
        try {
            log.debug ("🔍 Iniciando validación de claims requeridos");

            // Validar roles si están configurados
            if (requiredRoles != null && !requiredRoles.isEmpty ()) {
                if (!jwtService.validateRoles (jwt, requiredRoles, rolesMatchType)) {
                    log.warn ("❌ Validación de roles falló");
                    return false;
                }
            }

            // Validar scopes si están configurados
            if (requiredScopes != null && !requiredScopes.isEmpty ()) {
                if (!jwtService.validateScopes (jwt, requiredScopes, scopesMatchType)) {
                    log.warn ("❌ Validación de scopes falló");
                    return false;
                }
            }

            // Validar department si está configurado
            if (requiredDepartments != null && !requiredDepartments.isEmpty ()) {
                if (!jwtService.validateCustomClaim (jwt, "department", requiredDepartments, departmentMatchType)) {
                    log.warn ("❌ Validación de department falló");
                    return false;
                }
            }

            log.info ("✅ Todas las validaciones de claims pasaron exitosamente");
            return true;

        } catch (Exception e) {
            log.error ("❌ Error al validar claims: {}", e.getMessage (), e);
            return false;
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