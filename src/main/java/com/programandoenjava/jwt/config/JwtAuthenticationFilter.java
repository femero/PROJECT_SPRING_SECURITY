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
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String requestPath = request.getServletPath();
        final String requestURI = request.getRequestURI();
        log.debug("Processing request: {} {}", request.getMethod(), requestURI);

        // Skip JWT filter for public endpoints
        if (shouldSkipJwtFilter(requestPath)) {
            log.debug("Skipping JWT filter for path: {}", requestPath);
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

            // CORRECCIÓN PRINCIPAL: Verificar que el token NO esté expirado NI revocado
            final boolean isTokenValid = tokenRepository.findByToken(jwt)
                    .map(token -> {
                        boolean isNotExpired = !token.getIsExpired();
                        boolean isNotRevoked = !token.getIsRevoked();
                        log.debug("Token validation - Expired: {}, Revoked: {}", token.getIsExpired(), token.getIsRevoked());
                        return isNotExpired && isNotRevoked;
                    })
                    .orElse(false); // Si no encuentra el token en BD, es inválido

            log.debug("Token valid in database: {}", isTokenValid);

            if (isTokenValid) {
                final Optional<User> user = userRepository.findByEmail(userEmail);

                if (user.isPresent()) {
                    // Verificar también la validez del JWT (firma, expiración, etc.)
                    final boolean isJwtValid = jwtService.isTokenValid(jwt, user.get());
                    log.debug("JWT signature and expiration valid: {}", isJwtValid);

                    if (isJwtValid) {
                        log.debug("Authenticating user: {}", userEmail);

                        // DEBUG: Verificar el rol del usuario
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
                        authToken.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request)
                        );
                        SecurityContextHolder.getContext().setAuthentication(authToken);

                        log.debug("User {} authenticated successfully with authorities: {}",
                                userEmail, userDetails.getAuthorities());
                    } else {
                        log.warn("JWT token signature/expiration invalid for user: {}", userEmail);
                    }
                } else {
                    log.warn("User not found in database: {}", userEmail);
                }
            } else {
                log.warn("Token is expired, revoked, or not found in database");
            }

        } catch (Exception e) {
            log.error("Error processing JWT authentication: {}", e.getMessage(), e);
            // No lanzar excepción, continuar sin autenticar
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Determina si el filtro JWT debe ser omitido para ciertos paths
     */
    private boolean shouldSkipJwtFilter(String requestPath) {
        return requestPath.contains("/auth") ||
                requestPath.contains("/h2-console") ||
                requestPath.startsWith("/error") ||
                requestPath.equals("/") ||
                requestPath.startsWith("/public");
    }
}