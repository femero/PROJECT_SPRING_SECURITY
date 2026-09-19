package com.programandoenjava.jwt.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.programandoenjava.jwt.auth.repository.Token;
import com.programandoenjava.jwt.auth.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
@Slf4j
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final TokenRepository tokenRepository;

    private static Customizer <AuthorizeHttpRequestsConfigurer <HttpSecurity>.AuthorizationManagerRequestMatcherRegistry> builderRequestMatchers () {
        return req -> req
                // Endpoints públicos - NO requieren autenticación
                .requestMatchers ("/api/v1/auth/register", "/api/v1/auth/login", "/h2-console/**", "/error", "/actuator/**", "/actuator/health", "/actuator/prometheus", "/actuator/metrics", "/actuator/info")
                .permitAll ()

                // Refresh token requiere autenticación (con refresh token válido)
                .requestMatchers ("/api/v1/auth/refresh-token")
                .authenticated ()

                // Endpoints específicos por ROL
                /*.requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/v1/editor/**").hasAnyRole("ADMIN", "EDITOR")*/

                // Endpoints específicos por PERMISO
                /*   .requestMatchers("/api/v1/read/**").hasAuthority("READ")
                   .requestMatchers("/api/v1/write/**").hasAuthority("WRITE")*/

                // Cualquier otra petición requiere autenticación
                .anyRequest ()
                .authenticated ();
    }

    @Bean
    public SecurityFilterChain securityFilterChain (final HttpSecurity http) throws Exception {
        http.csrf (AbstractHttpConfigurer :: disable)
                .cors (AbstractHttpConfigurer :: disable)
                .headers (headers -> headers
                        // Prevenir clickjacking
                        .frameOptions (frame -> frame.deny ())

                        // XSS Protection
                        .xssProtection (xss -> xss.headerValue (XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))

                        // Content Type Options
                        .contentTypeOptions (contentType -> contentType.disable ())

                        // HSTS (HTTP Strict Transport Security)
                        .httpStrictTransportSecurity (hsts -> hsts.includeSubDomains (true)
                                .maxAgeInSeconds (31536000) // 1 año
                        )

                        // Referrer Policy
                        .referrerPolicy (referrer -> referrer.policy (ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))

                        // Content Security Policy
                        .contentSecurityPolicy (csp -> csp.policyDirectives ("default-src 'self'; " + "script-src 'self' 'unsafe-inline'; " + "style-src 'self' 'unsafe-inline'; " + "img-src 'self' data: https:; " + "font-src 'self' data:; " + "connect-src 'self' http://localhost:* ws://localhost:*"))

                        // Permissions Policy (antes Feature-Policy)
                        .permissionsPolicy (permissions -> permissions.policy ("geolocation=(), microphone=(), camera=()")))
                .sessionManagement (session -> session.sessionCreationPolicy (STATELESS))
                .authenticationProvider (authenticationProvider)
                .addFilterBefore (jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests (builderRequestMatchers ())
                // Configurar manejo de errores de autenticación (401) y autorización (403)
                .exceptionHandling (exception -> exception.authenticationEntryPoint (jwtAuthenticationEntryPoint ())
                        .accessDeniedHandler (jwtAccessDeniedHandler ()))
                .logout (logout -> logout.logoutUrl ("/auth/logout")
                        .addLogoutHandler (this :: logout)
                        .logoutSuccessHandler ((request, response, authentication) -> SecurityContextHolder.clearContext ()));

        return http.build ();
    }

    /**
     * Maneja errores de autenticación (401 Unauthorized)
     * Se activa cuando:
     * - No hay token JWT en la petición
     * - El token JWT es inválido (firma incorrecta, formato incorrecto)
     * - El token JWT ha expirado
     * - El token JWT ha sido revocado
     */
    @Bean
    public AuthenticationEntryPoint jwtAuthenticationEntryPoint () {
        return (request, response, authException) -> {
            log.error ("❌ Error de autenticación (401): {} - Path: {}", authException.getMessage (), request.getRequestURI ());

            response.setContentType (MediaType.APPLICATION_JSON_VALUE);
            response.setStatus (HttpServletResponse.SC_UNAUTHORIZED);

            Map <String, Object> errorDetails = new HashMap <> ();
            errorDetails.put ("timestamp", LocalDateTime.now ()
                    .toString ());
            errorDetails.put ("status", String.valueOf (HttpServletResponse.SC_UNAUTHORIZED));
            errorDetails.put ("error", "Unauthorized");
            errorDetails.put ("message", "Token JWT inválido, expirado o ausente. Por favor, inicie sesión nuevamente.");
            errorDetails.put ("path", request.getRequestURI ());

            ObjectMapper mapper = new ObjectMapper ();
            mapper.writeValue (response.getOutputStream (), errorDetails);
        };
    }

    /**
     * Maneja errores de autorización (403 Forbidden)
     * Se activa cuando:
     * - El usuario está autenticado (tiene token válido)
     * - Pero NO tiene los permisos necesarios para acceder al recurso
     */
    @Bean
    public AccessDeniedHandler jwtAccessDeniedHandler () {
        return (request, response, accessDeniedException) -> {
            log.error ("🚫 Error de autorización (403): {} - Path: {}", accessDeniedException.getMessage (), request.getRequestURI ());

            response.setContentType (MediaType.APPLICATION_JSON_VALUE);
            response.setStatus (HttpServletResponse.SC_FORBIDDEN);

            Map <String, Object> errorDetails = new HashMap <> ();
            errorDetails.put ("timestamp", LocalDateTime.now ()
                    .toString ());
            errorDetails.put ("status", String.valueOf (HttpServletResponse.SC_FORBIDDEN));
            errorDetails.put ("error", "Forbidden");
            errorDetails.put ("message", "No tiene permisos suficientes para acceder a este recurso.");
            errorDetails.put ("path", request.getRequestURI ());

            ObjectMapper mapper = new ObjectMapper ();
            mapper.writeValue (response.getOutputStream (), errorDetails);
        };
    }

    private void logout (final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) {

        final String authHeader = request.getHeader (HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith ("Bearer ")) {
            return;
        }

        final String jwt = authHeader.substring (7);
        final Token storedToken = tokenRepository.findByToken (jwt)
                .orElse (null);
        if (storedToken != null) {
            storedToken.setIsExpired (Boolean.TRUE);
            storedToken.setIsRevoked (Boolean.TRUE);
            tokenRepository.save (storedToken);
            SecurityContextHolder.clearContext ();
        }
    }
}
