package com.programandoenjava.jwt.auth.service;

import com.programandoenjava.jwt.user.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;
    
    // Configuración de validación JWT
    @Value("${application.security.jwt.validation.audiences:}")
    private List<String> allowedAudiences;
    
    @Value("${application.security.jwt.validation.failed-validation-httpcode:403}")
    private int failedValidationHttpCode;

    public String extractUsername(String token) {
        Claims claims = extractAllClaims(token);
        return claims.getSubject();
    }

    public String generateToken(final User user) {
        return buildToken(user, jwtExpiration);
    }

    public String generateRefreshToken(final User user) {
        return buildToken(user, refreshExpiration);
    }

    private String buildToken(final User user, final long expiration) {
        List<String> scopes = user.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .filter(auth -> !auth.startsWith("ROLE_"))
                .toList();

        return Jwts
                .builder()
                .setHeaderParam(Header.TYPE, "JWT")
                .setSubject("user-" + user.getId())
                .claim("roles", List.of(user.getRole().name()))
                .claim("scopes", scopes)
                .issuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey())
                .compact();
    }

    public boolean isTokenValid(String token, User user) {
        final String subject = extractUsername(token);
        return (subject.equals("user-" + user.getId())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration();
    }

    private SecretKey getSignInKey() {
        final byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Extrae todos los claims del token JWT
     */
    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Extrae un claim específico del token
     */
    @SuppressWarnings("unchecked")
    public <T> T extractClaim(String token, String claimName, Class<T> claimType) {
        Claims claims = extractAllClaims(token);
        return claims.get(claimName, claimType);
    }

    /**
     * Extrae roles del token JWT
     * Soporta tanto claim "roles" como "role"
     */
    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        Claims claims = extractAllClaims(token);

        // Extract "roles" as list
        Object rolesObj = claims.get("roles");
        if (rolesObj instanceof List) {
            return (List<String>) rolesObj;
        }

        return List.of();
    }

    /**
     * Extrae scopes/permisos del token JWT
     * Soporta claims "scp", "scope", "scopes"
     */
    @SuppressWarnings("unchecked")
    public List<String> extractScopes(String token) {
        Claims claims = extractAllClaims(token);
        
        // Intentar "scp" (Azure AD)
        Object scpObj = claims.get("scp");
        if (scpObj instanceof String) {
            return Arrays.asList(((String) scpObj).split(" "));
        } else if (scpObj instanceof List) {
            return (List<String>) scpObj;
        }
        
        // Intentar "scopes"
        Object scopesObj = claims.get("scopes");
        if (scopesObj instanceof List) {
            return (List<String>) scopesObj;
        }
        
        // Intentar "scope"
        String scope = claims.get("scope", String.class);
        if (scope != null) {
            return Arrays.asList(scope.split(" "));
        }
        
        return List.of();
    }

    /**
     * Extrae un claim personalizado (ej: department)
     */
    public String extractCustomClaim(String token, String claimName) {
        Claims claims = extractAllClaims(token);
        return claims.get(claimName, String.class);
    }

    /**
     * Extrae la audiencia (aud) del token
     */
    @SuppressWarnings("unchecked")
    public List<String> extractAudiences(String token) {
        Claims claims = extractAllClaims(token);
        Object audObj = claims.getAudience();
        
        if (audObj instanceof String) {
            return List.of((String) audObj);
        } else if (audObj instanceof List) {
            return (List<String>) audObj;
        }
        
        return List.of();
    }

    /**
     * Valida roles: al menos uno de los roles requeridos debe estar presente
     * @param token Token JWT
     * @param requiredRoles Lista de roles requeridos
     * @param matchType "any" (al menos uno) o "all" (todos)
     * @return true si la validación es exitosa
     */
    public boolean validateRoles(String token, List<String> requiredRoles, String matchType) {
        if (requiredRoles == null || requiredRoles.isEmpty()) {
            return true; // No hay roles requeridos
        }
        
        List<String> tokenRoles = extractRoles(token);
        log.debug("🔑 Validando roles - Token: {} | Requeridos: {} | Match: {}", tokenRoles, requiredRoles, matchType);
        
        if ("all".equalsIgnoreCase(matchType)) {
            // Todos los roles requeridos deben estar presentes
            boolean valid = tokenRoles.containsAll(requiredRoles);
            log.debug("✅ Validación roles (all): {}", valid);
            return valid;
        } else {
            // Al menos uno de los roles requeridos debe estar presente
            boolean valid = tokenRoles.stream().anyMatch(requiredRoles::contains);
            log.debug("✅ Validación roles (any): {}", valid);
            return valid;
        }
    }

    /**
     * Valida scopes/permisos
     * @param token Token JWT
     * @param requiredScopes Lista de scopes requeridos
     * @param matchType "any" (al menos uno) o "all" (todos)
     * @return true si la validación es exitosa
     */
    public boolean validateScopes(String token, List<String> requiredScopes, String matchType) {
        if (requiredScopes == null || requiredScopes.isEmpty()) {
            return true; // No hay scopes requeridos
        }
        
        List<String> tokenScopes = extractScopes(token);
        log.debug("🔑 Validando scopes - Token: {} | Requeridos: {} | Match: {}", tokenScopes, requiredScopes, matchType);
        
        if ("all".equalsIgnoreCase(matchType)) {
            // Todos los scopes requeridos deben estar presentes
            boolean valid = tokenScopes.containsAll(requiredScopes);
            log.debug("✅ Validación scopes (all): {}", valid);
            return valid;
        } else {
            // Al menos uno de los scopes requeridos debe estar presente
            boolean valid = tokenScopes.stream().anyMatch(requiredScopes::contains);
            log.debug("✅ Validación scopes (any): {}", valid);
            return valid;
        }
    }

    /**
     * Valida claim personalizado (ej: department)
     * @param token Token JWT
     * @param claimName Nombre del claim
     * @param allowedValues Valores permitidos
     * @param matchType "any" (al menos uno)
     * @return true si la validación es exitosa
     */
    public boolean validateCustomClaim(String token, String claimName, List<String> allowedValues, String matchType) {
        if (allowedValues == null || allowedValues.isEmpty()) {
            return true; // No hay valores requeridos
        }
        
        String claimValue = extractCustomClaim(token, claimName);
        log.debug("🔑 Validando claim '{}' - Token: {} | Permitidos: {} | Match: {}", 
                  claimName, claimValue, allowedValues, matchType);
        
        if (claimValue == null) {
            log.warn("❌ Claim '{}' no encontrado en el token", claimName);
            return false;
        }
        
        boolean valid = allowedValues.contains(claimValue);
        log.debug("✅ Validación claim '{}': {}", claimName, valid);
        return valid;
    }

    /**
     * Valida audiencias (aud)
     * @param token Token JWT
     * @param allowedAudiences Lista de audiencias permitidas
     * @return true si al menos una audiencia coincide
     */
    public boolean validateAudiences(String token, List<String> allowedAudiences) {
        if (allowedAudiences == null || allowedAudiences.isEmpty()) {
            return true; // No hay audiencias requeridas
        }
        
        List<String> tokenAudiences = extractAudiences(token);
        log.debug("🔑 Validando audiences - Token: {} | Permitidas: {}", tokenAudiences, allowedAudiences);
        
        boolean valid = tokenAudiences.stream().anyMatch(allowedAudiences::contains);
        log.debug("✅ Validación audiences: {}", valid);
        return valid;
    }

    /**
     * Validación completa de JWT con todas las reglas configuradas
     * @param token Token JWT
     * @return true si todas las validaciones pasan
     */
    public boolean validateTokenWithClaims(String token, User user) {
        try {
            // Validación básica (firma, expiración, usuario)
            if (!isTokenValid(token, user)) {
                log.warn("❌ Validación básica del token falló");
                return false;
            }
            
            // Validar audiencias si están configuradas
            if (!validateAudiences(token, allowedAudiences)) {
                log.warn("❌ Validación de audiences falló");
                return false;
            }
            
            log.info("✅ Token JWT válido con todos los claims requeridos");
            return true;
            
        } catch (Exception e) {
            log.error("❌ Error al validar token JWT: {}", e.getMessage(), e);
            return false;
        }
    }
}
