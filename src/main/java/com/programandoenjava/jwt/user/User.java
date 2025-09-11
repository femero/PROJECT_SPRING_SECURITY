package com.programandoenjava.jwt.user;

import com.programandoenjava.jwt.util.Role;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "_user") // Evitar conflictos con palabra reservada "user"
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String name;

    @Column(unique = true)
    private String email;

    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // IMPORTANTE: Verificar que role no sea null
        if (role == null) {
            return Collections.emptyList();
        }

        // Opción 1: Si tu enum Role tiene el método getAuthorities()
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
        // Opción 2: Si no tienes ese método, usar esto:
        // return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        // Spring Security usa username, pero nosotros usamos email
        return email;
    }

    /*@Override
    public boolean isAccountNonExpired() {
        return true;
    }
*/
 /*   @Override
    public boolean isAccountNonLocked() {
        return true;
    }*/

 /*   @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }*/

 /*   @Override
    public boolean isEnabled() {
        return true;
    }

  */
}