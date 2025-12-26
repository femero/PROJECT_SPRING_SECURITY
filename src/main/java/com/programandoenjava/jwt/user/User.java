package com.programandoenjava.jwt.user;

import com.programandoenjava.jwt.util.Role;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Getter
@Setter
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
        if (role == null) {
            return Collections.emptyList();
        }

        List<GrantedAuthority> authorities = new java.util.ArrayList<>();

        // Agregar el rol con prefijo ROLE_
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role.name()));

        // Agregar los permisos usando el scope (ej: "accounts:read")
        role.getPermissions().forEach(permission ->
                                              authorities.add(new SimpleGrantedAuthority(permission.getScope()))
        );

        return authorities;
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

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}