package com.programandoenjava.jwt.auth.repository;

import com.programandoenjava.jwt.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public final class Token {

    @Id
    @GeneratedValue
    private Integer id;

    @Column(unique = true, length = 1000)
    private String token;

    @Enumerated(EnumType.STRING)
    @Builder.Default
    private TokenType tokenType = TokenType.BEARER;

    @Enumerated(EnumType.STRING)
    @Builder.Default
    private TokenCategory tokenCategory = TokenCategory.ACCESS;

    @Column(name = "revoked", nullable = false)
    private Boolean isRevoked;

    @Column(name = "expired", nullable = false)
    private Boolean isExpired;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    public enum TokenType {
        BEARER
    }

    public enum TokenCategory {
        ACCESS,
        REFRESH
    }
}