package com.programandoenjava.jwt.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {

    @Query(value = """
      select t from Token t inner join User u 
      on t.user.id = u.id 
      where u.id = :id and (t.isExpired = false or t.isRevoked = false) 
      """)
    List<Token> findAllValidTokenByUser(Integer id);

    @Query(value = """
      select t from Token t inner join User u 
      on t.user.id = u.id 
      where u.id = :userId and t.tokenCategory = 'REFRESH' 
      and (t.isExpired = false or t.isRevoked = false) 
      """)
    List<Token> findAllValidRefreshTokensByUser(Integer userId);

    Optional<Token> findByToken(String token);
}