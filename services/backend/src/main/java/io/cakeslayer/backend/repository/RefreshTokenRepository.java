package io.cakeslayer.backend.repository;

import io.cakeslayer.backend.entity.RefreshToken;
import io.cakeslayer.backend.entity.User;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.sql.Ref;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findAllByUser_Username(String username);

    List<RefreshToken> findAllByToken(String token);
}
