package io.cakeslayer.backend.security.authentication;

import io.cakeslayer.backend.entity.RefreshToken;
import io.cakeslayer.backend.entity.User;

import java.util.UUID;

public interface RefreshTokenService {
    String createRefreshToken(User user);
    String createRefreshToken(User user, UUID familyId);
    RefreshToken validateAndRevoke(String token);
    void revokeAllByUser(String username);
}
