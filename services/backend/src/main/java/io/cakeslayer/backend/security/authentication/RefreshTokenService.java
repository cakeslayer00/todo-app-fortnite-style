package io.cakeslayer.backend.security.authentication;

import io.cakeslayer.backend.entity.RefreshToken;
import io.cakeslayer.backend.entity.User;

import java.util.UUID;

public interface RefreshTokenService {

    RefreshToken createRefreshToken(User user);

    RefreshToken createRefreshToken(User user, UUID familyId);

    RefreshToken validateAndRevoke(String token);

    void revokeRefreshToken(UUID tokenId);
}
