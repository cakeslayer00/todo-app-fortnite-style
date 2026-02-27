package io.cakeslayer.backend.security.authentication.impl;

import io.cakeslayer.backend.config.properties.JwtProperties;
import io.cakeslayer.backend.entity.RefreshToken;
import io.cakeslayer.backend.entity.User;
import io.cakeslayer.backend.exception.security.RefreshTokenExpiredException;
import io.cakeslayer.backend.exception.security.RefreshTokenNotFoundException;
import io.cakeslayer.backend.exception.security.RefreshTokenRevokedException;
import io.cakeslayer.backend.repository.RefreshTokenRepository;
import io.cakeslayer.backend.security.authentication.RefreshTokenFamilyService;
import io.cakeslayer.backend.security.authentication.RefreshTokenService;
import io.cakeslayer.backend.security.token.RefreshTokenUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private static final String ERR_REFRESH_TOKEN_NOT_FOUND = "Refresh token not found";
    private static final String ERR_REFRESH_TOKEN_EXPIRED = "Refresh token has expired";
    private static final String ERR_REFRESH_TOKEN_REVOKED = "Refresh token has been revoked";
    private static final int GRACE_PERIOD = 30;

    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenFamilyService refreshTokenFamilyService;
    private final JwtProperties jwtProperties;

    @Override
    @Transactional
    public String createRefreshToken(User user) {
        return createRefreshToken(user, UUID.randomUUID());
    }

    @Override
    @Transactional
    public String createRefreshToken(User user, UUID familyId) {
        String plainToken = RefreshTokenUtils.generateRefreshToken();
        
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(RefreshTokenUtils.hashToken(plainToken));
        refreshToken.setUser(user);
        refreshToken.setFamilyId(familyId);
        refreshToken.setExpiresAt(Instant.now().plus(jwtProperties.refreshExpiration(), ChronoUnit.SECONDS));

        refreshTokenRepository.save(refreshToken);
        return plainToken;
    }

    @Override
    @Transactional
    public RefreshToken validateAndRevoke(String token) {
        String hashedToken = RefreshTokenUtils.hashToken(token);

        RefreshToken refreshToken = refreshTokenRepository.findByToken(hashedToken)
                .orElseThrow(() -> new RefreshTokenNotFoundException(ERR_REFRESH_TOKEN_NOT_FOUND));

        validateRefreshToken(refreshToken);

        refreshToken.setRevokedAt(Instant.now().plusSeconds(GRACE_PERIOD));
        return refreshTokenRepository.save(refreshToken);
    }

    @Override
    @Transactional
    public void revokeAllByUser(String username) {
        List<RefreshToken> tokens = refreshTokenRepository.findAllByUser_Username(username);
        tokens.forEach(rt -> rt.setRevokedAt(Instant.now()));
        refreshTokenRepository.saveAll(tokens);
    }

    private void validateRefreshToken(RefreshToken token) {
        if (token.isExpired()) {
            throw new RefreshTokenExpiredException(ERR_REFRESH_TOKEN_EXPIRED);
        }

        if (token.isRevoked()) {
            refreshTokenFamilyService.revokeFamily(token);
            throw new RefreshTokenRevokedException(ERR_REFRESH_TOKEN_REVOKED);
        }
    }
}
