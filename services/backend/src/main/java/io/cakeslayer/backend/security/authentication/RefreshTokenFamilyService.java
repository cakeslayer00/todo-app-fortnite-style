package io.cakeslayer.backend.security.authentication;

import io.cakeslayer.backend.entity.RefreshToken;
import io.cakeslayer.backend.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenFamilyService {
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeFamily(RefreshToken token) {
        log.warn("Refresh token reuse detected for user: {}", token.getUser().getUsername());
        log.warn("Revoking all tokens in family: {}", token.getFamilyId());
        List<RefreshToken> family = refreshTokenRepository.findAllByFamilyId(token.getFamilyId());
        family.forEach(rt -> rt.setRevokedAt(Instant.now()));
        refreshTokenRepository.saveAll(family);
    }
}