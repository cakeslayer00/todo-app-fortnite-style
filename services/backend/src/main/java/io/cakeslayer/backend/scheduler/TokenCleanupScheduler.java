package io.cakeslayer.backend.scheduler;

import io.cakeslayer.backend.repository.RefreshTokenRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@Slf4j
@RequiredArgsConstructor
public class TokenCleanupScheduler {

    private final RefreshTokenRepository refreshTokenRepository;

    @Scheduled(cron = "${scheduler.expired-token-cleanup.cron}")
    @Transactional
    public void cleanupExpiredTokens() {
        int deleted = refreshTokenRepository.deleteAllByExpiresAtBefore(Instant.now());
        log.info("Cleaned up {} expired refresh tokens", deleted);
    }

    @Scheduled(cron = "${scheduler.revoked-token-cleanup.cron}")
    @Transactional
    public void cleanupRevokedTokens() {
        int deleted = refreshTokenRepository.deleteAllByRevokedAtBefore(Instant.now());
        log.info("Cleaned up {} revoked refresh tokens", deleted);
    }
}
