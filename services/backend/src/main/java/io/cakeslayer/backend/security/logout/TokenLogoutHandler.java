package io.cakeslayer.backend.security.logout;

import io.cakeslayer.backend.entity.RefreshToken;
import io.cakeslayer.backend.repository.RefreshTokenRepository;
import io.cakeslayer.backend.security.jwt.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Component
@RequiredArgsConstructor
public class TokenLogoutHandler implements LogoutHandler {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication) {
        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return;
        }
        String token = authorization.substring("Bearer ".length());

        String username = jwtService.extractSubject(token);

        List<RefreshToken> tokens = refreshTokenRepository.findAllByUser_Username(username);
        tokens.forEach(rt -> rt.setRevokedAt(Instant.now()));
        refreshTokenRepository.saveAll(tokens);
    }
}
