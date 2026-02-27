package io.cakeslayer.backend.security.logout;

import io.cakeslayer.backend.security.authentication.RefreshTokenService;
import io.cakeslayer.backend.security.jwt.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class TokenLogoutHandler implements LogoutHandler {

    private final RefreshTokenService refreshTokenService;
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

        UUID tokenId = UUID.fromString(jwtService.extractJTI(token));

        refreshTokenService.revokeRefreshToken(tokenId);
    }
}
