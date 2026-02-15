package io.cakeslayer.backend.service.impl;

import io.cakeslayer.backend.config.properties.JwtProperties;
import io.cakeslayer.backend.dto.request.LoginRequest;
import io.cakeslayer.backend.dto.request.RefreshRequest;
import io.cakeslayer.backend.dto.request.RegisterRequest;
import io.cakeslayer.backend.dto.response.AuthResponse;
import io.cakeslayer.backend.entity.RefreshToken;
import io.cakeslayer.backend.entity.User;
import io.cakeslayer.backend.exception.NoActiveRefreshTokenException;
import io.cakeslayer.backend.exception.UserAlreadyExistsException;
import io.cakeslayer.backend.repository.RefreshTokenRepository;
import io.cakeslayer.backend.repository.UserRepository;
import io.cakeslayer.backend.service.AuthService;
import io.cakeslayer.backend.service.JwtService;
import io.cakeslayer.backend.util.RefreshTokenUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final String ERR_USERNAME_ALREADY_EXISTS = "User with username '%s' already exists";
    private static final String ERR_REFRESH_TOKEN_NOT_FOUND = "Refresh token not found or inactive";

    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.findByUsername(request.username()).isPresent()) {
            throw new UserAlreadyExistsException(ERR_USERNAME_ALREADY_EXISTS.formatted(request.username()));
        }

        User user = new User();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        userRepository.save(user);

        log.info("New user '{}' is created", user.getUsername());
        return authenticate(new LoginRequest(request.username(), request.password()));
    }

    @Override
    @Transactional
    public AuthResponse authenticate(LoginRequest request) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password())
        );

        User user = (User) auth.getPrincipal();

        String accessToken = jwtService.generateToken(user);
        String refreshToken = RefreshTokenUtils.generateRefreshToken();

        saveRefreshToken(user, refreshToken);

        log.info("User '{}' is authenticated", user.getUsername());
        return new AuthResponse(user.getUsername(), accessToken, refreshToken);
    }

    @Override
    @Transactional
    public AuthResponse refresh(RefreshRequest request) {
        RefreshToken token = refreshTokenRepository.findByToken(RefreshTokenUtils.hashToken(request.refreshToken()))
                .filter(RefreshToken::isActive)
                .orElseThrow(()-> new NoActiveRefreshTokenException(ERR_REFRESH_TOKEN_NOT_FOUND));

        token.setRevokedAt(Instant.now());

        User user = token.getUser();
        String accessToken = jwtService.generateToken(user);
        String newRefreshToken = RefreshTokenUtils.generateRefreshToken();

        saveRefreshToken(user, newRefreshToken);

        return new AuthResponse(user.getUsername(), accessToken, newRefreshToken);
    }

    private void saveRefreshToken(User user, String plainToken) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(RefreshTokenUtils.hashToken(plainToken));
        refreshToken.setUser(user);
        refreshToken.setExpiresAt(Instant.now().plus(jwtProperties.refreshExpiration(), ChronoUnit.SECONDS));

        refreshTokenRepository.save(refreshToken);
    }

    // TODO: Add token family tracking for reuse detection, fix revocation to set active=false, validate expiration on refresh, implement logout endpoint, add scheduled cleanup job, optimize token size to 32 bytes, add database indexes, and reuse SecureRandom instance
}
