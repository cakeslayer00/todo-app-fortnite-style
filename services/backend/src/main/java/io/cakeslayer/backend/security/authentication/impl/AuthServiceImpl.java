package io.cakeslayer.backend.security.authentication.impl;

import io.cakeslayer.backend.config.properties.JwtProperties;
import io.cakeslayer.backend.dto.request.LoginRequest;
import io.cakeslayer.backend.dto.request.RefreshRequest;
import io.cakeslayer.backend.dto.request.RegisterRequest;
import io.cakeslayer.backend.dto.response.AuthResponse;
import io.cakeslayer.backend.entity.RefreshToken;
import io.cakeslayer.backend.entity.User;
import io.cakeslayer.backend.exception.security.RefreshTokenExpiredException;
import io.cakeslayer.backend.exception.security.RefreshTokenNotFoundException;
import io.cakeslayer.backend.exception.security.RefreshTokenRevokedException;
import io.cakeslayer.backend.exception.UserAlreadyExistsException;
import io.cakeslayer.backend.repository.RefreshTokenRepository;
import io.cakeslayer.backend.repository.UserRepository;
import io.cakeslayer.backend.security.authentication.AuthService;
import io.cakeslayer.backend.security.jwt.JwtService;
import io.cakeslayer.backend.security.token.RefreshTokenUtils;
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
import java.util.List;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final String ERR_USERNAME_ALREADY_EXISTS = "User with username '%s' already exists";
    private static final String ERR_EMAIL_ALREADY_EXISTS = "User with email '%s' already exists";
    private static final String ERR_REFRESH_TOKEN_NOT_FOUND = "Refresh token not found";
    private static final String ERR_REFRESH_TOKEN_EXPIRED = "Refresh token has expired";
    private static final String ERR_REFRESH_TOKEN_REVOKED = "Refresh token has been revoked";

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

        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new UserAlreadyExistsException(ERR_EMAIL_ALREADY_EXISTS.formatted(request.email()));
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
        String hashedToken = RefreshTokenUtils.hashToken(request.refreshToken());

        RefreshToken token = refreshTokenRepository.findByToken(hashedToken)
                .orElseThrow(() -> new RefreshTokenNotFoundException(ERR_REFRESH_TOKEN_NOT_FOUND));

        validateRefreshToken(token);

        token.setRevokedAt(Instant.now());

        User user = token.getUser();
        String accessToken = jwtService.generateToken(user);
        String newRefreshToken = RefreshTokenUtils.generateRefreshToken();

        saveRefreshToken(user, newRefreshToken, token.getFamilyId());

        return new AuthResponse(user.getUsername(), accessToken, newRefreshToken);
    }

    private void validateRefreshToken(RefreshToken token) {
        if (token.isExpired()) {
            throw new RefreshTokenExpiredException(ERR_REFRESH_TOKEN_EXPIRED);
        }

        if (token.isRevoked()) {
            handleTokenReuse(token);
            throw new RefreshTokenRevokedException(ERR_REFRESH_TOKEN_REVOKED);
        }
    }

    private void handleTokenReuse(RefreshToken token) {
        log.warn("Refresh token reuse detected for user: {}", token.getUser().getUsername());
        log.warn("Revoking all tokens in family: {}", token.getFamilyId());
        List<RefreshToken> family = refreshTokenRepository.findAllByFamilyId(token.getFamilyId());
        family.forEach(rt -> rt.setRevokedAt(Instant.now()));
        refreshTokenRepository.saveAll(family);
    }

    private void saveRefreshToken(User user, String plainToken) {
        saveRefreshToken(user, plainToken, UUID.randomUUID());
    }

    private void saveRefreshToken(User user, String plainToken, UUID familyId) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(RefreshTokenUtils.hashToken(plainToken));
        refreshToken.setUser(user);
        refreshToken.setFamilyId(familyId);
        refreshToken.setExpiresAt(Instant.now().plus(jwtProperties.refreshExpiration(), ChronoUnit.SECONDS));

        refreshTokenRepository.save(refreshToken);
    }
}
