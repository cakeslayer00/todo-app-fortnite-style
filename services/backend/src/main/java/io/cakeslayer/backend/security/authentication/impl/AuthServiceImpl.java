package io.cakeslayer.backend.security.authentication.impl;

import io.cakeslayer.backend.dto.request.LoginRequest;
import io.cakeslayer.backend.dto.request.RefreshRequest;
import io.cakeslayer.backend.dto.request.RegisterRequest;
import io.cakeslayer.backend.dto.response.AuthResponse;
import io.cakeslayer.backend.entity.RefreshToken;
import io.cakeslayer.backend.entity.User;
import io.cakeslayer.backend.exception.UserAlreadyExistsException;
import io.cakeslayer.backend.repository.UserRepository;
import io.cakeslayer.backend.security.authentication.AuthService;
import io.cakeslayer.backend.security.authentication.RefreshTokenService;
import io.cakeslayer.backend.security.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final String ERR_USERNAME_ALREADY_EXISTS = "User with username '%s' already exists";
    private static final String ERR_EMAIL_ALREADY_EXISTS = "User with email '%s' already exists";

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

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
        log.info("New user '{}' is created", request.username());
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
        String refreshToken = refreshTokenService.createRefreshToken(user);

        log.info("User '{}' is authenticated", user.getUsername());
        return new AuthResponse(user.getUsername(), accessToken, refreshToken);
    }

    @Override
    @Transactional
    public AuthResponse refresh(RefreshRequest request) {
        RefreshToken token = refreshTokenService.validateAndRevoke(request.refreshToken());

        User user = token.getUser();
        String accessToken = jwtService.generateToken(user);
        String newRefreshToken = refreshTokenService.createRefreshToken(user, token.getFamilyId());

        return new AuthResponse(user.getUsername(), accessToken, newRefreshToken);
    }
}
