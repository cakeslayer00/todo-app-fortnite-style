package io.cakeslayer.backend.service.impl;

import io.cakeslayer.backend.dto.request.LoginRequest;
import io.cakeslayer.backend.dto.request.RegisterRequest;
import io.cakeslayer.backend.dto.response.AuthResponse;
import io.cakeslayer.backend.entity.User;
import io.cakeslayer.backend.exception.UserAlreadyExistsException;
import io.cakeslayer.backend.repository.UserRepository;
import io.cakeslayer.backend.service.AuthService;
import io.cakeslayer.backend.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final String ERR_USER_ALREADY_EXISTS = "User with email '%s' already exists";

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Override
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new UserAlreadyExistsException(ERR_USER_ALREADY_EXISTS.formatted(request.email()));
        }

        User user = new User();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        userRepository.save(user);

        log.info("New user '{}' is created", user.getUsername());
        return authenticate(new LoginRequest(request.email(), request.password()));
    }

    @Override
    public AuthResponse authenticate(LoginRequest request) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password())
        );

        UserDetails userDetails = (UserDetails) auth.getPrincipal();
        String token = jwtService.generateToken(userDetails);

        log.info("User {} is authenticated", userDetails.getUsername());
        return new AuthResponse(userDetails.getUsername(), token);
    }
}
