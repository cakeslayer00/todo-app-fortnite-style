package io.cakeslayer.backend.service.impl;

import io.cakeslayer.backend.dto.request.LoginRequest;
import io.cakeslayer.backend.dto.request.RegisterRequest;
import io.cakeslayer.backend.dto.response.AuthResponse;
import io.cakeslayer.backend.entity.User;
import io.cakeslayer.backend.repository.UserRepository;
import io.cakeslayer.backend.service.AuthService;
import io.cakeslayer.backend.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    //TODO: implement AuthService

    @Override
    public AuthResponse register(RegisterRequest request) {
        return null;
    }

    @Override
    public AuthResponse authenticate(LoginRequest request) {
        return null;
    }
}
