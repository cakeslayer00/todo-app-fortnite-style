package io.cakeslayer.backend.security.authentication;

import io.cakeslayer.backend.dto.request.LoginRequest;
import io.cakeslayer.backend.dto.request.RefreshRequest;
import io.cakeslayer.backend.dto.request.RegisterRequest;
import io.cakeslayer.backend.dto.response.AuthResponse;

public interface AuthService {

    AuthResponse register(RegisterRequest request);

    AuthResponse authenticate(LoginRequest request);
    
    AuthResponse refresh(RefreshRequest refreshToken);
}
