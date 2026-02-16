package io.cakeslayer.backend.exception.security;

public class RefreshTokenNotFoundException extends RefreshTokenException {
    public RefreshTokenNotFoundException(String message) {
        super(message);
    }
}
