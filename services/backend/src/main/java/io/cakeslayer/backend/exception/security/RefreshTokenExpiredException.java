package io.cakeslayer.backend.exception.security;

public class RefreshTokenExpiredException extends RefreshTokenException {
    public RefreshTokenExpiredException(String message) {
        super(message);
    }
}
