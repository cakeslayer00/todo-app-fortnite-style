package io.cakeslayer.backend.exception.security;

public class RefreshTokenRevokedException extends RefreshTokenException {
    public RefreshTokenRevokedException(String message) {
        super(message);
    }
}
