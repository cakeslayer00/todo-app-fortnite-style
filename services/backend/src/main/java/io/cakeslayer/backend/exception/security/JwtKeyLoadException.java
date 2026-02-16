package io.cakeslayer.backend.exception.security;

public class JwtKeyLoadException extends RuntimeException {
    public JwtKeyLoadException(String message, Exception e) {
        super(message, e);
    }
}
