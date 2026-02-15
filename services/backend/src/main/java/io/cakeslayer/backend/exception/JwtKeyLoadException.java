package io.cakeslayer.backend.exception;

public class JwtKeyLoadException extends RuntimeException {
    public JwtKeyLoadException(String message, Exception e) {
        super(message, e);
    }
}
