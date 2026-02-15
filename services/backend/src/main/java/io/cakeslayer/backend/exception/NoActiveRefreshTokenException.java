package io.cakeslayer.backend.exception;

public class NoActiveRefreshTokenException extends RuntimeException {
    public NoActiveRefreshTokenException(String message) {
        super(message);
    }
}
