package io.cakeslayer.backend.exception;

public class UserUnauthenticatedException extends RuntimeException {
    public UserUnauthenticatedException(String message) {
        super(message);
    }
}
