package io.cakeslayer.backend.exception.security;

public class HashingAlgorithmNotSupportedException extends RuntimeException {
    public HashingAlgorithmNotSupportedException(String message) {
        super(message);
    }
}
