package io.cakeslayer.backend.exception;

public class HashingAlgorithmNotSupportedException extends RuntimeException {
    public HashingAlgorithmNotSupportedException(String message) {
        super(message);
    }
}
