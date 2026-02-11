package io.cakeslayer.backend.dto.response;

public record AuthResponse(
    String token,
    String email
) {}
