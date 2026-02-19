package io.cakeslayer.backend.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AuthResponse(String username,
                           @JsonProperty("access_token") String accessToken,
                           @JsonProperty("refresh_token") String refreshToken
) {
}
