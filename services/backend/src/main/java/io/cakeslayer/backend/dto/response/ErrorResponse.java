package io.cakeslayer.backend.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

public record ErrorResponse(int status,
                            String message,
                            @JsonInclude(JsonInclude.Include.NON_NULL) Map<String, String> errors
) {
    public ErrorResponse(int status, String message) {
        this(status, message, null);
    }
}
