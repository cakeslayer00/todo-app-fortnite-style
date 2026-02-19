package io.cakeslayer.backend.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(@NotBlank(message = "Username is required")
                           @Size(min = 6, message = "Username should be at least 6 characters")
                           String username,

                           @NotBlank(message = "Password is required")
                           String password
) {
}
