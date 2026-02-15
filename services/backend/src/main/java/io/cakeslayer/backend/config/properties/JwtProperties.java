package io.cakeslayer.backend.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("jwt")
public record JwtProperties(String privateKey,
                            String publicKey,
                            long expiration) {
}