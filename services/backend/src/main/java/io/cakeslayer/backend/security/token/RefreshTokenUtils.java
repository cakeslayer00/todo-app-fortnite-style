package io.cakeslayer.backend.security.token;

import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@UtilityClass
public class RefreshTokenUtils {

    private static final String REFRESH_TOKEN_HASHING_ALGORITHM = "SHA-256";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int TOKEN_SIZE_BYTES = 32;

    public String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance(REFRESH_TOKEN_HASHING_ALGORITHM);
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public String generateRefreshToken() {
        byte[] bytes = new byte[TOKEN_SIZE_BYTES];
        SECURE_RANDOM.nextBytes(bytes);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
