package io.cakeslayer.backend.security.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

@Component
@RequiredArgsConstructor
public class JwtKeyLoader {

    private static final Pattern PEM_PATTERN = Pattern.compile("-----[^-]+-----");
    private static final String ALGORITHM = "RSA";

    private final ResourceLoader resourceLoader;

    public PrivateKey loadPrivateKey(String location)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String keyContent = loadKeyContent(location);
        String cleanedKey = cleanPemFormat(keyContent);
        byte[] decoded = Base64.getDecoder().decode(cleanedKey);

        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        return keyFactory.generatePrivate(keySpec);
    }

    public PublicKey loadPublicKey(String location)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String keyContent = loadKeyContent(location);
        String cleanedKey = cleanPemFormat(keyContent);
        byte[] decoded = Base64.getDecoder().decode(cleanedKey);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(keySpec);
    }

    private String loadKeyContent(String location) throws IOException {
        Resource resource = resourceLoader.getResource(location);
        if (!resource.exists()) {
            throw new IOException("Key resource not found: " + location);
        }
        try (InputStream inputStream = resource.getInputStream()) {
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private String cleanPemFormat(String pemContent) {
        return PEM_PATTERN.matcher(pemContent)
                .replaceAll("")
                .replaceAll("\\s", "");
    }
}
