package io.cakeslayer.backend.util;

import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class JwtKeyLoaderUtils {

    private static final String BEGIN_PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String END_PRIVATE_KEY_HEADER = "-----END PRIVATE KEY-----";
    private static final String BEGIN_PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String END_PUBLIC_KEY_HEADER = "-----END PUBLIC KEY-----";
    private static final String ALGORITHM = "RSA";
    private static final String CHARSET_ENCODING = "UTF-8";
    private static final String EMPTY_STRING = "";

    private final ResourceLoader resourceLoader;

    public PrivateKey loadPrivateKeyFromPEM(String location)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Resource resource = resourceLoader.getResource(location);
        String key = readKeyFromResource(resource);

        String privateKeyPEM = key
                .replace(BEGIN_PRIVATE_KEY_HEADER, EMPTY_STRING)
                .replace(END_PRIVATE_KEY_HEADER, EMPTY_STRING)
                .replaceAll("\\s", EMPTY_STRING);

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }

    public PublicKey loadPublicKeyFromPEM(String location)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Resource resource = resourceLoader.getResource(location);
        String key = readKeyFromResource(resource);

        String publicKeyPEM = key
                .replace(BEGIN_PUBLIC_KEY_HEADER, EMPTY_STRING)
                .replace(END_PUBLIC_KEY_HEADER, EMPTY_STRING)
                .replaceAll("\\s", EMPTY_STRING);

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(keySpec);
    }

    private String readKeyFromResource(Resource resource) throws IOException {
        try (InputStream inputStream = resource.getInputStream()) {
            return new String(inputStream.readAllBytes(), CHARSET_ENCODING);
        }
    }
}
