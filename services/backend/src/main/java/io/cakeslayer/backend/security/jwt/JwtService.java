package io.cakeslayer.backend.security.jwt;

import io.cakeslayer.backend.config.properties.JwtProperties;
import io.cakeslayer.backend.entity.User;
import io.cakeslayer.backend.exception.security.JwtKeyLoadException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.UUID;
import java.util.function.Function;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtService {

    private static final SignatureAlgorithm ALGORITHM = Jwts.SIG.RS256;

    private final JwtProperties properties;
    private final JwtKeyLoader jwtKeyLoader;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    private void init() {
        try {
            this.privateKey = jwtKeyLoader.loadPrivateKey(properties.privateKey());
            this.publicKey = jwtKeyLoader.loadPublicKey(properties.publicKey());
        } catch (Exception e) {
            throw new JwtKeyLoadException("Failed to load JWT keys", e);
        }
    }

    public String generateToken(User user, UUID refreshTokenId) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + properties.expiration());

        return Jwts.builder()
                .subject(user.getId().toString())
                .id(refreshTokenId.toString())
                .issuer(properties.issuer())
                .issuedAt(now)
                .expiration(expiration)
                .signWith(privateKey, ALGORITHM)
                .compact();
    }

    public String extractSubject(String token) {
        return readClaim(token, Claims::getSubject);
    }

    public boolean isTokenValid(String token) {
        try {
            String issuer = extractIssuer(token);
            return properties.issuer().equals(issuer) && !isTokenExpired(token);
        } catch (JwtException e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    private <T> T readClaim(String token, Function<Claims, T> claimsResolver) {
        try {
            Claims claims = readAllClaims(token);
            return claimsResolver.apply(claims);
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Failed to read claim: {}", e.getMessage());
            throw e;
        }
    }

    private Date extractExpiration(String token) {
        return readClaim(token, Claims::getExpiration);
    }

    private String extractIssuer(String token) {
        return readClaim(token, Claims::getIssuer);
    }

    private boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (JwtException e) {
            log.debug("Token expiration check failed: {}", e.getMessage());
            return true;
        }
    }

    private Claims readAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractJTI(String token) {
        return readClaim(token, Claims::getId);
    }
}