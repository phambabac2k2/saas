package com.bacpham.saas.security;

import com.bacpham.saas.exceptions.UnauthorizedException;
import com.bacpham.saas.properties.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.annotation.Nonnull;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenService {

    private final JwtProperties jwtProperties;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    public void init() {
        try {
            if (this.jwtProperties.getPrivateKey() == null || this.jwtProperties.getPrivateKey().isBlank()) {
                throw new RuntimeException("JWT Private Key is missing");
            }
            if (this.jwtProperties.getPublicKey() == null || this.jwtProperties.getPublicKey().isBlank()) {
                throw new RuntimeException("JWT Public Key is missing");
            }

            this.privateKey = parsePrivateKey(this.jwtProperties.getPrivateKey());
            this.publicKey = parsePublicKey(this.jwtProperties.getPublicKey());

            log.info("Private & Public key loaded successfully");
        } catch (final Exception e) {
            log.error("Error loading keys", e);
            throw new RuntimeException("Error loading keys", e);
        }
    }

    public String generateAccessToken(
            @Nonnull final String tenantId,
            @Nonnull final String userId,
            final String role
    ) {
        final Date now = new Date();
        final Date expiration = new Date(System.currentTimeMillis() + this.jwtProperties.getAccessTokenExpiration());

        return Jwts.builder()
                .subject(userId)
                .claim("tenant_id", tenantId)
                .claim("role", role)
                .issuedAt(now)
                .expiration(expiration)
                .issuer("stock-saas-app")
                .signWith(this.privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public Claims validateAndGetClaims(final String token) {
        try {
            return Jwts.parser()
                    .verifyWith(this.publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (final ExpiredJwtException e) {
            throw new UnauthorizedException("Token has expired");
        } catch (final UnsupportedOperationException e) {
            throw new UnauthorizedException("Token is not signed");
        } catch (final MalformedJwtException e) {
            throw new UnauthorizedException("Token is malformed");
        } catch (final SecurityException e) {
            throw new UnauthorizedException("Invalid JWT Signature");
        } catch (final IllegalArgumentException e) {
            throw new UnauthorizedException("JWT claims string is empty");
        }
    }

    private PrivateKey parsePrivateKey(final String key) throws Exception {
        final String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        final byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    private PublicKey parsePublicKey(final String key) throws Exception {
        final String publicKeyPEM = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        final byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }
}