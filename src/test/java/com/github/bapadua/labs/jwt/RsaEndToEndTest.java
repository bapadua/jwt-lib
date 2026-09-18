package com.github.bapadua.labs.jwt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class RsaEndToEndTest {
    @Test
    @DisplayName("End-to-end RS256: builder assina, parser verifica")
    void endToEndRs256() {
        KeyPair kp = TestKeys.rsa();

        String token = Jwts.builder()
                .alg(Algorithm.RS256)
                .signWith(kp.getPrivate())
                .keyId("key-rsa-01")
                .subject("user-1")
                .issuer("https://idp.example.com")
                .audience("minha-api")
                .expiresInSeconds(3600)
                .compact();

        Jwt jwt = Jwts.parser()
                .verifyWith(kp.getPublic())
                .requireAlgorithm(Algorithm.RS256)
                .requireIssuer("https://idp.example.com")
                .requireAudience("minha-api")
                .parse(token);

        assertEquals("user-1", jwt.getSubject());
        assertEquals("key-rsa-01", jwt.getKeyId());
        assertEquals("RS256", jwt.getHeader().get("alg"));
    }

    @Test
    @DisplayName("Parser rejeita token RS256 se a chave for de outro par")
    void rejeitaChaveDeOutroParEndToEnd() throws Exception {
        KeyPair kp1 = TestKeys.rsa();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        PublicKey outraPublica = kpg.generateKeyPair().getPublic();

        String token = Jwts.builder()
                .alg(Algorithm.RS256)
                .signWith(kp1.getPrivate())
                .subject("user-1")
                .compact();

        assertThrows(JwtException.class, () ->
                Jwts.parser().verifyWith(outraPublica).parse(token)
        );
    }
}
