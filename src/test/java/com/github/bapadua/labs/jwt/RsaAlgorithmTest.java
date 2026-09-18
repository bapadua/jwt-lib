package com.github.bapadua.labs.jwt;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RsaAlgorithmTest {

    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    @BeforeAll
    static void gerarChaves() throws Exception {
        // 2048 bits é o mínimo recomendado hoje. 4096 é mais lento.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        privateKey = kp.getPrivate();
        publicKey  = kp.getPublic();
    }

    @Test
    @DisplayName("RS256 assina com PrivateKey e verifica com PublicKey")
    void roundTrip() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);

        byte[] signature = Algorithm.RS256.sign(data, privateKey);
        assertNotNull(signature);
        assertTrue(signature.length >= 256); // 2048 bits / 8 = 256 bytes

        assertTrue(Algorithm.RS256.verify(data, signature, publicKey));
    }

    @Test
    @DisplayName("verify rejeita assinatura adulterada")
    void rejeitaAdulterada() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);
        byte[] signature = Algorithm.RS256.sign(data, privateKey);

        signature[10] ^= 0x01;

        assertFalse(Algorithm.RS256.verify(data, signature, publicKey));
    }

    @Test
    @DisplayName("verify rejeita mensagem alterada")
    void rejeitaMensagemAlterada() {
        byte[] data      = "mensagem".getBytes(StandardCharsets.UTF_8);
        byte[] dataAlter = "mensagem!".getBytes(StandardCharsets.UTF_8);

        byte[] signature = Algorithm.RS256.sign(data, privateKey);

        assertFalse(Algorithm.RS256.verify(dataAlter, signature, publicKey));
    }

    @Test
    @DisplayName("verify rejeita chave pública de outro par")
    void rejeitaChaveDeOutroPar() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        PublicKey outraPublica = kpg.generateKeyPair().getPublic();

        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);
        byte[] signature = Algorithm.RS256.sign(data, privateKey);

        assertFalse(Algorithm.RS256.verify(data, signature, outraPublica));
    }

    @Test
    @DisplayName("RS256 assinar com PublicKey lança exceção")
    void assinarComPublicaFalha() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);

        JwtException ex = assertThrows(JwtException.class, () ->
                Algorithm.RS256.sign(data, publicKey)
        );
        assertTrue(ex.getMessage().contains("PrivateKey"));
    }

    @Test
    @DisplayName("RS256 verificar com PrivateKey lança exceção")
    void verificarComPrivadaFalha() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);
        byte[] sig  = Algorithm.RS256.sign(data, privateKey);

        JwtException ex = assertThrows(JwtException.class, () ->
                Algorithm.RS256.verify(data, sig, privateKey)
        );
        assertTrue(ex.getMessage().contains("PublicKey"));
    }

    @Test
    @DisplayName("fromJwtName reconhece RS256")
    void fromJwtName() {
        assertEquals(Algorithm.RS256, Algorithm.fromJwtName("RS256"));
    }

    @Test
    @DisplayName("RS384 assina e verifica")
    void rs384RoundTrip() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);
        byte[] sig = Algorithm.RS384.sign(data, privateKey);
        assertTrue(Algorithm.RS384.verify(data, sig, publicKey));
    }

    @Test
    @DisplayName("RS512 assina e verifica")
    void rs512RoundTrip() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);
        byte[] sig = Algorithm.RS512.sign(data, privateKey);
        assertTrue(Algorithm.RS512.verify(data, sig, publicKey));
    }

    @Test
    @DisplayName("Token RS384 end-to-end")
    void endToEndRs384() {
        KeyPair kp = TestKeys.rsa();
        String token = Jwts.builder()
                .alg(Algorithm.RS384)
                .signWith(kp.getPrivate())
                .subject("user-1")
                .compact();

        Jwt jwt = Jwts.parser().verifyWith(kp.getPublic()).parse(token);
        assertEquals("user-1", jwt.getSubject());
        assertEquals("RS384", jwt.getHeader().get("alg"));
    }
}