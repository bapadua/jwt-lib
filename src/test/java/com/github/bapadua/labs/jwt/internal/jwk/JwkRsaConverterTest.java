package com.github.bapadua.labs.jwt.internal.jwk;

import com.github.bapadua.labs.jwt.JwtException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwkRsaConverterTest {

    private static RSAPublicKey publicKey;
    private static RSAPrivateKey privateKey;

    @BeforeAll
    static void gerarChaves() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        publicKey  = (RSAPublicKey) kp.getPublic();
        privateKey = (RSAPrivateKey) kp.getPrivate();
    }

    @Test
    @DisplayName("Pública: round-trip Key -> Jwk -> Key preserva valores")
    void publicaRoundTrip() {
        Jwk jwk = JwkRsaConverter.toJwk(publicKey, "key-01", "sig", "RS256");

        assertEquals("RSA", jwk.kty());
        assertEquals("key-01", jwk.kid());
        assertEquals("sig", jwk.use());
        assertEquals("RS256", jwk.alg());

        RSAPublicKey reconstruida = JwkRsaConverter.toPublicKey(jwk);

        assertEquals(publicKey.getModulus(), reconstruida.getModulus());
        assertEquals(publicKey.getPublicExponent(), reconstruida.getPublicExponent());
    }

    @Test
    @DisplayName("Privada: round-trip Key -> Jwk -> Key preserva valores")
    void privadaRoundTrip() {
        Jwk jwk = JwkRsaConverter.toJwk(privateKey, "key-01", "sig", "RS256");

        assertTrue(jwk.isPrivate());
        assertNotNull(jwk.d());
        assertNotNull(jwk.p());
        assertNotNull(jwk.q());

        RSAPrivateKey reconstruida = JwkRsaConverter.toPrivateKey(jwk);

        assertEquals(privateKey.getModulus(), reconstruida.getModulus());
        assertEquals(privateKey.getPrivateExponent(), reconstruida.getPrivateExponent());
    }

    @Test
    @DisplayName("JWK público não expõe material privado")
    void publicoNaoExpoePrivado() {
        Jwk jwk = JwkRsaConverter.toJwk(publicKey, "key-01", "sig", "RS256");

        assertFalse(jwk.isPrivate());
        assertNull(jwk.d());
        assertNull(jwk.p());
        assertNull(jwk.q());
        assertNull(jwk.dp());
        assertNull(jwk.dq());
        assertNull(jwk.qi());
    }

    @Test
    @DisplayName("Pública exposta em base64url não tem byte 0x00 à esquerda")
    void semByteZeroAEsquerda() throws Exception {
        // Gera várias chaves para aumentar a chance de pegar o caso "bit alto setado"
        for (int i = 0; i < 10; i++) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            RSAPublicKey pub = (RSAPublicKey) kpg.generateKeyPair().getPublic();

            Jwk jwk = JwkRsaConverter.toJwk(pub, "k", "sig", "RS256");

            byte[] modulusBytes = com.github.bapadua.labs.jwt.internal.Base64Url.decode(jwk.n());
            assertTrue(modulusBytes.length > 0);
            assertNotEquals(0x00, modulusBytes[0],
                    "Módulo não pode começar com 0x00 (RFC 7518)");
        }
    }

    @Test
    @DisplayName("JWK público reconstruído verifica assinatura real")
    void publicaReconstruidaVerifica() throws Exception {
        // Gera par, assina com privada, reconstrói pública via JWK, verifica
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();

        // Reconstrói a pública através de JWK
        Jwk jwk = JwkRsaConverter.toJwk(pub, "k", "sig", "RS256");
        RSAPublicKey pubReconstruida = JwkRsaConverter.toPublicKey(jwk);

        // Assina com a privada original
        byte[] data = "mensagem".getBytes();
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initSign(priv);
        sig.update(data);
        byte[] assinatura = sig.sign();

        // Verifica com a pública reconstruída
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withRSA");
        verifier.initVerify(pubReconstruida);
        verifier.update(data);
        assertTrue(verifier.verify(assinatura),
                "Chave pública reconstruída via JWK deve verificar assinaturas");
    }

    @Test
    @DisplayName("toPublicKey rejeita JWK não-RSA")
    void toPublicKeyRejeitaNaoRsa() {
        Jwk jwk = Jwk.ec().curve("P-256").x("x").y("y").kid("k").build();
        assertThrows(JwtException.class, () -> JwkRsaConverter.toPublicKey(jwk));
    }

    @Test
    @DisplayName("toPublicKey rejeita JWK RSA incompleto")
    void toPublicKeyRejeitaIncompleto() {
        // JWK com kty=RSA mas sem n/e é pego pelo Builder. Para simular
        // um JWK inválido vindo de fora, construímos via fromJson.
        String json = "{\"kty\":\"RSA\"}";
        assertThrows(JwtException.class, () -> {
            Jwk jwk = Jwk.fromJson(json);
            JwkRsaConverter.toPublicKey(jwk);
        });
    }

    @Test
    @DisplayName("toPrivateKey rejeita JWK público (sem material privado)")
    void toPrivateKeyRejeitaPublico() {
        Jwk jwk = JwkRsaConverter.toJwk(publicKey, "k", "sig", "RS256");
        assertThrows(JwtException.class, () -> JwkRsaConverter.toPrivateKey(jwk));
    }

    @Test
    @DisplayName("Round-trip via JSON preserva a chave pública")
    void roundTripViaJson() {
        Jwk original = JwkRsaConverter.toJwk(publicKey, "key-01", "sig", "RS256");

        // Serializa -> parseia -> reconstrói
        String json = original.toJson();
        Jwk parsed = Jwk.fromJson(json);
        RSAPublicKey reconstruida = JwkRsaConverter.toPublicKey(parsed);

        assertEquals(publicKey.getModulus(), reconstruida.getModulus());
        assertEquals(publicKey.getPublicExponent(), reconstruida.getPublicExponent());
    }
}