package com.github.bapadua.labs.jwt.internal.jwk;

import com.github.bapadua.labs.jwt.JwtException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwkTest {

    @Test
    @DisplayName("Cria JWK RSA mínimo (kty, n, e)")
    void rsaMinimo() {
        Jwk jwk = Jwk.rsa()
                .modulus("0vx7agoebGcQ")
                .exponent("AQAB")
                .build();

        assertEquals("RSA", jwk.kty());
        assertEquals("0vx7agoebGcQ", jwk.n());
        assertEquals("AQAB", jwk.e());
    }

    @Test
    @DisplayName("JWK RSA sem 'n' ou 'e' falha")
    void rsaIncompletoFalha() {
        assertThrows(JwtException.class, () -> Jwk.rsa().exponent("AQAB").build());
        assertThrows(JwtException.class, () -> Jwk.rsa().modulus("0vx7").build());
    }

    @Test
    @DisplayName("JWK EC sem crv/x/y falha")
    void ecIncompletoFalha() {
        assertThrows(JwtException.class, () -> Jwk.ec().build());
    }

    @Test
    @DisplayName("JWK exige kty")
    void exigeKty() {
        assertThrows(JwtException.class, () -> Jwk.builder().build());
    }

    @Test
    @DisplayName("Serialização preserva campos conhecidos")
    void serializacao() {
        Jwk jwk = Jwk.rsa()
                .kid("key-01")
                .use("sig")
                .alg("RS256")
                .modulus("0vx7agoebGcQ")
                .exponent("AQAB")
                .build();

        String json = jwk.toJson();
        assertTrue(json.contains("\"kty\":\"RSA\""));
        assertTrue(json.contains("\"kid\":\"key-01\""));
        assertTrue(json.contains("\"use\":\"sig\""));
        assertTrue(json.contains("\"alg\":\"RS256\""));
        assertTrue(json.contains("\"n\":\"0vx7agoebGcQ\""));
        assertTrue(json.contains("\"e\":\"AQAB\""));
    }

    @Test
    @DisplayName("Round-trip JSON → objeto → JSON")
    void roundTrip() {
        Jwk original = Jwk.rsa()
                .kid("key-01")
                .modulus("n-value")
                .exponent("e-value")
                .build();

        Jwk parsed = Jwk.fromJson(original.toJson());

        assertEquals(original.kty(), parsed.kty());
        assertEquals(original.kid(), parsed.kid());
        assertEquals(original.n(),   parsed.n());
        assertEquals(original.e(),   parsed.e());
    }

    @Test
    @DisplayName("Campos extras são preservados no round-trip")
    void camposExtras() {
        String json = """
                {
                  "kty": "RSA",
                  "kid": "key-01",
                  "n": "n-value",
                  "e": "e-value",
                  "x5c": ["certificado-base64"],
                  "custom": "campo-exotico"
                }
                """;

        Jwk jwk = Jwk.fromJson(json);
        assertEquals("campo-exotico", jwk.extra().get("custom"));
        assertNotNull(jwk.extra().get("x5c"));

        String serialized = jwk.toJson();
        assertTrue(serialized.contains("custom"));
        assertTrue(serialized.contains("x5c"));
    }
}