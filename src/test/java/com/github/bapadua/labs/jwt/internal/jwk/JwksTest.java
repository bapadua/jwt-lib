package com.github.bapadua.labs.jwt.internal.jwk;

import com.github.bapadua.labs.jwt.JwtException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwksTest {

    @Test
    @DisplayName("Cria JWKS com múltiplas chaves")
    void multiplasChaves() {
        Jwks jwks = Jwks.of(
                Jwk.rsa().kid("key-1").modulus("n1").exponent("e1").build(),
                Jwk.rsa().kid("key-2").modulus("n2").exponent("e2").build()
        );

        assertEquals(2, jwks.keys().size());
    }

    @Test
    @DisplayName("findByKid retorna a chave correta")
    void findByKid() {
        Jwks jwks = Jwks.of(
                Jwk.rsa().kid("key-1").modulus("n1").exponent("e1").build(),
                Jwk.rsa().kid("key-2").modulus("n2").exponent("e2").build()
        );

        Optional<Jwk> k2 = jwks.findByKid("key-2");
        assertTrue(k2.isPresent());
        assertEquals("n2", k2.get().n());
    }

    @Test
    @DisplayName("findByKid retorna empty para kid inexistente")
    void findByKidInexistente() {
        Jwks jwks = Jwks.of(
                Jwk.rsa().kid("key-1").modulus("n1").exponent("e1").build()
        );

        assertTrue(jwks.findByKid("key-inexistente").isEmpty());
        assertTrue(jwks.findByKid(null).isEmpty());
    }

    @Test
    @DisplayName("Serialização produz formato {\"keys\":[...]}")
    void serializacao() {
        Jwks jwks = Jwks.of(
                Jwk.rsa().kid("key-1").modulus("n1").exponent("e1").build()
        );

        String json = jwks.toJson();
        assertTrue(json.contains("\"keys\""));
        assertTrue(json.contains("\"kid\":\"key-1\""));
    }

    @Test
    @DisplayName("Round-trip JWKS")
    void roundTrip() {
        Jwks original = Jwks.of(
                Jwk.rsa().kid("key-1").modulus("n1").exponent("e1").build(),
                Jwk.rsa().kid("key-2").modulus("n2").exponent("e2").build()
        );

        Jwks parsed = Jwks.fromJson(original.toJson());

        assertEquals(2, parsed.keys().size());
        assertEquals("n1", parsed.findByKid("key-1").orElseThrow().n());
        assertEquals("n2", parsed.findByKid("key-2").orElseThrow().n());
    }

    @Test
    @DisplayName("JWKS sem 'keys' falha")
    void semKeysFalha() {
        assertThrows(JwtException.class, () -> Jwks.fromJson("{\"other\":[]}"));
    }
}