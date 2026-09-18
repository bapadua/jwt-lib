package com.github.bapadua.labs.jwt;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;

import static org.junit.jupiter.api.Assertions.*;

class AlgorithmTest {

    private static Key key = TestKeys.hmac("chave-secreta");


    @Test
    @DisplayName("HS256 produz assinatura de 32 bytes")
    void hs256TamanhoCorreto() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);

        byte[] signature = Algorithm.HS256.sign(data, key);

        assertEquals(32, signature.length);
    }

    @Test
    @DisplayName("HS384 produz assinatura de 48 bytes")
    void hs384TamanhoCorreto() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);

        assertEquals(48, Algorithm.HS384.sign(data, key).length);
    }

    @Test
    @DisplayName("HS512 produz assinatura de 64 bytes")
    void hs512TamanhoCorreto() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);

        assertEquals(64, Algorithm.HS512.sign(data, key).length);
    }

    @Test
    @DisplayName("Assinatura é determinística para mesma chave e mensagem")
    void determinismo() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);

        byte[] sig1 = Algorithm.HS256.sign(data, key);
        byte[] sig2 = Algorithm.HS256.sign(data, key);

        assertArrayEquals(sig1, sig2);
    }

    @Test
    @DisplayName("Assinatura muda se a mensagem mudar em um único byte")
    void avalanche() {
        byte[] data1 = "mensagem".getBytes(StandardCharsets.UTF_8);
        byte[] data2 = "mensagem!".getBytes(StandardCharsets.UTF_8); // um byte a mais

        byte[] sig1 = Algorithm.HS256.sign(data1, key);
        byte[] sig2 = Algorithm.HS256.sign(data2, key);

        assertFalse(java.util.Arrays.equals(sig1, sig2));
    }

    @Test
    @DisplayName("Assinatura muda se a chave mudar")
    void assinaturaDependeDaChave() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);

        byte[] sig1 = Algorithm.HS256.sign(data, TestKeys.hmac("chave-a"));
        byte[] sig2 = Algorithm.HS256.sign(data, TestKeys.hmac("chave-b"));

        assertFalse(java.util.Arrays.equals(sig1, sig2));
    }

    @Test
    @DisplayName("verify aceita assinatura correta")
    void verifyCorreta() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);
        byte[] signature = Algorithm.HS256.sign(data, key);

        assertTrue(Algorithm.HS256.verify(data, signature, key));
    }

    @Test
    @DisplayName("verify rejeita assinatura com um byte alterado")
    void verifyRejeitaAdulterada() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);
        byte[] signature = Algorithm.HS256.sign(data, key);

        // Adultera o último byte
        signature[signature.length - 1] ^= 0x01;

        assertFalse(Algorithm.HS256.verify(data, signature, key));
    }

    @Test
    @DisplayName("verify rejeita assinatura com chave errada")
    void verifyRejeitaChaveErrada() {
        byte[] data = "mensagem".getBytes(StandardCharsets.UTF_8);
        byte[] signature = Algorithm.HS256.sign(data, TestKeys.hmac("chave-certa"));

        assertFalse(Algorithm.HS256.verify(data, signature, TestKeys.hmac("chave-errada")));
    }

    @Test
    @DisplayName("fromJwtName reconhece algoritmos suportados")
    void fromJwtNameReconhece() {
        assertEquals(Algorithm.HS256, Algorithm.fromJwtName("HS256"));
        assertEquals(Algorithm.HS384, Algorithm.fromJwtName("HS384"));
        assertEquals(Algorithm.HS512, Algorithm.fromJwtName("HS512"));
        assertEquals(Algorithm.RS256, Algorithm.fromJwtName("RS256"));
        assertEquals(Algorithm.RS384, Algorithm.fromJwtName("RS384"));
        assertEquals(Algorithm.RS512, Algorithm.fromJwtName("RS512"));
    }

    @Test
    @DisplayName("fromJwtName rejeita algoritmos desconhecidos ou perigosos")
    void fromJwtNameRejeitaDesconhecido() {
        // "none" é previsto pela RFC 7515 mas NUNCA aceitamos — fail-closed
        assertThrows(JwtException.class, () -> Algorithm.fromJwtName("none"));

        // Algoritmos ainda não implementados (RS384/RS512 chegam na 11.3;
        // ES256+ na 11.4; PS256/EdDSA talvez nunca)
        assertThrows(JwtException.class, () -> Algorithm.fromJwtName("ES256"));
        assertThrows(JwtException.class, () -> Algorithm.fromJwtName("PS256"));
        assertThrows(JwtException.class, () -> Algorithm.fromJwtName("EdDSA"));

        // Nomes que nunca existirão
        assertThrows(JwtException.class, () -> Algorithm.fromJwtName(""));
        assertThrows(JwtException.class, () -> Algorithm.fromJwtName("FOO"));
        assertThrows(JwtException.class, () -> Algorithm.fromJwtName("hs256")); // case-sensitive
    }


}