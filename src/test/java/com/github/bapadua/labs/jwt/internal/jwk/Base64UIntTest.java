package com.github.bapadua.labs.jwt.internal.jwk;

import com.github.bapadua.labs.jwt.JwtException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class Base64UIntTest {

    @Test
    @DisplayName("Expoente público 65537 = 'AQAB' (vetor conhecido)")
    void expoentePadrao() {
        // 65537 é o expoente público de facto em RSA.
        // Em base64url: AQAB (do RFC 7517 e RFC 7515).
        BigInteger e = BigInteger.valueOf(65537);
        assertEquals("AQAB", Base64UInt.encode(e));
        assertEquals(e, Base64UInt.decode("AQAB"));
    }

    @Test
    @DisplayName("Valor 0 -> 'AA' (1 byte zero)")
    void zero() {
        assertEquals("AA", Base64UInt.encode(BigInteger.ZERO));
        assertEquals(BigInteger.ZERO, Base64UInt.decode("AA"));
    }

    @Test
    @DisplayName("Não emite 0x00 à esquerda mesmo com bit alto setado")
    void semZeroAEsquerda() {
        // Valor com bit mais significativo setado.
        // BigInteger.toByteArray() prefixa 0x00; nosso toBytes não.
        BigInteger valor = new BigInteger("FF", 16);   // 255

        byte[] bytes = Base64UInt.toBytes(valor);

        assertEquals(1, bytes.length, "255 deve ocupar 1 byte unsigned");
        assertEquals((byte) 0xFF, bytes[0]);
    }

    @Test
    @DisplayName("Valor grande com bit alto setado preserva unsigned")
    void valorGrandeComBitAlto() {
        // Um valor de 256 bytes com o bit mais alto setado.
        // Este é exatamente o caso do módulo RSA real.
        BigInteger n = BigInteger.ONE.shiftLeft(2047); // 2^2047

        byte[] bytes = Base64UInt.toBytes(n);

        // 2^2047 exige 256 bytes: primeiro byte = 0x80, resto 0x00.
        assertEquals(256, bytes.length);
        assertEquals((byte) 0x80, bytes[0]);

        // Round-trip
        BigInteger back = Base64UInt.toBigInteger(bytes);
        assertEquals(n, back);
    }

    @Test
    @DisplayName("Round-trip com valor arbitrário")
    void roundTrip() {
        BigInteger valor = new BigInteger(
                "1234567890123456789012345678901234567890"
        );
        assertEquals(valor, Base64UInt.decode(Base64UInt.encode(valor)));
    }

    @Test
    @DisplayName("Valor negativo é rejeitado")
    void negativoFalha() {
        assertThrows(JwtException.class, () -> Base64UInt.encode(BigInteger.valueOf(-1)));
        assertThrows(JwtException.class, () -> Base64UInt.toBytes(BigInteger.valueOf(-1)));
    }

    @Test
    @DisplayName("Bytes vazios são rejeitados")
    void bytesVaziosFalham() {
        assertThrows(JwtException.class, () -> Base64UInt.toBigInteger(new byte[0]));
    }

    @Test
    @DisplayName("String base64url vazia é rejeitada")
    void stringVaziaFalha() {
        assertThrows(JwtException.class, () -> Base64UInt.decode(""));
        assertThrows(JwtException.class, () -> Base64UInt.decode(null));
    }
}