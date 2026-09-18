package com.github.bapadua.labs.jwt.internal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class Base64UrlTest {

    @Test
    @DisplayName("Codifica string simples em Base64 URL-safe sem padding")
    void codificaStringSimples() {
        // RFC 7515, Apêndice A.1 — header do exemplo
        String header = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
        String esperado = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9";

        assertEquals(esperado, Base64Url.encode(header));
    }

    @Test
    @DisplayName("Decodifica de volta o Base64 URL-safe")
    void decodificaStringSimples() {
        String encoded = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9";
        String esperado = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";

        assertEquals(esperado, Base64Url.decodeToString(encoded));
    }

    @Test
    @DisplayName("Não emite padding '=' no final")
    void semPadding() {
        // 3 bytes -> 4 chars Base64, seria "TWFu" sem padding
        // 2 bytes -> "TWE=" com padding, "TWE" sem
        // 1 byte  -> "TQ=="  com padding, "TQ" sem
        assertEquals("TWFu", Base64Url.encode("Man".getBytes(StandardCharsets.UTF_8)));
        assertEquals("TWE",  Base64Url.encode("Ma".getBytes(StandardCharsets.UTF_8)));
        assertEquals("TQ",   Base64Url.encode("M".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    @DisplayName("Usa alfabeto URL-safe (- e _) em vez de + e /")
    void usaAlfabetoUrlSafe() {
        // Encontrar bytes cujo Base64 padrão contenha '+' e '/'
        // 0xFB, 0xEF, 0xBE no Base64 padrão vira "++++"? Não. Vamos achar um caso concreto:
        // 0x3E, 0x3F, 0xBF -> Base64 padrão: "Pj+..." ; URL-safe: "Pj-..."
        byte[] bytes = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };

        String urlSafe = Base64Url.encode(bytes);
        String padrao  = Base64.getEncoder().withoutPadding().encodeToString(bytes);

        // No Base64 padrão, 0xFF 0xFF 0xFF vira "////"
        // No URL-safe, vira "____"
        assertEquals("____", urlSafe);
        assertEquals("////", padrao);
        assertNotEquals(urlSafe, padrao);
    }

    @Test
    @DisplayName("Aceita Base64 com padding na entrada (tolerância do decoder JDK)")
    void aceitaPaddingNaEntrada() {
        // Mesmo conteúdo, um com padding e outro sem
        String comPadding  = "TWE=";
        String semPadding  = "TWE";

        assertEquals("Ma", Base64Url.decodeToString(comPadding));
        assertEquals("Ma", Base64Url.decodeToString(semPadding));
    }

    @Test
    @DisplayName("UTF-8 é usado, não o charset padrão da plataforma")
    void usaUtf8() {
        String texto = "José"; // acento testa bem o UTF-8
        String encoded = Base64Url.encode(texto);
        String decoded = Base64Url.decodeToString(encoded);

        assertEquals(texto, decoded);
    }

}