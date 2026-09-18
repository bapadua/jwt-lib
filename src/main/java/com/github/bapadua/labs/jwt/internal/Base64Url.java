package com.github.bapadua.labs.jwt.internal;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Encoding/decoding Base64 URL-safe SEM padding, conforme RFC 7515, seção 2.
 *
 * <p>Esta classe encapsula as decisões de encoding que o JWT exige:
 * <ul>
 *   <li>Alfabeto URL-safe ({@code -} e {@code _} no lugar de {@code +} e {@code /})</li>
 *   <li>Sem padding ({@code =} removido do final)</li>
 *   <li>Sempre UTF-8 na conversão texto ↔ bytes</li>
 * </ul>
 *
 * <p><b>Por que não implementar na mão?</b> A JVM já traz uma implementação
 * altamente otimizada em {@link java.util.Base64}. Reimplementar seria mais
 * lento, mais propenso a bug, e reinventaria uma roda já auditada.
 *
 * <p>Esta é uma classe utilitária pura: sem estado, sem instanciação.
 */
public final class Base64Url {

    /**
     * Encoder thread-safe. Construído uma única vez e reutilizado.
     *
     * <p>O {@link Base64.Encoder} retornado por {@code getUrlEncoder()}
     * é thread-safe por contrato da JDK — podemos guardá-lo num campo
     * {@code static final} sem nos preocuparmos com concorrência.
     * Isso evita realocar o encoder a cada chamada, o que importaria
     * em cenários de alta performance (ex.: validação de JWT em cada
     * request HTTP).
     */
    private static final Base64.Encoder ENCODER =
            Base64.getUrlEncoder().withoutPadding();

    private static final Base64.Decoder DECODER =
            Base64.getUrlDecoder();

    private Base64Url() {
    }


    /**
     * Codifica bytes em Base64 URL-safe sem padding.
     *
     * @param data bytes a codificar (nunca {@code null})
     * @return string Base64 URL-safe sem padding
     */
    public static String encode(byte[] data) {
        return ENCODER.encodeToString(data);
    }

    /**
     * Codifica texto em Base64 URL-safe sem padding, usando UTF-8.
     *
     * @param data texto a codificar (nunca {@code null})
     * @return string Base64 URL-safe sem padding
     */
    public static String encode(String data) {
        return ENCODER.encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decodifica Base64 URL-safe (sem padding) em bytes.
     *
     * @param data string Base64 URL-safe (nunca {@code null})
     * @return bytes decodificados
     * @throws IllegalArgumentException se a entrada não for Base64 URL-safe válido
     */
    public static byte[] decode(String data) {
        return DECODER.decode(data);
    }

    /**
     * Decodifica Base64 URL-safe em texto, usando UTF-8.
     *
     * @param data string Base64 URL-safe (nunca {@code null})
     * @return texto decodificado
     * @throws IllegalArgumentException se a entrada não for Base64 URL-safe válido
     */
    public static String decodeToString(String data) {
        return new String(DECODER.decode(data), StandardCharsets.UTF_8);
    }
}
