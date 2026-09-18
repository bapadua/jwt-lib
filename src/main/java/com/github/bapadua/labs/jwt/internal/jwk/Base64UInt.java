package com.github.bapadua.labs.jwt.internal.jwk;

import com.github.bapadua.labs.jwt.JwtException;
import com.github.bapadua.labs.jwt.internal.Base64Url;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Codificação de inteiros no formato <b>Base64urlUInt</b> (RFC 7518, seção 2).
 *
 * <p>A RFC define o formato como:
 * <blockquote>
 *   "The octet sequence MUST utilize the minimum number of octets needed
 *    to represent the value. Leading zero octets MUST NOT be used."
 * </blockquote>
 *
 * <p>Ou seja: <b>unsigned big-endian, com comprimento mínimo, sem zeros à
 * esquerda</b>. É o formato usado em todos os valores numéricos de JWK
 * ({@code n}, {@code e}, {@code d}, {@code p}, {@code q}, ...).
 *
 * <p><b>Por que não usar {@link BigInteger#toByteArray()} direto?</b>
 * Porque ele retorna <b>complemento de dois signed</b>. Se o bit mais
 * significativo do valor estiver setado, o array gerado começa com
 * {@code 0x00} — e a RFC 7518 proíbe isso. O resultado seria um JWK
 * inválido para outras libs.
 *
 * <p>Esse é um bug silencioso: sua lib aceita seus próprios JWKs, mas
 * jwt.io, Nimbus, Auth0 e qualquer outro consumer rejeitam. É por isso
 * que essa classe existe separada, com testes dedicados.
 */
public final class Base64UInt {

    private Base64UInt() {}

    /**
     * Converte um {@link BigInteger} positivo para bytes unsigned
     * big-endian com comprimento mínimo (sem zeros à esquerda).
     *
     * @throws JwtException se o valor for negativo (não deveria acontecer em JWK)
     */
    public static byte[] toBytes(BigInteger value) {
        if (value == null) {
            throw new JwtException("Valor nulo em Base64urlUInt");
        }
        if (value.signum() < 0) {
            throw new JwtException("Base64urlUInt não admite valores negativos");
        }
        if (value.signum() == 0) {
            // "0" em base64url com comprimento mínimo = 1 byte zero.
            // Não deveria acontecer em RSA real, mas tratamos para robustez.
            return new byte[] { 0x00 };
        }

        byte[] bytes = value.toByteArray();

        // toByteArray pode prefixar 0x00 como marcador de "positivo".
        // Removemos apenas UM 0x00 (nunca mais que um deveria existir).
        if (bytes.length > 1 && bytes[0] == 0x00) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    /**
     * Converte bytes unsigned big-endian de volta para BigInteger positivo.
     *
     * <p>O {@code 1} no construtor de {@link BigInteger} é <b>essencial</b>:
     * indica "interprete como positivo (unsigned)". Sem ele, um valor com
     * o bit mais alto setado seria lido como negativo, e o JWK
     * reconstruído seria uma chave completamente diferente.
     */
    public static BigInteger toBigInteger(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            throw new JwtException("Bytes vazios em Base64urlUInt");
        }
        return new BigInteger(1, bytes);
    }

    /**
     * Codifica um {@link BigInteger} positivo como string base64url
     * (formato do campo em JWK).
     */
    public static String encode(BigInteger value) {
        return Base64Url.encode(toBytes(value));
    }

    /**
     * Decodifica uma string base64url (campo de JWK) de volta para
     * {@link BigInteger} positivo.
     */
    public static BigInteger decode(String base64url) {
        if (base64url == null || base64url.isBlank()) {
            throw new JwtException("Valor base64url vazio");
        }
        return toBigInteger(Base64Url.decode(base64url));
    }
}