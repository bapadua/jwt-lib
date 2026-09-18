package com.github.bapadua.labs.jwt.internal;

import java.security.Key;

/**
 * Contrato interno para algoritmos que <b>ass</b>inam JWTs.
 *
 * <p><b>Por que existe?</b> Antes, a lógica de assinatura vivia dentro do
 * enum {@code Algorithm}. Isso misturava "identificação" (o nome que vai
 * no header, ex: "HS256") com "comportamento" (como assinar). Separar
 * permite que cada família de algoritmo (HMAC, RSA, EC) tenha sua própria
 * classe, sem inflar o enum.
 *
 * <p><b>Por que é sealed?</b> Criptografia é uma área onde <b>não queremos</b>
 * que terceiros injetem algoritmos via SPI, classpath ou reflection. A lista
 * fechada de implementações é uma decisão defensiva: o compilador garante
 * que ninguém fora deste pacote pode implementar {@code Signer}.
 *
 * <p>Ao adicionar um novo algoritmo (ex: PS256, EdDSA), expandimos o
 * {@code permits} — isso é intencional: mudanças na superfície criptográfica
 * devem ser explícitas e revisáveis.
 */
public sealed interface Signer permits HmacSigner, RsaSigner {

    /**
     * Nome do algoritmo como aparece no header JWT (ex: "HS256").
     */
    String jwtName();

    /**
     * Assina os bytes informados.
     *
     * @param data bytes a assinar (o "signing input" da RFC 7515)
     * @param key  chave de assinatura. O tipo concreto depende do algoritmo:
     *             {@link javax.crypto.SecretKey} para HMAC,
     *             {@link java.security.PrivateKey} para RSA/EC.
     * @return bytes da assinatura
     * @throws com.github.bapadua.labs.jwt.JwtException se o tipo de chave
     *         não for compatível com o algoritmo
     */
    byte[] sign(byte[] data, Key key);
}