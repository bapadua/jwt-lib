package com.github.bapadua.labs.jwt.internal;

import java.security.Key;

/**
 * Contrato interno para algoritmos que <b>ver</b>ificam JWTs.
 *
 * <p>Deliberadamente separado de {@link Signer}, mesmo que a maioria das
 * implementações concretas seja a mesma classe. Motivo: <b>Interface
 * Segregation Principle</b>. Um resource server que só verifica tokens
 * depende apenas de {@code Verifier}. Uma ferramenta de emissão depende
 * apenas de {@code Signer}. Quando as interfaces são separadas, cada lado
 * declara apenas o que precisa.
 *
 * <p>O {@code permits} acompanha o de {@link Signer} — cada algoritmo deve
 * saber assinar <b>e</b> verificar (exceto casos exóticos que não temos hoje).
 */
public sealed interface Verifier permits HmacSigner, RsaSigner {

    String jwtName();

    /**
     * Verifica se a assinatura é válida.
     *
     * @param data      bytes originais (o "signing input")
     * @param signature assinatura recebida, já decodificada de Base64URL
     * @param key       chave de verificação. {@link javax.crypto.SecretKey}
     *                  para HMAC, {@link java.security.PublicKey} para RSA/EC.
     * @return {@code true} se a assinatura for válida
     */
    boolean verify(byte[] data, byte[] signature, Key key);
}