package com.github.bapadua.labs.jwt;

import java.security.Key;
import java.util.Map;

/**
 * Resolve a chave de verificação a partir do header do JWT.
 *
 * <p>Retorna {@link Key} (não {@code byte[]}) porque:
 * <ul>
 *   <li>HMAC usa {@link javax.crypto.SecretKey}.</li>
 *   <li>RSA/EC usam {@link java.security.PublicKey}.</li>
 *   <li>A implementação escolhe o tipo adequado com base no {@code kid} e/ou {@code alg}.</li>
 * </ul>
 *
 * <p>O parser então passa essa {@code Key} para o {@code Verifier},
 * que valida se o tipo é compatível.
 */
@FunctionalInterface
public interface KeyProvider {
    Key getKey(Map<String, Object> header);
}