package com.github.bapadua.labs.jwt.internal;

import com.github.bapadua.labs.jwt.JwtException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.MessageDigest;

/**
 * Implementação HMAC (HS256, HS384, HS512).
 *
 * <p>Cada instância encapsula um único algoritmo. As três variantes são
 * expostas por fábricas estáticas ({@link #hs256()}, etc.) para evitar
 * duplicar código de inicialização.
 *
 * <p><b>Sobre a chave</b>: HMAC exige {@link SecretKey}. Se receber
 * {@code PrivateKey} ou {@code PublicKey}, lança {@link JwtException}
 * imediatamente — nunca tenta "adivinhar" o que o usuário quis dizer.
 * Isso é a <b>defesa contra algorithm confusion</b> na camada mais baixa.
 */
public final class HmacSigner implements Signer, Verifier {

    private final String jwtName;
    private final String macAlgorithm;

    private HmacSigner(String jwtName, String macAlgorithm) {
        this.jwtName = jwtName;
        this.macAlgorithm = macAlgorithm;
    }

    public static HmacSigner hs256() {
        return new HmacSigner("HS256", "HmacSHA256");
    }

    public static HmacSigner hs384() {
        return new HmacSigner("HS384", "HmacSHA384");
    }

    public static HmacSigner hs512() {
        return new HmacSigner("HS512", "HmacSHA512");
    }

    @Override
    public String jwtName() {
        return jwtName;
    }

    @Override
    public byte[] sign(byte[] data, Key key) {
        SecretKey secretKey = requireSecretKey(key);
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            mac.init(secretKey);   // SecretKey já carrega o nome do algoritmo
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new JwtException("Falha ao assinar com " + jwtName, e);
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] signature, Key key) {
        byte[] expected = sign(data, key);
        // Constant-time. Nunca use Arrays.equals aqui (timing attack).
        return MessageDigest.isEqual(expected, signature);
    }

    /**
     * Garante que a chave é uma {@link SecretKey}.
     *
     * <p>Fail-fast: preferimos lançar uma exceção clara agora do que
     * produzir um token inválido silenciosamente.
     */
    private SecretKey requireSecretKey(Key key) {
        if (key == null) {
            throw new JwtException("Chave nula para " + jwtName);
        }
        if (!(key instanceof SecretKey sk)) {
            throw new JwtException(
                    jwtName + " requer SecretKey, mas recebeu "
                            + key.getClass().getName()
                            + ". Para HMAC, use SecretKeySpec."
            );
        }
        return sk;
    }
}