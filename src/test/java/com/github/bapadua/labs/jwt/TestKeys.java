package com.github.bapadua.labs.jwt;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Utilitário de teste para construir chaves de forma legível.
 *
 * <p>Vive em {@code src/test} — não é parte da API pública e não vai
 * para o JAR final. Existe apenas para reduzir ruído nos testes.
 */
public final class TestKeys {
    private TestKeys() {}

    private static KeyPair cachedRsa;
    public static synchronized KeyPair rsa() {
        if (cachedRsa == null) {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                cachedRsa = kpg.generateKeyPair();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return cachedRsa;
    }

    /**
     * Cria uma {@link SecretKey} HMAC-SHA256 a partir de uma string UTF-8.
     */
    public static SecretKey hmac(String secret) {
        return new SecretKeySpec(
                secret.getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
        );
    }
}
