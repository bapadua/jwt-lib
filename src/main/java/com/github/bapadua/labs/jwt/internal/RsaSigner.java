package com.github.bapadua.labs.jwt.internal;

import com.github.bapadua.labs.jwt.JwtException;

import java.security.*;

/**
 * Implementação RSA (RS256, RS384, RS512).
 *
 * <p>Usa {@link java.security.Signature} da JCA com os algoritmos
 * {@code "SHA256withRSA"}, {@code "SHA384withRSA"} e {@code "SHA512withRSA"}.
 *
 * <p><b>Diferença fundamental em relação a HMAC:</b>
 * <ul>
 *   <li><b>Assinatura</b> usa {@link PrivateKey}.</li>
 *   <li><b>Verificação</b> usa {@link PublicKey}.</li>
 * </ul>
 * Ou seja, <b>as chaves são diferentes</b>. Isso permite que o emissor
 * (que tem a privada) e o verificador (que só tem a pública) operem sem
 * compartilhar segredo — o motivo de RSA ser preferido em OIDC.
 *
 * <p><b>Sobre thread-safety:</b> criamos uma nova instância de
 * {@link Signature} por chamada. {@code Signature} mantém estado interno
 * (mensagem acumulada), então não é thread-safe. O custo de instanciação
 * é desprezível em comparação ao cálculo RSA em si.
 *
 * <p><b>Sobre timing attacks:</b> o {@code Signature} da JCA já faz a
 * verificação de forma constant-time nas implementações modernas.
 * Não precisamos de {@link MessageDigest#isEqual} aqui — essa proteção
 * é específica para comparações manuais de HMAC.
 */
public final class RsaSigner implements Signer, Verifier {

    private final String jwtName;
    private final String javaAlgorithm;

    private RsaSigner(String jwtName, String javaAlgorithm) {
        this.jwtName = jwtName;
        this.javaAlgorithm = javaAlgorithm;
    }

    public static RsaSigner rs256() {
        return new RsaSigner("RS256", "SHA256withRSA");
    }

    public static RsaSigner rs384() {
        return new RsaSigner("RS384", "SHA384withRSA");
    }

    public static RsaSigner rs512() {
        return new RsaSigner("RS512", "SHA512withRSA");
    }

    @Override
    public String jwtName() {
        return jwtName;
    }

    @Override
    public byte[] sign(byte[] data, Key key) {
        PrivateKey privateKey = requirePrivateKey(key);
        try {
            Signature signature = Signature.getInstance(javaAlgorithm);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new JwtException("Falha ao assinar com " + jwtName, e);
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] signatureBytes, Key key) {
        PublicKey publicKey = requirePublicKey(key);
        try {
            Signature signature = Signature.getInstance(javaAlgorithm);
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            // Assinatura malformada também cai aqui. Retornamos false
            // em vez de propagar a exceção, porque "assinatura inválida"
            // é um resultado legítimo — não um erro do nosso código.
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Validação de tipo de chave (fail-fast)
    // ------------------------------------------------------------------

    private PrivateKey requirePrivateKey(Key key) {
        if (key == null) {
            throw new JwtException("Chave nula para " + jwtName);
        }
        if (!(key instanceof PrivateKey pk)) {
            throw new JwtException(
                    jwtName + " requer PrivateKey, mas recebeu "
                            + key.getClass().getName()
                            + ". Para verificar, use verify(...) com PublicKey."
            );
        }
        return pk;
    }

    private PublicKey requirePublicKey(Key key) {
        if (key == null) {
            throw new JwtException("Chave nula para " + jwtName);
        }
        if (!(key instanceof PublicKey pk)) {
            throw new JwtException(
                    jwtName + " requer PublicKey, mas recebeu "
                            + key.getClass().getName()
                            + ". Para assinar, use sign(...) com PrivateKey."
            );
        }
        return pk;
    }
}