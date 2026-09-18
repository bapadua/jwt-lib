package com.github.bapadua.labs.jwt;

import com.github.bapadua.labs.jwt.internal.HmacSigner;
import com.github.bapadua.labs.jwt.internal.RsaSigner;
import com.github.bapadua.labs.jwt.internal.Signer;
import com.github.bapadua.labs.jwt.internal.Verifier;

import java.security.Key;

/**
 * Algoritmos suportados pela lib.
 *
 * <p><b>O que este enum é:</b> uma fachada. Cada valor identifica um nome
 * de algoritmo (usado no header JWT) e delega a assinatura/verificação
 * para uma implementação interna ({@link Signer}/{@link Verifier}).
 *
 * <p><b>O que este enum NÃO é:</b> onde a criptografia vive. Isso ficou
 * em {@code internal/HmacSigner}, {@code internal/RsaSigner}, etc. A
 * separação existe para que:
 * <ul>
 *   <li>O enum continue pequeno e legível.</li>
 *   <li>Cada família de algoritmo tenha seu próprio arquivo.</li>
 *   <li>Novos algoritmos sejam uma linha no enum + uma classe nova.</li>
 * </ul>
 *
 * <p><b>Pinning via enum</b>: como enums são fechados por natureza,
 * não é possível registrar algoritmos em runtime. Isso é uma
 * <b>feature de segurança</b>, não uma limitação.
 */
public enum Algorithm {

    HS256(HmacSigner.hs256()),
    HS384(HmacSigner.hs384()),
    HS512(HmacSigner.hs512()),

    RS256(RsaSigner.rs256()),
    RS384(RsaSigner.rs384()),
    RS512(RsaSigner.rs512());

    // TODO: ECDSA (ES256, ES384, ES512)
    //  - Criar internal/EcSigner.java
    //  - Criar internal/EcdsaSignatures.java (conversão DER <-> raw R||S)
    //  - Expandir permits em Signer/Verifier
    //  - A pegadinha: JCA produz DER, RFC 7515 exige raw. Sem conversão,
    //    tokens são válidos internamente mas rejeitados por outras libs.
    //  - Detalhes na documentação interna da Etapa 11.4

    private final Signer signer;
    private final Verifier verifier;

    /**
     * Construtor genérico: aceita qualquer implementação que seja
     * simultaneamente {@link Signer} e {@link Verifier}. A interseção
     * de tipos ({@code &}) é validada em tempo de compilação.
     */
    private <T extends Signer & Verifier> Algorithm(T impl) {
        this.signer = impl;
        this.verifier = impl;
    }

    public String jwtName() {
        return name();
    }

    public byte[] sign(byte[] data, Key key) {
        return signer.sign(data, key);
    }

    public boolean verify(byte[] data, byte[] signature, Key key) {
        return verifier.verify(data, signature, key);
    }

    public static Algorithm fromJwtName(String jwtName) {
        for (Algorithm alg : values()) {
            if (alg.name().equals(jwtName)) {
                return alg;
            }
        }
        throw new JwtException("Algoritmo não suportado: " + jwtName);
    }
}