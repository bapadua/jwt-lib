package com.github.bapadua.labs.jwt.internal.jwk;

import com.github.bapadua.labs.jwt.JwtException;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Conversão bidirecional entre {@link RSAPublicKey}/{@link RSAPrivateKey}
 * do {@code java.security} e {@link Jwk} (RFC 7517).
 *
 * <p>Usado por dois lados:
 * <ul>
 *   <li><b>Servidor OIDC</b>: converte suas chaves em JWK para publicar
 *       o JWKS e para persistir chaves privadas com segurança.</li>
 *   <li><b>Cliente</b>: converte JWKs do JWKS remoto em
 *       {@link RSAPublicKey} para verificar tokens.</li>
 * </ul>
 *
 * <p><b>Pegadinha tratada:</b> todos os valores numéricos passam por
 * {@link Base64UInt}, que garante o formato correto da RFC 7518
 * (unsigned big-endian, sem zeros à esquerda). Sem isso, JWKs gerados
 * aqui seriam rejeitados por outras libs.
 */
public final class JwkRsaConverter {

    private JwkRsaConverter() {}

    // ------------------------------------------------------------------
    // java.security.Key -> Jwk
    // ------------------------------------------------------------------

    /**
     * Converte uma chave pública RSA em JWK.
     *
     * @param key chave pública RSA
     * @param kid identificador da chave (vai no JWK)
     * @param use uso pretendido ("sig" para assinatura)
     * @param alg algoritmo (ex: "RS256")
     */
    public static Jwk toJwk(RSAPublicKey key, String kid, String use, String alg) {
        return Jwk.rsa()
                .kid(kid)
                .use(use)
                .alg(alg)
                .modulus(Base64UInt.encode(key.getModulus()))
                .exponent(Base64UInt.encode(key.getPublicExponent()))
                .build();
    }

    /**
     * Converte uma chave privada RSA em JWK.
     *
     * <p><b>PERIGO:</b> o JWK resultante contém material secreto
     * (expoente privado, primos). Nunca logue, nunca serialize em texto
     * claro, nunca transmita por canal não seguro.
     *
     * <p>Requer que a chave seja do tipo {@link RSAPrivateCrtKey} — o
     * padrão em Java, mas não garantido por contrato. Chaves não-CRT
     * são raras e não suportadas aqui.
     */
    public static Jwk toJwk(RSAPrivateKey key, String kid, String use, String alg) {
        if (!(key instanceof RSAPrivateCrtKey crt)) {
            throw new JwtException(
                    "Apenas chaves RSA CRT são suportadas. Recebido: " + key.getClass()
            );
        }

        return Jwk.rsa()
                .kid(kid)
                .use(use)
                .alg(alg)
                // Par público (obrigatório em JWK privado também)
                .modulus(Base64UInt.encode(crt.getModulus()))
                .exponent(Base64UInt.encode(crt.getPublicExponent()))
                // Material privado
                .privateExponent(Base64UInt.encode(crt.getPrivateExponent()))
                .primeP(Base64UInt.encode(crt.getPrimeP()))
                .primeQ(Base64UInt.encode(crt.getPrimeQ()))
                .crtDp(Base64UInt.encode(crt.getPrimeExponentP()))
                .crtDq(Base64UInt.encode(crt.getPrimeExponentQ()))
                .crtQi(Base64UInt.encode(crt.getCrtCoefficient()))
                .build();
    }

    // ------------------------------------------------------------------
    // Jwk -> java.security.Key
    // ------------------------------------------------------------------

    /**
     * Reconstrói uma chave pública RSA a partir de um JWK.
     *
     * @throws JwtException se o JWK não for RSA ou faltarem campos
     */
    public static RSAPublicKey toPublicKey(Jwk jwk) {
        if (!"RSA".equals(jwk.kty())) {
            throw new JwtException("JWK não é RSA: kty=" + jwk.kty());
        }
        if (jwk.n() == null || jwk.e() == null) {
            throw new JwtException("JWK RSA sem 'n' ou 'e'");
        }

        BigInteger n = Base64UInt.decode(jwk.n());
        BigInteger e = Base64UInt.decode(jwk.e());

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) kf.generatePublic(new RSAPublicKeySpec(n, e));
        } catch (Exception ex) {
            throw new JwtException("Falha ao reconstruir chave pública RSA", ex);
        }
    }

    /**
     * Reconstrói uma chave privada RSA a partir de um JWK.
     *
     * @throws JwtException se o JWK não for RSA, não tiver campos privados,
     *         ou faltar algum dos componentes CRT
     */
    public static RSAPrivateKey toPrivateKey(Jwk jwk) {
        if (!"RSA".equals(jwk.kty())) {
            throw new JwtException("JWK não é RSA: kty=" + jwk.kty());
        }
        if (!jwk.isPrivate()) {
            throw new JwtException("JWK não contém material privado ('d' ausente)");
        }
        if (jwk.p() == null || jwk.q() == null || jwk.dp() == null
                || jwk.dq() == null || jwk.qi() == null) {
            throw new JwtException("JWK RSA privado incompleto (faltam primos/CRT)");
        }

        BigInteger n  = Base64UInt.decode(jwk.n());
        BigInteger e  = Base64UInt.decode(jwk.e());
        BigInteger d  = Base64UInt.decode(jwk.d());
        BigInteger p  = Base64UInt.decode(jwk.p());
        BigInteger q  = Base64UInt.decode(jwk.q());
        BigInteger dp = Base64UInt.decode(jwk.dp());
        BigInteger dq = Base64UInt.decode(jwk.dq());
        BigInteger qi = Base64UInt.decode(jwk.qi());

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi);
            return (RSAPrivateKey) kf.generatePrivate(spec);
        } catch (Exception ex) {
            throw new JwtException("Falha ao reconstruir chave privada RSA", ex);
        }
    }
}