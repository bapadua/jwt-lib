package com.github.bapadua.labs.jwt.internal.jwk;

/**
 * Abstração para "obter o JWKS atual".
 *
 * <p>Existe para permitir testar o {@link RemoteJwksKeyProvider} sem
 * rede, e para permitir fontes alternativas no futuro (banco, S3, cache
 * local, etc.).
 *
 * <p>A implementação padrão é HTTP, mas a interface é agnóstica.
 */
@FunctionalInterface
public interface JwksFetcher {

    /**
     * Retorna o JWKS atual.
     *
     * <p>Não deve retornar {@code null}. Em caso de falha, deve lançar
     * {@link com.github.bapadua.labs.jwt.JwtException} ou outra
     * {@link RuntimeException} descrevendo o problema.
     *
     * @return o JWKS atual (nunca {@code null})
     */
    Jwks fetch();
}