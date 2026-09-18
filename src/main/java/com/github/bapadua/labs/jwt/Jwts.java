package com.github.bapadua.labs.jwt;

/**
 * Facade (ponto de entrada) da biblioteca JWT.
 *
 * <p>Esse padrão — uma classe com métodos estáticos que servem como
 * "porta de entrada" — é comum em libs Java. Exemplos:
 * <ul>
 *   <li>{@code Jwts} (jjwt)</li>
 *   <li>{@code Files} (java.nio)</li>
 *   <li>{@code Collections} (java.util)</li>
 * </ul>
 *
 * <p>A vantagem é que o usuário tem <b>um único ponto</b> para descobrir
 * a API. Ao invés de procurar por {@code JwtBuilder}, {@code JwtParser},
 * etc., ele começa por aqui e segue o fluxo.
 */
public class Jwts {

    private Jwts() {
        // Classe utilitária: não instanciável.
    }

    /**
     * Cria um novo builder para gerar um JWT.
     *
     * <p>Exemplo:
     * <pre>{@code
     * String token = Jwts.builder()
     *         .alg(Algorithm.HS256)
     *         .signWith("segredo")
     *         .subject("user-1")
     *         .expiresInSeconds(3600)
     *         .compact();
     * }</pre>
     */
    public static JwtBuilder builder() {
        return new JwtBuilder();
    }

    public static JwtParser parser() {
        return new JwtParser();
    }

}
