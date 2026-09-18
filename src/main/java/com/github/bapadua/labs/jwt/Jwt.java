package com.github.bapadua.labs.jwt;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Representação imutável de um JWT já processado.
 *
 * <p>Um {@code Jwt} é o resultado de {@link JwtParser#parse(String)}. Ele expõe:
 * <ul>
 *   <li>O header decodificado ({@link #getHeader()}).</li>
 *   <li>Os claims (payload) decodificados ({@link #getClaims()}).</li>
 *   <li>A assinatura crua em bytes ({@link #getSignature()}).</li>
 *   <li>O token original em formato compacto ({@link #getRawToken()}).</li>
 * </ul>
 *
 * <p><b>Imutabilidade:</b> todos os mapas retornados são <i>unmodifiable views</i>
 * sobre os mapas internos. Tentar modificá-los lança {@link UnsupportedOperationException}.
 * Isso evita que o usuário mute o token depois de validado — o que seria uma
 * fonte sutil de bugs (ex.: validar, então mutar, então usar achando que ainda é válido).
 *
 * <p><b>Por que não expor métodos tipados diretos ({@code getSubject()}, etc.)?</b>
 * Nós expomos, mas eles são <i>helpers</i> em cima de {@link #getStringClaim(String)}
 * e {@link #getLongClaim(String)}. O coração continua sendo o mapa cru, para
 * suportar claims customizados sem precisar de classes específicas.
 */
public class Jwt {
    private final Map<String, Object> header;
    private final Map<String, Object> claims;
    private final byte[] signature;
    private final String rawToken;

    /**
     * Construtor com visibilidade de pacote: só {@link JwtParser} instancia.
     */
    Jwt(Map<String, Object> header,
        Map<String, Object> claims,
        byte[] signature,
        String rawToken) {
        // Envolvemos em unmodifiable para tornar a imutabilidade efetiva.
        this.header = Collections.unmodifiableMap(header);
        this.claims = Collections.unmodifiableMap(claims);

        // Defensive copy da assinatura (byte[] é mutável).
        this.signature = signature.clone();

        this.rawToken = rawToken;
    }

    /** Retorna o {@code typ} do header, ou {@code null} se ausente. */
    public String getType() {
        Object t = header.get("typ");
        return (t instanceof String s) ? s : null;
    }

    /** Retorna o {@code kid} do header, ou {@code null} se ausente. */
    public String getKeyId() {
        Object kid = header.get("kid");
        return (kid instanceof String s) ? s : null;
    }

    public Map<String, Object> getHeader() {
        return header;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    public byte[] getSignature() {
        // Defensive copy na saída também, para o usuário não alterar o interno.
        return signature.clone();
    }

    public String getRawToken() {
        return rawToken;
    }

    /**
     * Retorna um claim como {@code Object}, sem conversão.
     */
    public Object getClaim(String name) {
        return claims.get(name);
    }

    /**
     * Retorna um claim como {@code String}.
     *
     * @return o valor, ou {@code null} se o claim não existir
     * @throws JwtException se o valor existir mas não for uma {@code String}
     */
    public String getStringClaim(String name) {
        Object v = claims.get(name);
        if (v == null) return null;
        if (v instanceof String s) return s;
        throw new JwtException("Claim '" + name + "' não é uma String: " + v.getClass());
    }

    /**
     * Retorna um claim como {@code Long}, normalizando qualquer {@link Number}.
     *
     * <p><b>Por que normalizar?</b> Conforme discutimos, o Jackson pode
     * desserializar inteiros como {@code Integer} ou {@code Long}, dependendo
     * do valor. Também pode vir {@code BigInteger} para valores gigantes.
     * Ao expor {@code Long}, escondemos essa complexidade do usuário.
     *
     * @return o valor como {@code Long}, ou {@code null} se ausente
     * @throws JwtException se o valor não for numérico
     */
    public Long getLongClaim(String name) {
        Object v = claims.get(name);
        if (v == null) return null;
        if (v instanceof Number n) return n.longValue();

        // Alguns emissores colocam timestamps como string numérica.
        // Aceitamos isso por tolerância a implementações "criativas".
        if (v instanceof String s) {
            try {
                return Long.parseLong(s);
            } catch (NumberFormatException e) {
                throw new JwtException("Claim '" + name + "' não é numérico: " + s, e);
            }
        }

        throw new JwtException("Claim '" + name + "' não é numérico: " + v.getClass());
    }

    /**
     * Retorna um claim como {@code Boolean}.
     */
    public Boolean getBooleanClaim(String name) {
        Object v = claims.get(name);
        if (v == null) return null;
        if (v instanceof Boolean b) return b;
        throw new JwtException("Claim '" + name + "' não é boolean: " + v.getClass());
    }

    // ------------------------------------------------------------------
    // Helpers de claims registrados (RFC 7519, seção 4.1)
    // ------------------------------------------------------------------

    /** Claim {@code sub} (subject). */
    public String getSubject() {
        return getStringClaim("sub");
    }

    /** Claim {@code iss} (issuer). */
    public String getIssuer() {
        return getStringClaim("iss");
    }

    /** Claim {@code aud} (audience). */
    /**
     * Retorna todos os valores de {@code aud} como lista, normalizando
     * string única em lista de um elemento.
     *
     * <p>Conforme RFC 7519, seção 4.1.3, {@code aud} pode ser:
     * <ul>
     *   <li>Uma string única: {@code "aud": "meu-servico"}</li>
     *   <li>Um array de strings: {@code "aud": ["meu-servico", "outro"]}</li>
     * </ul>
     *
     * <p>Retornamos sempre uma lista para simplificar a vida do chamador.
     */
    public List<String> getAudiences() {
        Object aud = claims.get("aud");
        if (aud == null) return List.of();
        if (aud instanceof String s) return List.of(s);
        if (aud instanceof List<?> list) {
            return list.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .toList();
        }
        throw new JwtException("Claim 'aud' com tipo inválido: " + aud.getClass());
    }

    /**
     * Claim {@code jti} (JWT ID).
     *
     * <p><b>Não fazemos revogação.</b> A lib não tem estado, não consulta
     * blacklists, não sabe o que foi revogado. O chamador é responsável por
     * manter sua própria estrutura (Redis, banco, memória) e checar
     * {@code jwt.getId()} contra ela, se quiser revogação.
     *
     * <p>Isso é uma decisão de design: manter a lib <b>stateless</b> é
     * fundamental para que ela seja thread-safe, escalável horizontalmente,
     * e componível. Revogação é responsabilidade do servidor de identidade.
     */
    public String getId() {
        return getStringClaim("jti");
    }

    /** Claim {@code exp} (expiration) em segundos desde epoch. */
    public Long getExpiration() {
        return getLongClaim("exp");
    }

    /** Claim {@code iat} (issued at) em segundos desde epoch. */
    public Long getIssuedAt() {
        return getLongClaim("iat");
    }

    /** Claim {@code nbf} (not before) em segundos desde epoch. */
    public Long getNotBefore() {
        return getLongClaim("nbf");
    }

    /**
     * Verifica se o token está expirado, com tolerância opcional de clock skew.
     *
     * @param clockSkewSeconds margem de tolerância (0 = sem tolerância)
     */
    public boolean isExpired(long clockSkewSeconds) {
        Long exp = getExpiration();
        if (exp == null) return false;
        long now = System.currentTimeMillis() / 1000L;
        return now >= (exp + clockSkewSeconds);
    }

    public boolean isExpired() {
        return isExpired(0);
    }

    /**
     * Verifica se o token já é válido ({@code nbf} no passado).
     */
    public boolean isNotYetValid(long clockSkewSeconds) {
        Long nbf = getNotBefore();
        if (nbf == null) return false;
        long now = System.currentTimeMillis() / 1000L;
        return now < (nbf - clockSkewSeconds);
    }

    @Override
    public String toString() {
        return rawToken;
    }

}
