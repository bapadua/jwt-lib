package com.github.bapadua.labs.jwt;

import com.github.bapadua.labs.jwt.internal.Base64Url;
import com.github.bapadua.labs.jwt.internal.Json;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Construtor fluente de JWTs.
 *
 * <p>Objetos desta classe são <b>mutáveis</b> e <b>não thread-safe</b>.
 * Uso típico:
 *
 * <pre>{@code
 * String token = Jwts.builder()
 *         .alg(Algorithm.HS256)
 *         .signWith(secretKey)
 *         .subject("user-1")
 *         .expiresInSeconds(3600)
 *         .claim("role", "admin")
 *         .compact();
 * }</pre>
 *
 * <p>Cada chamada de método retorna {@code this}, permitindo o encadeamento.
 * Isso é conhecido como <b>fluent API</b> — um padrão consagrado em libs
 * Java modernas (jjwt, OkHttp, Spring Security DSL).
 *
 * <p><b>Sobre a chave de assinatura:</b> a lib <b>não</b> aceita {@code String}
 * nem {@code byte[]} como chave, de propósito. Isso elimina uma classe de
 * bugs conhecida em bibliotecas JWT, onde strings são interpretadas como
 * chaves HMAC por engano. Para HMAC, construa explicitamente um
 * {@link javax.crypto.SecretKey} (via {@code SecretKeySpec}); para RSA/EC,
 * use {@link PrivateKey}.
 *
 * <p><b>Por que mutável e não imutável?</b> Construir um objeto imutável
 * encadeando cópias a cada chamada geraria N alocações, uma por método.
 * Como o builder é descartado após {@link #compact()}, mutabilidade local
 * é aceitável e mais performática. O importante é que o <b>token resultante</b>
 * é uma String imutável.
 */
public class JwtBuilder {

    /**
     * Header do JWT. Usamos {@link LinkedHashMap} para garantir ordem
     * determinística das chaves — crítico para que a assinatura seja
     * reproduzível.
     */
    private final Map<String, Object> header = new LinkedHashMap<>();

    /**
     * Payload (claims) do JWT. Mesma justificativa de ordem determinística.
     */
    private final Map<String, Object> claims = new LinkedHashMap<>();

    private Algorithm algorithm;
    private Key signingKey;

    /**
     * Construtor com visibilidade de pacote: só a classe {@link Jwts}
     * pode instanciar. Isso mantém a superfície pública controlada.
     * O usuário obtém um builder via {@code Jwts.builder()}.
     */
    JwtBuilder() {
        // Por padrão, todo JWT deve ter o campo "typ". É recomendado pela RFC 7519.
        header.put("typ", "JWT");
    }

    // ------------------------------------------------------------------
    // Configuração de algoritmo e chave
    // ------------------------------------------------------------------

    /**
     * Define o algoritmo de assinatura.
     * Deve ser chamado antes de {@link #compact()}.
     */
    public JwtBuilder alg(Algorithm algorithm) {
        this.algorithm = algorithm;
        header.put("alg", algorithm.jwtName());
        return this;
    }

    /**
     * Define a chave HMAC (simétrica).
     *
     * <p><b>Segurança:</b> para criar a partir de uma string:
     * <pre>{@code
     * SecretKey key = new SecretKeySpec(
     *     "segredo".getBytes(StandardCharsets.UTF_8),
     *     "HmacSHA256"
     * );
     * }</pre>
     */
    public JwtBuilder signWith(SecretKey key) {
        this.signingKey = key;
        return this;
    }

    /**
     * Define a chave privada (RSA/EC).
     */
    public JwtBuilder signWith(PrivateKey key) {
        this.signingKey = key;
        return this;
    }

    /**
     * Define qualquer {@link Key}. Preferível usar os overloads específicos
     * ({@link #signWith(SecretKey)}, {@link #signWith(PrivateKey)}) para
     * validação em tempo de compilação.
     */
    public JwtBuilder signWith(Key key) {
        this.signingKey = key;
        return this;
    }

    // ------------------------------------------------------------------
    // Header
    // ------------------------------------------------------------------

    /**
     * Define o identificador da chave (Key ID) usada para assinar.
     *
     * <p>O {@code kid} vai no <b>header</b> do JWT (RFC 7515, seção 4.1.4),
     * não no payload. Ele permite que o verificador escolha qual chave
     * usar quando o emissor publica múltiplas chaves (rotação de chaves).
     *
     * @param kid identificador da chave (ex: "2025-10-key-01")
     */
    public JwtBuilder keyId(String kid) {
        if (kid == null || kid.isBlank()) {
            throw new JwtException("kid não pode ser vazio");
        }
        header.put("kid", kid);
        return this;
    }

    // ------------------------------------------------------------------
    // Claims genéricos
    // ------------------------------------------------------------------

    /**
     * Adiciona um claim arbitrário ao payload.
     */
    public JwtBuilder claim(String name, Object value) {
        claims.put(name, value);
        return this;
    }

    // ------------------------------------------------------------------
    // Claims registrados (RFC 7519, seção 4.1)
    // ------------------------------------------------------------------

    /** Atalho para o claim registrado {@code sub} (subject). */
    public JwtBuilder subject(String subject) {
        return claim("sub", subject);
    }

    /** Atalho para o claim registrado {@code iss} (issuer). */
    public JwtBuilder issuer(String issuer) {
        return claim("iss", issuer);
    }

    /** Atalho para o claim registrado {@code aud} (audience). */
    public JwtBuilder audience(String audience) {
        return claim("aud", audience);
    }

    /** Atalho para o claim registrado {@code jti} (JWT ID) com valor explícito. */
    public JwtBuilder id(String id) {
        return claim("jti", id);
    }

    /**
     * Gera automaticamente um {@code jti} único (UUID v4) e o adiciona ao payload.
     *
     * <p>O {@code jti} identifica unicamente este token. É usado para:
     * <ul>
     *   <li><b>Revogação:</b> um verificador pode manter uma blacklist
     *       de {@code jti} e consultá-la antes de aceitar o token.</li>
     *   <li><b>Idempotência:</b> detectar reuso de token em protocolos
     *       que exigem unicidade.</li>
     * </ul>
     *
     * <p>UUID v4 é escolhido por ser único sem coordenação entre instâncias.
     * Em um cluster, cada nó gera UUIDs sem colidir.
     */
    public JwtBuilder id() {
        return claim("jti", UUID.randomUUID().toString());
    }

    // ------------------------------------------------------------------
    // Claims de tempo (RFC 7519, seção 4.1)
    // ------------------------------------------------------------------

    /**
     * Define {@code iat} (issued at) com o horário atual em segundos.
     */
    public JwtBuilder issuedNow() {
        return claim("iat", nowSeconds());
    }

    /**
     * Define {@code exp} (expiration) como {@code agora + segundos}.
     *
     * @param seconds tempo de vida em segundos (deve ser > 0)
     */
    public JwtBuilder expiresInSeconds(long seconds) {
        return claim("exp", nowSeconds() + seconds);
    }

    /**
     * Define {@code nbf} (not before) como {@code agora + segundos}.
     */
    public JwtBuilder notBeforeInSeconds(long seconds) {
        return claim("nbf", nowSeconds() + seconds);
    }

    private static long nowSeconds() {
        return System.currentTimeMillis() / 1000L;
    }

    // ------------------------------------------------------------------
    // Geração do token
    // ------------------------------------------------------------------

    /**
     * Gera o token final.
     *
     * <p>Este é o ponto onde tudo se junta:
     * <ol>
     *   <li>Valida que algoritmo e chave foram definidos.</li>
     *   <li>Serializa header e payload em JSON.</li>
     *   <li>Aplica Base64URL em ambos.</li>
     *   <li>Concatena com "." para obter o {@code signing_input}.</li>
     *   <li>Assina o {@code signing_input} com o algoritmo configurado.</li>
     *   <li>Aplica Base64URL na assinatura.</li>
     *   <li>Concatena tudo.</li>
     * </ol>
     *
     * @return o token JWT completo (formato {@code header.payload.signature})
     * @throws JwtException se algoritmo ou chave não foram definidos
     */
    public String compact() {
        if (algorithm == null) {
            throw new JwtException("Algoritmo não definido. Chame .alg(...) antes de .compact()");
        }
        if (signingKey == null) {
            throw new JwtException("Chave não definida. Chame .signWith(...) antes de .compact()");
        }

        // 1. Serializa header e payload
        String headerJson  = Json.stringify(header);
        String payloadJson = Json.stringify(claims);

        // 2. Base64URL de ambos
        String headerB64  = Base64Url.encode(headerJson);
        String payloadB64 = Base64Url.encode(payloadJson);

        // 3. signing_input = headerB64 + "." + payloadB64
        //    Assinamos sobre a STRING ASCII resultante, não sobre os JSONs.
        String signingInput = headerB64 + "." + payloadB64;

        // 4. Assina com o algoritmo e a chave configurados
        byte[] signature = algorithm.sign(
                signingInput.getBytes(StandardCharsets.UTF_8),
                signingKey
        );

        // 5. Base64URL da assinatura
        String signatureB64 = Base64Url.encode(signature);

        // 6. Monta token final
        return signingInput + "." + signatureB64;
    }
}