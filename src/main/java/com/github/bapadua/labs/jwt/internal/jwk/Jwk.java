package com.github.bapadua.labs.jwt.internal.jwk;

import com.github.bapadua.labs.jwt.JwtException;
import com.github.bapadua.labs.jwt.internal.Json;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Representação imutável de um JSON Web Key (RFC 7517).
 *
 * <p>Um JWK é a serialização JSON de uma chave criptográfica. Os campos
 * variam por tipo de chave ({@code kty}):
 *
 * <ul>
 *   <li><b>RSA</b>: {@code n} (módulo), {@code e} (expoente público);
 *       quando privada, também {@code d}, {@code p}, {@code q},
 *       {@code dp}, {@code dq}, {@code qi}</li>
 *   <li><b>EC</b>: {@code crv} (curva), {@code x}, {@code y} (coordenadas)</li>
 *   <li><b>oct</b>: {@code k} (chave simétrica)</li>
 * </ul>
 *
 * <p><b>Imutabilidade:</b> todos os campos são {@code final}, e o mapa
 * de campos extras é envolvido em {@link Collections#unmodifiableMap}.
 * Um {@code Jwk} não muda depois de construído.
 *
 * <p><b>Construção:</b> via {@link #builder()}, {@link #rsa()} ou
 * {@link #ec()}. Não há construtor público — todo JWK nasce de um
 * builder que valida os campos obrigatórios para o tipo declarado.
 *
 * <p><b>E os campos que não modelamos?</b> Vão para {@link #extra}. Isso
 * permite ler JWKs com campos exóticos ({@code x5c}, {@code jku},
 * {@code key_ops}) sem perder dados.
 */
public final class Jwk {

    // ------------------------------------------------------------------
    // Campos comuns (RFC 7517, seção 4)
    // ------------------------------------------------------------------
    private final String kty;
    private final String kid;
    private final String use;
    private final String alg;

    // ------------------------------------------------------------------
    // Campos RSA (RFC 7518, seção 6.3)
    // ------------------------------------------------------------------
    private final String n;    // modulus
    private final String e;    // public exponent
    private final String d;    // private exponent (somente chave privada)
    private final String p;    // first prime factor (privada)
    private final String q;    // second prime factor (privada)
    private final String dp;   // first factor CRT exponent (privada)
    private final String dq;   // second factor CRT exponent (privada)
    private final String qi;   // first CRT coefficient (privada)

    // ------------------------------------------------------------------
    // Campos EC (RFC 7518, seção 6.2) — reservados para ES256+
    // ------------------------------------------------------------------
    private final String crv;
    private final String x;
    private final String y;

    // ------------------------------------------------------------------
    // Escape hatch para campos não modelados
    // ------------------------------------------------------------------
    private final Map<String, Object> extra;

    /**
     * Construtor privado. A única porta de entrada é o {@link Builder}.
     * Copia os campos, faz defensive copy do mapa {@code extra}, e
     * valida os campos obrigatórios por tipo.
     */
    private Jwk(Builder b) {
        this.kty = require(b.kty, "kty");
        this.kid = b.kid;
        this.use = b.use;
        this.alg = b.alg;

        this.n   = b.n;
        this.e   = b.e;
        this.d   = b.d;
        this.p   = b.p;
        this.q   = b.q;
        this.dp  = b.dp;
        this.dq  = b.dq;
        this.qi  = b.qi;

        this.crv = b.crv;
        this.x   = b.x;
        this.y   = b.y;

        // Defensive copy: ninguém fora daqui pode mutar nosso mapa.
        this.extra = Collections.unmodifiableMap(new LinkedHashMap<>(b.extra));

        validateByType();
    }

    /**
     * Valida campos obrigatórios por tipo de chave.
     * Falha rápido se faltar algo essencial.
     */
    private void validateByType() {
        switch (kty) {
            case "RSA" -> {
                if (n == null || e == null) {
                    throw new JwtException("JWK RSA requer 'n' e 'e'");
                }
                // Se a chave tem material privado, todos os componentes
                // CRT são obrigatórios. A JCA exige isso para reconstruir
                // via RSAPrivateCrtKeySpec.
                if (d != null) {
                    if (p == null || q == null || dp == null || dq == null || qi == null) {
                        throw new JwtException(
                                "JWK RSA privado requer 'd', 'p', 'q', 'dp', 'dq', 'qi'"
                        );
                    }
                }
            }
            case "EC" -> {
                if (crv == null || x == null || y == null) {
                    throw new JwtException("JWK EC requer 'crv', 'x' e 'y'");
                }
            }
            // 'oct' e outros tipos ficam para depois. Aceitamos sem validar.
        }
    }

    private static String require(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new JwtException("Campo obrigatório ausente: " + field);
        }
        return value;
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    public String kty() { return kty; }
    public String kid() { return kid; }
    public String use() { return use; }
    public String alg() { return alg; }

    public String n()  { return n; }
    public String e()  { return e; }
    public String d()  { return d; }
    public String p()  { return p; }
    public String q()  { return q; }
    public String dp() { return dp; }
    public String dq() { return dq; }
    public String qi() { return qi; }

    public String crv() { return crv; }
    public String x()   { return x; }
    public String y()   { return y; }

    public Map<String, Object> extra() { return extra; }

    /**
     * Retorna true se este JWK contém material de chave privada.
     */
    public boolean isPrivate() {
        return d != null;
    }

    // ------------------------------------------------------------------
    // Serialização
    // ------------------------------------------------------------------

    /**
     * Serializa este JWK para JSON, preservando ordem determinística
     * das chaves (para hashing/comparação estável).
     */
    public String toJson() {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("kty", kty);
        if (kid != null) json.put("kid", kid);
        if (use != null) json.put("use", use);
        if (alg != null) json.put("alg", alg);
        if (n   != null) json.put("n", n);
        if (e   != null) json.put("e", e);
        if (crv != null) json.put("crv", crv);
        if (x   != null) json.put("x", x);
        if (y   != null) json.put("y", y);
        if (d   != null) json.put("d", d);
        if (p   != null) json.put("p", p);
        if (q   != null) json.put("q", q);
        if (dp  != null) json.put("dp", dp);
        if (dq  != null) json.put("dq", dq);
        if (qi  != null) json.put("qi", qi);

        json.putAll(extra);

        return Json.stringify(json);
    }

    /**
     * Parseia um JWK a partir de JSON.
     */
    @SuppressWarnings("unchecked")
    public static Jwk fromJson(String json) {
        Map<String, Object> map = Json.parse(json);

        Builder b = new Builder();
        b.kty = (String) map.get("kty");
        b.kid = (String) map.get("kid");
        b.use = (String) map.get("use");
        b.alg = (String) map.get("alg");
        b.n   = (String) map.get("n");
        b.e   = (String) map.get("e");
        b.d   = (String) map.get("d");
        b.p   = (String) map.get("p");
        b.q   = (String) map.get("q");
        b.dp  = (String) map.get("dp");
        b.dq  = (String) map.get("dq");
        b.qi  = (String) map.get("qi");
        b.crv = (String) map.get("crv");
        b.x   = (String) map.get("x");
        b.y   = (String) map.get("y");

        // O restante vai para extra
        map.forEach((k, v) -> {
            if (!isCanonicalField(k)) {
                b.extra.put(k, v);
            }
        });

        return b.build();
    }

    private static boolean isCanonicalField(String key) {
        return switch (key) {
            case "kty", "kid", "use", "alg",
                 "n", "e", "d", "p", "q", "dp", "dq", "qi",
                 "crv", "x", "y" -> true;
            default -> false;
        };
    }

    // ------------------------------------------------------------------
    // Builder
    // ------------------------------------------------------------------

    public static Builder builder() {
        return new Builder();
    }

    /** Fábrica para JWK RSA. */
    public static Builder rsa() {
        return new Builder().kty("RSA");
    }

    /** Fábrica para JWK EC. */
    public static Builder ec() {
        return new Builder().kty("EC");
    }

    /**
     * Builder mutável para {@link Jwk}. Todos os campos são opcionais no
     * builder — a validação por tipo acontece só no {@link #build()}.
     * Isso permite construir o JWK na ordem que fizer sentido.
     */
    public static final class Builder {
        private String kty;
        private String kid;
        private String use;
        private String alg;

        private String n;
        private String e;
        private String d;
        private String p;
        private String q;
        private String dp;
        private String dq;
        private String qi;

        private String crv;
        private String x;
        private String y;

        private final Map<String, Object> extra = new LinkedHashMap<>();

        private Builder() {}

        public Builder kty(String kty)   { this.kty = kty; return this; }
        public Builder kid(String kid)   { this.kid = kid; return this; }
        public Builder use(String use)   { this.use = use; return this; }
        public Builder alg(String alg)   { this.alg = alg; return this; }

        public Builder modulus(String n)  { this.n = n; return this; }
        public Builder exponent(String e) { this.e = e; return this; }

        public Builder privateExponent(String d)  { this.d = d; return this; }
        public Builder primeP(String p)           { this.p = p; return this; }
        public Builder primeQ(String q)           { this.q = q; return this; }
        public Builder crtDp(String dp)           { this.dp = dp; return this; }
        public Builder crtDq(String dq)           { this.dq = dq; return this; }
        public Builder crtQi(String qi)           { this.qi = qi; return this; }

        public Builder curve(String crv) { this.crv = crv; return this; }
        public Builder x(String x)       { this.x = x; return this; }
        public Builder y(String y)       { this.y = y; return this; }

        public Builder extra(String key, Object value) {
            this.extra.put(key, value);
            return this;
        }

        public Jwk build() {
            return new Jwk(this);
        }
    }
}