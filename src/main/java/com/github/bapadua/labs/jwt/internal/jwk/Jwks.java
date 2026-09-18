package com.github.bapadua.labs.jwt.internal.jwk;

import com.github.bapadua.labs.jwt.JwtException;
import com.github.bapadua.labs.jwt.internal.Json;

import java.util.*;

/**
 * Representação imutável de um JSON Web Key Set (RFC 7517, seção 5).
 *
 * <p>Um JWKS é simplesmente {@code {"keys": [...]}}. É o formato publicado
 * em {@code /.well-known/jwks.json} por todo provedor OIDC.
 */
public final class Jwks {

    private final List<Jwk> keys;

    private Jwks(List<Jwk> keys) {
        this.keys = Collections.unmodifiableList(new ArrayList<>(keys));
    }

    /**
     * Cria um JWKS a partir de uma lista de chaves.
     */
    public static Jwks of(List<Jwk> keys) {
        return new Jwks(keys);
    }

    /**
     * Cria um JWKS a partir de chaves variádicas. Conveniente para testes.
     */
    public static Jwks of(Jwk... keys) {
        return new Jwks(List.of(keys));
    }

    public List<Jwk> keys() {
        return keys;
    }

    /**
     * Busca uma chave pelo {@code kid}.
     *
     * <p>Retorna {@link Optional#empty()} se não encontrar — não lança
     * exceção, porque "não achei" é um resultado esperado em rotação de
     * chaves (o cliente pode tentar um refresh antes de falhar).
     */
    public Optional<Jwk> findByKid(String kid) {
        if (kid == null) return Optional.empty();
        return keys.stream()
                .filter(k -> kid.equals(k.kid()))
                .findFirst();
    }

    // ------------------------------------------------------------------
    // Serialização
    // ------------------------------------------------------------------

    /**
     * Serializa o JWKS para JSON no formato {@code {"keys":[...]}}.
     */
    public String toJson() {
        // Cada JWK vira um Map para compor o array
        List<Map<String, Object>> keyList = new ArrayList<>(keys.size());
        for (Jwk k : keys) {
            // Parse de volta para Map para reaproveitar a estrutura
            keyList.add(Json.parse(k.toJson()));
        }
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("keys", keyList);
        return Json.stringify(root);
    }

    /**
     * Parseia um JWKS a partir de JSON.
     */
    @SuppressWarnings("unchecked")
    public static Jwks fromJson(String json) {
        Map<String, Object> root = Json.parse(json);
        Object keysNode = root.get("keys");
        if (!(keysNode instanceof List<?> list)) {
            throw new JwtException("JWKS inválido: 'keys' deve ser um array");
        }

        List<Jwk> parsed = new ArrayList<>(list.size());
        for (Object node : list) {
            if (!(node instanceof Map)) {
                throw new JwtException("JWKS inválido: item não é objeto");
            }
            // Re-serializa e delega ao parser do Jwk
            parsed.add(Jwk.fromJson(Json.stringify((Map<String, Object>) node)));
        }

        return new Jwks(parsed);
    }
}