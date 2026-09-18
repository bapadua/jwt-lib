package com.github.bapadua.labs.jwt;


import com.github.bapadua.labs.jwt.internal.Base64Url;
import com.github.bapadua.labs.jwt.internal.Json;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Set;

/**
 * Parser e verificador de JWTs.
 *
 * <p>Uso típico:
 * <pre>{@code
 * Jwt jwt = Jwts.parser()
 *         .signWith("minha-chave")
 *         .requireAlgorithm(Algorithm.HS256)
 *         .clockSkewSeconds(30)
 *         .parse(token);
 * }</pre>
 *
 * <p><b>Defesas de segurança embutidas:</b>
 * <ul>
 *   <li><b>Algorithm pinning opcional</b> ({@link #requireAlgorithm}) — evita
 *       o ataque de "algorithm confusion", onde um atacante troca {@code alg}
 *       no header para enganar o verificador.</li>
 *   <li><b>Rejeição de {@code alg=none}</b> — não suportamos {@code none},
 *       ponto. Se aparecer, é erro.</li>
 *   <li><b>Verificação de assinatura constant-time</b> — via {@link Algorithm#verify}.</li>
 *   <li><b>Verificação de expiração</b> com tolerância configurável de clock skew.</li>
 * </ul>
 *
 * <p><b>Mutável e não thread-safe.</b> Crie um novo parser por operação,
 * ou sincronize externamente.
 */
public class JwtParser {
    // ---- Chaves ----
    private Key verificationKey;
    private KeyProvider keyProvider;

    // ---- Validações obrigatórias ----
    /**
     * Algoritmos aceitos. Se vazio, aceita qualquer um que a lib suporte
     * ...
     */
    private Set<Algorithm> allowedAlgorithms = Set.of();
    private String expectedKeyId;
    private String expectedIssuer;
    private String expectedType;
    private Set<String> requiredAudiences = Set.of();

    // ---- Configuração do parser ----
    private boolean verifyExpiration = true;
    private boolean verifySignature = true;
    /**
     * Tolerância de clock skew em segundos. A RFC 7519, seção 4.1.4,
     * recomenda uma pequena margem para compensar diferenças de relógio
     * entre emissores e verificadores.
     *
     * <p>Zero significa "sem tolerância".
     */

    private long clockSkewSeconds = 0;



    JwtParser() {
        // Construção restrita a Jwts.parser().
    }

    public static JwtParser parser() {
        return new JwtParser();
    }


    /**
     * Restringe os algoritmos aceitos. Se o token vier com um algoritmo
     * fora do conjunto, é rejeitado antes mesmo da verificação de assinatura.
     */
    public JwtParser requireAlgorithm(Algorithm... algorithms) {
        this.allowedAlgorithms = Set.of(algorithms);
        return this;
    }

    /**
     * Exige que o header contenha exatamente este {@code kid}.
     *
     * <p>Use quando você tem múltiplas chaves ativas e quer garantir que
     * um token emitido com a chave X seja verificado apenas com a chave X.
     */
    public JwtParser requireKeyId(String kid) {
        this.expectedKeyId = kid;
        return this;
    }

    public JwtParser requireIssuer(String issuer) {
        this.expectedIssuer = issuer;
        return this;
    }

    /**
     * Exige que o token tenha pelo menos uma das audiências informadas.
     *
     * <p>Conforme RFC 7519, seção 4.1.3, o verificador <b>deve</b> rejeitar
     * tokens cujo {@code aud} não o inclua, quando {@code aud} está presente.
     */
    public JwtParser requireAudience(String... audiences) {
        this.requiredAudiences = java.util.Set.of(audiences);
        return this;
    }

    /**
     * Exige um {@code typ} específico no header.
     *
     * <p>Convenções comuns:
     * <ul>
     *   <li>{@code "JWT"} — genérico (RFC 7519).</li>
     *   <li>{@code "at+jwt"} — access token (RFC 9068).</li>
     *   <li>{@code "refresh+jwt"} — refresh token (convenção Keycloak).</li>
     * </ul>
     *
     * <p><b>Nota:</b> a comparação ignora case, conforme RFC 7515 trata
     * {@code typ} como case-insensitive.
     */
    public JwtParser requireType(String type) {
        this.expectedType = type;
        return this;
    }

    /**
     * Define tolerância de clock skew em segundos.
     */
    public JwtParser clockSkewSeconds(long seconds) {
        if (seconds < 0) {
            throw new JwtException("clockSkewSeconds não pode ser negativo");
        }
        this.clockSkewSeconds = seconds;
        return this;
    }

    public JwtParser verifyWith(SecretKey key) {
        this.verificationKey = key;
        return this;
    }

    public JwtParser verifyWith(PublicKey key) {
        this.verificationKey = key;
        return this;
    }

    public JwtParser verifyWith(Key key) {
        this.verificationKey = key;
        return this;
    }

    public JwtParser keyProvider(KeyProvider provider) {
        this.keyProvider = provider;
        return this;
    }

    /**
     * Desabilita a verificação de expiração ({@code exp}).
     *
     * <p><b>Cuidado:</b> use apenas em contextos controlados (ex: testes).
     * Em produção, você quase certamente quer que {@code exp} seja verificado.
     */
    public JwtParser skipExpirationCheck() {
        this.verifyExpiration = false;
        return this;
    }

    /**
     * Desabilita a verificação de assinatura.
     *
     * <p><b>PERIGOSO.</b> Só use quando o token já foi validado em outro
     * ponto e você quer apenas ler os claims (ex: logs de auditoria).
     * Nunca use no fluxo normal de autenticação.
     */
    public JwtParser skipSignatureCheck() {
        this.verifySignature = false;
        return this;
    }

    /**
     * Faz o parse e verificação do token.
     *
     * <p>Etapas:
     * <ol>
     *   <li>Divide em três partes.</li>
     *   <li>Decodifica header e payload de Base64URL.</li>
     *   <li>Valida algoritmo (se {@link #requireAlgorithm} foi chamado).</li>
     *   <li>Verifica assinatura.</li>
     *   <li>Verifica expiração e {@code nbf}.</li>
     *   <li>Retorna {@link Jwt} imutável.</li>
     * </ol>
     *
     * @param token o JWT em formato compacto
     * @return o token processado e validado
     * @throws JwtException em qualquer falha de formato, assinatura ou tempo
     */
    public Jwt parse(String token) {
        // 1. Formato
        if (token == null || token.isBlank()) {
            throw new JwtException("Token vazio ou nulo");
        }

        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new JwtException("Token malformado: esperado header.payload.signature");
        }

        String headerB64    = parts[0];
        String payloadB64   = parts[1];
        String signatureB64 = parts[2];

        // 2. Decode
        LinkedHashMap<String, Object> header;
        LinkedHashMap<String, Object> claims;
        try {
            header = Json.parse(Base64Url.decodeToString(headerB64));
            claims = Json.parse(Base64Url.decodeToString(payloadB64));
        } catch (IllegalArgumentException e) {
            throw new JwtException("Falha ao decodificar partes do token", e);
        }

        // 3. Algoritmo
        Object algName = header.get("alg");
        if (!(algName instanceof String algStr)) {
            throw new JwtException("Header sem campo 'alg' ou com tipo inválido");
        }

        Algorithm algorithm;
        try {
            algorithm = Algorithm.fromJwtName(algStr);
        } catch (JwtException e) {
            throw new JwtException("Algoritmo não suportado: " + algStr, e);
        }

        // 4. Algoritmo permitido?
        if (!allowedAlgorithms.isEmpty() && !allowedAlgorithms.contains(algorithm)) {
            throw new JwtException("Algoritmo não permitido: " + algorithm);
        }

        // 5. kid esperado?
        if (expectedKeyId != null) {
            Object kid = header.get("kid");
            if (!expectedKeyId.equals(kid)) {
                throw new JwtException(
                        "kid esperado '" + expectedKeyId + "', mas recebido '" + kid + "'"
                );
            }
        }

        // 6. typ esperado?
        if (expectedType != null) {
            Object typ = header.get("typ");
            if (!(typ instanceof String typStr) || !typStr.equalsIgnoreCase(expectedType)) {
                throw new JwtException(
                        "typ esperado '" + expectedType + "', mas recebido '" + typ + "'"
                );
            }
        }

        // 7. Assinatura
        if (verifySignature) {
            Key keyToUse;

            if (keyProvider != null) {
                keyToUse = keyProvider.getKey(header);
                if (keyToUse == null) {
                    throw new JwtException("KeyProvider retornou null");
                }
            } else if (verificationKey != null) {
                keyToUse = verificationKey;
            } else {
                throw new JwtException("Nenhuma chave ou KeyProvider configurado");
            }

            String signingInput = headerB64 + "." + payloadB64;
            byte[] signature = Base64Url.decode(signatureB64);

            boolean ok = algorithm.verify(
                    signingInput.getBytes(StandardCharsets.UTF_8),
                    signature,
                    keyToUse
            );

            if (!ok) {
                throw new JwtException("Assinatura inválida");
            }
        }

        // 8. Constrói o Jwt
        Jwt jwt = new Jwt(header, claims, Base64Url.decode(signatureB64), token);

        // 9. iss esperado?
        if (expectedIssuer != null) {
            String iss = jwt.getIssuer();
            if (!expectedIssuer.equals(iss)) {
                throw new JwtException(
                        "Issuer inválido: esperado '" + expectedIssuer + "', recebido '" + iss + "'"
                );
            }
        }

        // 10. aud esperada?
        if (!requiredAudiences.isEmpty()) {
            var audiences = jwt.getAudiences();
            boolean matched = audiences.stream().anyMatch(requiredAudiences::contains);
            if (!matched) {
                throw new JwtException(
                        "Audience inválida. Esperado um de " + requiredAudiences
                                + ", mas recebido " + audiences
                );
            }
        }

        // 11. exp / nbf
        if (verifyExpiration) {
            if (jwt.isExpired(clockSkewSeconds)) {
                throw new JwtException("Token expirado");
            }
            if (jwt.isNotYetValid(clockSkewSeconds)) {
                throw new JwtException("Token ainda não é válido (nbf)");
            }
        }

        return jwt;
    }
}
