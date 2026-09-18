package com.github.bapadua.labs.jwt;

import com.github.bapadua.labs.jwt.internal.Base64Url;
import com.github.bapadua.labs.jwt.internal.Json;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwtBuilderTest {

    private static final String SECRET =
            "minha-chave-secreta-com-32-bytes!!"; // >= 32 bytes para HS256

    @Test
    @DisplayName("Gera token com três partes separadas por ponto")
    void temTresPartes() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-1")
                .compact();

        String[] parts = token.split("\\.");
        assertEquals(3, parts.length, "JWT deve ter exatamente 3 partes");
    }

    @Test
    @DisplayName("Header decodificado contém alg e typ")
    void headerCorreto() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-1")
                .compact();

        String headerJson = Base64Url.decodeToString(token.split("\\.")[0]);
        Map<String, Object> header = Json.parse(headerJson);

        assertEquals("HS256", header.get("alg"));
        assertEquals("JWT", header.get("typ"));
    }

    @Test
    @DisplayName("Payload decodificado contém os claims informados")
    void payloadCorreto() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-1")
                .issuer("minha-app")
                .claim("role", "admin")
                .compact();

        String payloadJson = Base64Url.decodeToString(token.split("\\.")[1]);
        Map<String, Object> claims = Json.parse(payloadJson);

        assertEquals("user-1",    claims.get("sub"));
        assertEquals("minha-app", claims.get("iss"));
        assertEquals("admin",     claims.get("role"));
    }

    @Test
    @DisplayName("Assinatura bate com HMAC calculado manualmente")
    void assinaturaBate() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-1")
                .compact();

        String[] parts = token.split("\\.");
        String signingInput = parts[0] + "." + parts[1];
        byte[] expectedSig = Algorithm.HS256.sign(
                signingInput.getBytes(StandardCharsets.UTF_8),
                TestKeys.hmac(SECRET));

        assertEquals(Base64Url.encode(expectedSig), parts[2]);
    }

    @Test
    @DisplayName("Token é determinístico: mesmos inputs, mesmo token")
    void determinismo() {
        // Sem timestamps dinâmicos, o token deve ser sempre idêntico.
        // Isso valida que a ordem de chaves do LinkedHashMap está sendo
        // preservada e que o Base64URL é aplicado consistentemente.
        String token1 = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-1")
                .issuer("app")
                .claim("role", "admin")
                .compact();

        String token2 = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-1")
                .issuer("app")
                .claim("role", "admin")
                .compact();

        assertEquals(token1, token2);
    }

    @Test
    @DisplayName("Mudar um claim muda a assinatura")
    void mudancaDeClaimMudaAssinatura() {
        String token1 = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-1")
                .compact();

        String token2 = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-2") // diferente
                .compact();

        assertNotEquals(
                token1.split("\\.")[2], // assinatura 1
                token2.split("\\.")[2]  // assinatura 2
        );
    }

    @Test
    @DisplayName("Mudar a chave muda a assinatura")
    void mudancaDeChaveMudaAssinatura() {
        String token1 = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac("chave-1-com-32-bytes-para-hs256!!!!"))
                .subject("user-1")
                .compact();
        String token2 = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac("chave-2-com-32-bytes-para-hs256!!!!"))
                .subject("user-1")
                .compact();

        assertNotEquals(
                token1.split("\\.")[2],
                token2.split("\\.")[2]
        );

    }

    @Test
    @DisplayName("expiresInSeconds define exp no futuro")
    void expiraNoFuturo() {
        long before = System.currentTimeMillis() / 1000;
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .expiresInSeconds(3600)
                .compact();
        long after = System.currentTimeMillis() / 1000;

        Map<String, Object> claims = Json.parse(
                Base64Url.decodeToString(token.split("\\.")[1])
        );
        long exp = ((Number) claims.get("exp")).longValue();

        assertTrue(exp >= before + 3600);
        assertTrue(exp <= after  + 3600);
    }

    @Test
    @DisplayName("compact() falha se alg não definido")
    void falhaSemAlg() {
        assertThrows(JwtException.class, () ->
                Jwts.builder().signWith(TestKeys.hmac(SECRET)).compact()
        );
    }

    @Test
    @DisplayName("compact() falha se chave não definida")
    void falhaSemChave() {
        assertThrows(JwtException.class, () ->
                Jwts.builder().alg(Algorithm.HS256).compact()
        );
    }

    @Test
    @DisplayName("Fluent API retorna this para encadeamento")
    void fluentApi() {
        JwtBuilder builder = Jwts.builder();
        assertSame(builder, builder.alg(Algorithm.HS256));
        assertSame(builder, builder.signWith(TestKeys.hmac(SECRET)));
        assertSame(builder, builder.subject("x"));
        assertSame(builder, builder.claim("y", 1));
    }

    @Test
    @DisplayName("keyId é colocado no header, não no payload")
    void kidNoHeader() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .keyId("2025-10-key-01")
                .subject("user-1")
                .compact();

        String[] parts = token.split("\\.");
        Map<String, Object> header = Json.parse(Base64Url.decodeToString(parts[0]));
        Map<String, Object> claims = Json.parse(Base64Url.decodeToString(parts[1]));

        assertEquals("2025-10-key-01", header.get("kid"));
        assertFalse(claims.containsKey("kid"), "kid NÃO deve estar no payload");
    }

    @Test
    @DisplayName("id() gera jti único (UUID)")
    void geraJtiUnico() {
        String token1 = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))   // builder → signWith
                .id()
                .compact();

        String token2 = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .id()
                .compact();

        Jwt jwt1 = Jwts.parser()
                .verifyWith(TestKeys.hmac(SECRET)) // parser → verifyWith
                .parse(token1);

        Jwt jwt2 = Jwts.parser()
                .verifyWith(TestKeys.hmac(SECRET))
                .parse(token2);

        assertNotNull(jwt1.getId());
        assertNotNull(jwt2.getId());
        assertNotEquals(jwt1.getId(), jwt2.getId(), "jti deve ser único entre tokens");
    }

}