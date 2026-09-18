package com.github.bapadua.labs.jwt;

import com.github.bapadua.labs.jwt.internal.Base64Url;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.AssertionsKt.assertNotNull;

class JwtParserTest {

    private static final String SECRET = "minha-chave-super-secreta-com-32b!";

    @Test
    @DisplayName("Round-trip: gera e faz parse com sucesso")
    void roundTrip() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-1")
                .issuer("minha-app")
                .claim("role", "admin")
                .compact();

        Jwt jwt = Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse(token);

        assertEquals("user-1", jwt.getSubject());
        assertEquals("minha-app", jwt.getIssuer());
        assertEquals("admin", jwt.getStringClaim("role"));
        assertEquals(token, jwt.getRawToken());
    }

    @Test
    @DisplayName("Rejeita token com assinatura inválida")
    void assinaturaInvalida() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-1")
                .compact();

        JwtException ex = assertThrows(JwtException.class, () ->
                Jwts.parser().verifyWith(TestKeys.hmac("outra-chave-completamente-diferente!!")).parse(token)
        );
        assertEquals("Assinatura inválida", ex.getMessage());
    }

    @Test
    @DisplayName("Rejeita token com payload adulterado")
    void payloadAdulterado() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-1")
                .compact();

        // Adultera o payload: troca subject
        String[] parts = token.split("\\.");
        String payloadFalso = Base64Url.encode(
                "{\"sub\":\"hacker\"}"
        );
        String tokenForjado = parts[0] + "." + payloadFalso + "." + parts[2];

        assertThrows(JwtException.class, () ->
                Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse(tokenForjado)
        );
    }

    @Test
    @DisplayName("Rejeita token malformado (sem 3 partes)")
    void malformado() {
        assertThrows(JwtException.class, () -> Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse("abc.def"));
        assertThrows(JwtException.class, () -> Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse("abc"));
        assertThrows(JwtException.class, () -> Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse(""));
        assertThrows(JwtException.class, () -> Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse(null));
    }

    @Test
    @DisplayName("Rejeita token expirado")
    void expirado() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .claim("exp", System.currentTimeMillis() / 1000 - 10)
                .compact();

        JwtException ex = assertThrows(JwtException.class, () ->
                Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse(token)
        );
        assertEquals("Token expirado", ex.getMessage());
    }

    @Test
    @DisplayName("Aceita token expirado dentro da tolerância de clock skew")
    void clockSkew() {
        // Token expirou 5 segundos atrás
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .claim("exp", System.currentTimeMillis() / 1000 - 5)
                .compact();

        // Sem tolerância: rejeita
        assertThrows(JwtException.class, () ->
                Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse(token)
        );

        // Com 30s de tolerância: aceita
        Jwt jwt = Jwts.parser()
                .verifyWith(TestKeys.hmac(SECRET))
                .clockSkewSeconds(30)
                .parse(token);

        assertNotNull(jwt);
    }

    @Test
    @DisplayName("Rejeita token com nbf no futuro")
    void nbfNoFuturo() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .claim("nbf", System.currentTimeMillis() / 1000 + 3600)
                .compact();

        JwtException ex = assertThrows(JwtException.class, () ->
                Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse(token)
        );
        assertTrue(ex.getMessage().contains("nbf"));
    }

    @Test
    @DisplayName("Rejeita algoritmo não permitido (algorithm pinning)")
    void algorithmPinning() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-1")
                .compact();

        // Se exigirmos HS512, HS256 é rejeitado
        assertThrows(JwtException.class, () ->
                Jwts.parser()
                        .verifyWith(TestKeys.hmac(SECRET))
                        .requireAlgorithm(Algorithm.HS512)
                        .parse(token)
        );
    }

    @Test
    @DisplayName("Rejeita token com alg=none")
    void rejeitaNone() {
        // Constrói um token "none" manualmente
        String headerB64  = Base64Url.encode("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payloadB64 = Base64Url.encode("{\"sub\":\"x\"}");
        String token = headerB64 + "." + payloadB64 + ".";

        assertThrows(JwtException.class, () ->
                Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse(token)
        );
    }

    @Test
    @DisplayName("exp ausente: não expira")
    void semExpNaoExpira() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-1")
                .compact();

        Jwt jwt = Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse(token);
        assertNull(jwt.getExpiration());
        assertFalse(jwt.isExpired());
    }

    @Test
    @DisplayName("getLongClaim normaliza Integer para Long")
    void normalizaNumerico() {
        // 1 hora em segundos cabe em int
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .claim("exp", System.currentTimeMillis() / 1000 + 3600)
                .compact();

        Jwt jwt = Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse(token);

        // getExpiration() retorna Long mesmo se o Jackson desserializou como Integer
        Long exp = jwt.getExpiration();
        assertNotNull(exp);
        assertTrue(exp > System.currentTimeMillis() / 1000);
    }


    @Test
    @DisplayName("Fluent API do parser retorna this")
    void parserFluentApi() {
        JwtParser parser = Jwts.parser();
        assertSame(parser, parser.verifyWith(TestKeys.hmac(SECRET)));
        assertSame(parser, parser.clockSkewSeconds(30));
        assertSame(parser, parser.requireAlgorithm(Algorithm.HS256));
    }

    @Test
    @DisplayName("Jwt é imutável: claims não podem ser alterados")
    void jwtImutavel() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .subject("user-1")
                .compact();

        Jwt jwt = Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse(token);

        assertThrows(UnsupportedOperationException.class, () ->
                jwt.getClaims().put("hack", "boom")
        );
        assertThrows(UnsupportedOperationException.class, () ->
                jwt.getHeader().put("hack", "boom")
        );
    }

    @Test
    @DisplayName("Parser expõe o kid via getKeyId()")
    void parserExpoeKid() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .keyId("key-abc")
                .subject("user-1")
                .compact();

        Jwt jwt = Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse(token);
        assertEquals("key-abc", jwt.getKeyId());
    }

    @Test
    @DisplayName("requireKeyId rejeita token com kid diferente")
    void requireKeyIdRejeita() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .keyId("key-certa")
                .compact();

        assertThrows(JwtException.class, () ->
                Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).requireKeyId("key-errada").parse(token)
        );
    }

    @Test
    @DisplayName("Parser expõe jti via getId()")
    void parserExpoeJti() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .id("meu-jti-custom")
                .compact();

        Jwt jwt = Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).parse(token);
        assertEquals("meu-jti-custom", jwt.getId());
    }

    @Test
    @DisplayName("requireIssuer rejeita issuer diferente")
    void requireIssuer() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .issuer("https://idp.example.com")
                .compact();

        assertThrows(JwtException.class, () ->
                Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).requireIssuer("https://outro.com").parse(token)
        );
        // Com o issuer certo, passa
        Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).requireIssuer("https://idp.example.com").parse(token);
    }

    @Test
    @DisplayName("requireAudience aceita aud como string")
    void requireAudienceString() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .audience("minha-api")
                .compact();

        Jwt jwt = Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).requireAudience("minha-api").parse(token);
        assertEquals(java.util.List.of("minha-api"), jwt.getAudiences());
    }

    @Test
    @DisplayName("requireAudience aceita aud como array")
    void requireAudienceArray() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .claim("aud", java.util.List.of("api-a", "api-b"))
                .compact();

        Jwt jwt = Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).requireAudience("api-b").parse(token);
        assertEquals(2, jwt.getAudiences().size());
    }

    @Test
    @DisplayName("requireAudience rejeita quando nenhuma bate")
    void requireAudienceRejeita() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .audience("minha-api")
                .compact();

        assertThrows(JwtException.class, () ->
                Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).requireAudience("outra-api").parse(token)
        );
    }

    @Test
    @DisplayName("requireType valida typ do header")
    void requireType() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac(SECRET))
                .compact(); // typ padrão é "JWT"

        Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).requireType("JWT").parse(token);
        assertThrows(JwtException.class, () ->
                Jwts.parser().verifyWith(TestKeys.hmac(SECRET)).requireType("at+jwt").parse(token)
        );
    }

    @Test
    @DisplayName("keyProvider resolve chave por kid")
    void keyProviderPorKid() {
        // Mapa de kid → SecretKey (não String!)
        var chaves = java.util.Map.of(
                "key-1", TestKeys.hmac("chave-da-key-1-com-32-bytes!!!"),
                "key-2", TestKeys.hmac("chave-da-key-2-com-32-bytes!!!")
        );

        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(chaves.get("key-2"))   // já é SecretKey
                .keyId("key-2")
                .subject("user-1")
                .compact();

        // KeyProvider retorna Key (aqui, SecretKey é um Key)
        KeyProvider provider = header -> chaves.get((String) header.get("kid"));

        Jwt jwt = Jwts.parser()
                .keyProvider(provider)
                .parse(token);

        assertEquals("user-1", jwt.getSubject());
        assertEquals("key-2",  jwt.getKeyId());
    }

    @Test
    @DisplayName("keyProvider que não encontra a chave lança exceção")
    void keyProviderChaveAusente() {
        String token = Jwts.builder()
                .alg(Algorithm.HS256)
                .signWith(TestKeys.hmac("qualquer-coisa-com-32-bytes-aqui!!!"))
                .keyId("key-inexistente")
                .compact();

        KeyProvider provider = header -> {
            throw new JwtException("Chave não encontrada: " + header.get("kid"));
        };

        assertThrows(JwtException.class, () ->
                Jwts.parser().keyProvider(provider).parse(token)
        );
    }

}