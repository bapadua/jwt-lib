package com.github.bapadua.labs.jwt.internal.jwk;

import com.github.bapadua.labs.jwt.JwtException;
import com.github.bapadua.labs.jwt.internal.jwk.http.HttpJwksFetcher;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class RemoteJwksKeyProviderTest {

    private HttpServer server;
    private String jwksUrl;
    private AtomicInteger fetchCount;
    private AtomicReference<String> currentBody;

    private RSAPublicKey publicKey;

    @BeforeEach
    void setup() throws Exception {
        // Gera par RSA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        publicKey = (RSAPublicKey) kp.getPublic();

        // Prepara JWKS com a chave pública
        Jwk jwk = JwkRsaConverter.toJwk(publicKey, "key-01", "sig", "RS256");
        currentBody = new AtomicReference<>(Jwks.of(jwk).toJson());

        // Servidor HTTP em memória
        fetchCount = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/jwks.json", exchange -> {
            fetchCount.incrementAndGet();
            byte[] body = currentBody.get().getBytes();
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();

        jwksUrl = "http://localhost:" + server.getAddress().getPort() + "/jwks.json";
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    @DisplayName("Busca JWKS e resolve chave por kid")
    void resolvePorKid() {
        RemoteJwksKeyProvider provider = RemoteJwksKeyProvider.of(
                HttpJwksFetcher.of(jwksUrl)
        );

        Key key = provider.getKey(Map.of("kid", "key-01"));

        assertNotNull(key);
        assertEquals(publicKey, key);
        assertEquals(1, fetchCount.get());
    }

    @Test
    @DisplayName("Segunda chamada usa cache, não refaz fetch")
    void cacheHit() {
        RemoteJwksKeyProvider provider = RemoteJwksKeyProvider.of(
                HttpJwksFetcher.of(jwksUrl)
        );

        provider.getKey(Map.of("kid", "key-01"));
        provider.getKey(Map.of("kid", "key-01"));
        provider.getKey(Map.of("kid", "key-01"));

        assertEquals(1, fetchCount.get(), "Deve ter feito apenas 1 fetch");
    }

    @Test
    @DisplayName("refresh-on-miss: kid novo dispara novo fetch")
    void refreshOnMiss() throws Exception {
        RemoteJwksKeyProvider provider = RemoteJwksKeyProvider.of(
                HttpJwksFetcher.of(jwksUrl)
        );

        // Primeira chave
        provider.getKey(Map.of("kid", "key-01"));
        assertEquals(1, fetchCount.get());

        // Adiciona uma nova chave ao servidor (simula rotação)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        RSAPublicKey outraPub = (RSAPublicKey) kpg.generateKeyPair().getPublic();

        Jwk jwk1 = JwkRsaConverter.toJwk(publicKey, "key-01", "sig", "RS256");
        Jwk jwk2 = JwkRsaConverter.toJwk(outraPub,   "key-02", "sig", "RS256");
        currentBody.set(Jwks.of(jwk1, jwk2).toJson());

        // Pede a nova chave — deve disparar refresh
        Key key = provider.getKey(Map.of("kid", "key-02"));
        assertEquals(outraPub, key);
        assertEquals(2, fetchCount.get());
    }

    @Test
    @DisplayName("kid desconhecido lança exceção após refresh")
    void kidDesconhecido() {
        RemoteJwksKeyProvider provider = RemoteJwksKeyProvider.of(
                HttpJwksFetcher.of(jwksUrl)
        );

        JwtException ex = assertThrows(JwtException.class, () ->
                provider.getKey(Map.of("kid", "key-inexistente"))
        );
        assertTrue(ex.getMessage().contains("key-inexistente"));
        // Deve ter tentado fetch pelo menos uma vez
        assertEquals(1, fetchCount.get());
    }

    @Test
    @DisplayName("Header sem kid lança exceção")
    void headerSemKid() {
        RemoteJwksKeyProvider provider = RemoteJwksKeyProvider.of(
                HttpJwksFetcher.of(jwksUrl)
        );

        assertThrows(JwtException.class, () -> provider.getKey(Map.of()));
        assertThrows(JwtException.class, () -> provider.getKey(Map.of("alg", "RS256")));
        assertEquals(0, fetchCount.get(), "Não deve fazer fetch se não há kid");
    }

    @Test
    @DisplayName("TTL expirado dispara novo fetch")
    void ttlExpirado() throws Exception {
        RemoteJwksKeyProvider provider = RemoteJwksKeyProvider.of(
                HttpJwksFetcher.of(jwksUrl),
                Duration.ofMillis(100)
        );

        provider.getKey(Map.of("kid", "key-01"));
        assertEquals(1, fetchCount.get());

        Thread.sleep(150);

        provider.getKey(Map.of("kid", "key-01"));
        assertEquals(2, fetchCount.get(), "TTL expirado deve refazer fetch");
    }

    @Test
    @DisplayName("invalidate() força novo fetch")
    void invalidateForcaFetch() {
        RemoteJwksKeyProvider provider = RemoteJwksKeyProvider.of(
                HttpJwksFetcher.of(jwksUrl)
        );

        provider.getKey(Map.of("kid", "key-01"));
        provider.invalidate();
        provider.getKey(Map.of("kid", "key-01"));

        assertEquals(2, fetchCount.get());
    }

    @Test
    @DisplayName("HTTP 500 no servidor lança exceção")
    void erroHttp() {
        server.removeContext("/jwks.json");
        server.createContext("/jwks.json", exchange -> {
            exchange.sendResponseHeaders(500, -1);
            exchange.close();
        });

        RemoteJwksKeyProvider provider = RemoteJwksKeyProvider.of(
                HttpJwksFetcher.of(jwksUrl)
        );

        JwtException ex = assertThrows(JwtException.class, () ->
                provider.getKey(Map.of("kid", "key-01"))
        );
        assertTrue(ex.getMessage().contains("500"));
    }

    @Test
    @DisplayName("Timeout de rede lança exceção")
    void timeout() {
        RemoteJwksKeyProvider provider = RemoteJwksKeyProvider.of(
                HttpJwksFetcher.of(
                        "http://10.255.255.1:9/jwks.json",   // endereço não roteável
                        Duration.ofMillis(200),
                        Duration.ofMillis(200)
                )
        );

        assertThrows(JwtException.class, () ->
                provider.getKey(Map.of("kid", "key-01"))
        );
    }
}