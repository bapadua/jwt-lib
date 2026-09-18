package com.github.bapadua.labs.jwt.internal.jwk.http;

import com.github.bapadua.labs.jwt.JwtException;
import com.github.bapadua.labs.jwt.internal.jwk.Jwks;
import com.github.bapadua.labs.jwt.internal.jwk.JwksFetcher;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * {@link JwksFetcher} que busca o JWKS via HTTP(S).
 *
 * <p>Usa {@link java.net.http.HttpClient} (JDK 11+), não o legado
 * {@code HttpURLConnection}. Vantagens:
 * <ul>
 *   <li>Suporte nativo a HTTP/2</li>
 *   <li>Timeouts configuráveis por requisição</li>
 *   <li>API imutável e thread-safe</li>
 *   <li>Melhor comportamento com TLS moderno</li>
 * </ul>
 *
 * <p><b>Timeout:</b> sempre configure um. Um endpoint JWKS que não responde
 * deve falhar rápido, não pendurar a thread de validação de token.
 */
public final class HttpJwksFetcher implements JwksFetcher {

    private final URI uri;
    private final HttpClient client;
    private final Duration requestTimeout;

    private HttpJwksFetcher(URI uri, HttpClient client, Duration requestTimeout) {
        this.uri = uri;
        this.client = client;
        this.requestTimeout = requestTimeout;
    }

    /**
     * Cria um fetcher HTTP com configurações padrão sensatas.
     */
    public static HttpJwksFetcher of(String url) {
        return of(url, Duration.ofSeconds(5), Duration.ofSeconds(5));
    }

    /**
     * Cria um fetcher HTTP customizado.
     *
     * @param url             URL do endpoint JWKS
     * @param connectTimeout  timeout de conexão
     * @param requestTimeout  timeout total da requisição
     */
    public static HttpJwksFetcher of(String url,
                                     Duration connectTimeout,
                                     Duration requestTimeout) {
        if (url == null || url.isBlank()) {
            throw new JwtException("URL do JWKS não pode ser vazia");
        }

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        return new HttpJwksFetcher(URI.create(url), client, requestTimeout);
    }

    @Override
    public Jwks fetch() {
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(requestTimeout)
                .header("Accept", "application/json")
                .GET()
                .build();

        try {
            HttpResponse<String> response = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );

            if (response.statusCode() != 200) {
                throw new JwtException(
                        "JWKS fetch falhou: HTTP " + response.statusCode()
                                + " em " + uri
                );
            }

            return Jwks.fromJson(response.body());

        } catch (JwtException e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new JwtException("JWKS fetch interrompido", e);
        } catch (Exception e) {
            throw new JwtException("Falha ao buscar JWKS em " + uri, e);
        }
    }
}