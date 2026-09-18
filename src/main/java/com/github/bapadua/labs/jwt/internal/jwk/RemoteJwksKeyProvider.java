package com.github.bapadua.labs.jwt.internal.jwk;

import com.github.bapadua.labs.jwt.JwtException;
import com.github.bapadua.labs.jwt.KeyProvider;

import java.security.Key;
import java.time.Duration;
import java.util.Map;

/**
 * {@link KeyProvider} que resolve chaves a partir de um JWKS remoto.
 *
 * <p><b>Ciclo de operação:</b>
 * <ol>
 *   <li>Recebe o header do token, extrai o {@code kid}.</li>
 *   <li>Consulta o cache em memória.</li>
 *   <li>Se a chave não está ou o cache expirou, refaz o fetch via
 *       {@link JwksFetcher}.</li>
 *   <li>Busca a chave pelo {@code kid} no JWKS atualizado.</li>
 *   <li>Converte o {@link Jwk} em {@link java.security.Key} (RSAPublicKey).</li>
 * </ol>
 *
 * <p><b>Thread safety:</b> o cache é protegido por um lock dedicado.
 * Múltiplas threads podem ler em paralelo; o fetch é serializado para
 * evitar thundering herd (N threads disparando N requests simultâneas).
 *
 * <p><b>Refresh-on-miss:</b> quando o {@code kid} não é encontrado no
 * cache atual, o provider faz <b>um</b> re-fetch antes de falhar. Isso
 * é essencial para rotação de chaves: o IdP pode ter assinado um token
 * com uma chave nova antes do cache local expirar.
 *
 * <p><b>Cache negativo:</b> se o fetch falha (rede, HTTP error), <b>não</b>
 * armazenamos o erro. A próxima chamada tenta de novo. Em contrapartida,
 * uma falha em refresh-on-miss também não invalida o cache existente.
 */
public final class RemoteJwksKeyProvider implements KeyProvider {

    private static final Duration DEFAULT_TTL = Duration.ofMinutes(5);

    private final JwksFetcher fetcher;
    private final Duration ttl;

    // Estado interno protegido por "lock"
    private final Object lock = new Object();
    private volatile Jwks cached;
    private volatile long expiresAtMillis;

    private RemoteJwksKeyProvider(JwksFetcher fetcher, Duration ttl) {
        this.fetcher = fetcher;
        this.ttl = ttl;
    }

    /**
     * Cria um provider com TTL padrão (5 minutos).
     */
    public static RemoteJwksKeyProvider of(JwksFetcher fetcher) {
        return of(fetcher, DEFAULT_TTL);
    }

    /**
     * Cria um provider com TTL customizado.
     */
    public static RemoteJwksKeyProvider of(JwksFetcher fetcher, Duration ttl) {
        if (fetcher == null) throw new JwtException("JwksFetcher não pode ser nulo");
        if (ttl == null || ttl.isNegative() || ttl.isZero()) {
            throw new JwtException("TTL deve ser positivo");
        }
        return new RemoteJwksKeyProvider(fetcher, ttl);
    }

    @Override
    public Key getKey(Map<String, Object> header) {
        Object kidNode = header.get("kid");
        if (!(kidNode instanceof String kid) || kid.isBlank()) {
            throw new JwtException("Header do token sem 'kid'");
        }

        Jwk jwk = findInCache(kid);

        if (jwk == null) {
            // kid novo — pode ser rotação. Força fetch uma vez.
            Jwks fresh = forceRefresh();
            jwk = fresh.findByKid(kid)
                    .orElseThrow(() -> new JwtException(
                            "Chave não encontrada no JWKS: kid=" + kid
                    ));
        }

        return toJavaKey(jwk);
    }

    /**
     * Consulta o cache. Se expirado, dispara refresh e reconsulta.
     */
    private Jwk findInCache(String kid) {
        Jwks current = cached;
        if (current == null) return null;

        // Se o cache expirou, renova respeitando TTL
        if (System.currentTimeMillis() >= expiresAtMillis) {
            current = refreshIfExpired();
        }

        return current.findByKid(kid).orElse(null);
    }

    /**
     * Refaz o fetch do JWKS, respeitando o lock para evitar thundering herd.
     *
     * <p>Double-checked locking: várias threads podem ver o cache "vazio"
     * simultaneamente e tentar refresh. A primeira adquire o lock e faz o
     * fetch; as demais entram depois e veem que o cache já foi atualizado,
     * então retornam o valor atual.
     */
    private Jwks refresh() {
        synchronized (lock) {
            // Alguém pode ter feito o refresh enquanto esperávamos o lock
            long now = System.currentTimeMillis();
            if (cached != null && now < expiresAtMillis) {
                return cached;
            }

            Jwks fresh = fetcher.fetch();
            this.cached = fresh;
            this.expiresAtMillis = now + ttl.toMillis();
            return fresh;
        }
    }

    /**
     * Refaz o fetch respeitando TTL. Se o cache ainda é válido, devolve-o
     * sem chamar o fetcher. Usado quando o cache expirou.
     */
    private Jwks refreshIfExpired() {
        synchronized (lock) {
            long now = System.currentTimeMillis();
            if (cached != null && now < expiresAtMillis) {
                return cached;
            }
            return doFetch(now);
        }
    }

    /**
     * Força um fetch, ignorando TTL. Usado em refresh-on-miss: quando um
     * kid não está no cache, é provável que o IdP tenha rotacionado. Um
     * fetch forçado resolve em uma única tentativa.
     */
    private Jwks forceRefresh() {
        synchronized (lock) {
            return doFetch(System.currentTimeMillis());
        }
    }

    private Jwks doFetch(long now) {
        Jwks fresh = fetcher.fetch();
        this.cached = fresh;
        this.expiresAtMillis = now + ttl.toMillis();
        return fresh;
    }

    /**
     * Converte um Jwk em uma chave java.security apropriada para verificação.
     *
     * <p>Hoje só suporta RSA. EC virá quando ES256 for implementado.
     */
    private Key toJavaKey(Jwk jwk) {
        return switch (jwk.kty()) {
            case "RSA" -> JwkRsaConverter.toPublicKey(jwk);
            default -> throw new JwtException(
                    "Tipo de chave não suportado: " + jwk.kty()
            );
        };
    }

    /**
     * Força um refresh imediato, ignorando TTL. Útil em administração
     * ou testes.
     */
    public void invalidate() {
        synchronized (lock) {
            this.cached = null;
            this.expiresAtMillis = 0;
        }
    }
}