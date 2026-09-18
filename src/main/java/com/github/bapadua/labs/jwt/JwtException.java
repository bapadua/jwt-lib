package com.github.bapadua.labs.jwt;
/**
 * Exceção base para todos os erros da lib JWT.
 *
 * <p>É uma {@link RuntimeException} (unchecked) por escolha consciente:
 * o consumidor da lib não deveria ser obrigado a fazer try/catch
 * em torno de toda operação. Falhas de JWT são falhas de autenticação,
 * que tipicamente terminam em uma resposta 401 — não em recuperação
 * programática.
 *
 * <p>Estende {@link RuntimeException} e não {@link Exception} para
 * ficar alinhada com o que libs modernas de Java fazem (jjwt, nimbus).
 */
public class JwtException extends RuntimeException {
    public JwtException(String message) {
        super(message);
    }

    public JwtException(String message, Throwable cause) {
        super(message, cause);
    }
}
