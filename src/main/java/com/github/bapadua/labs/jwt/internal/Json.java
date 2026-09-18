package com.github.bapadua.labs.jwt.internal;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Fachada interna sobre o Jackson.
 *
 * <p>Centraliza a configuração do {@link ObjectMapper} e garante:
 * <ul>
 *   <li><b>Uma única instância</b> em toda a JVM — evita a criação
 *       repetida de um objeto notoriamente pesado.</li>
 *   <li><b>Determinismo de saída</b> — a ordem de inserção das chaves
 *       em um {@link LinkedHashMap} é preservada na serialização. Isso
 *       é obrigatório para JWT, pois a assinatura é calculada sobre os
 *       bytes exatos do JSON resultante.</li>
 *   <li><b>Sem falha em campos desconhecidos</b> — ao desserializar
 *       tokens de terceiros, não queremos explodir só porque veio
 *       um claim que não conhecemos.</li>
 * </ul>
 *
 * <p>Esta classe é <b>puramente interna</b>. Não faz parte da API
 * pública da lib.
 *
 *  * <p><b>Sobre tipos numéricos:</b> JSON não tem tipos — apenas "número".
 *  * Ao desserializar para {@code Map<String, Object>}, o Jackson escolhe o
 *  * tipo Java que melhor se encaixa em cada valor: {@code Integer} para
 *  * inteiros que cabem em 32 bits, {@code Long} para valores maiores, e
 *  * {@code Double} para decimais.
 *  *
 *  * <p>Isso significa que <b>nunca devemos assumir o tipo concreto</b> de
 *  * um claim numérico. A API pública da lib deve sempre ler via
 *  * {@link Number} e converter (ex.: {@code ((Number) v).longValue()}).
 */
public final class Json {


    /**
     * Instância única e thread-safe do ObjectMapper.
     *
     * <p>O Jackson é thread-safe após configuração. Todos os
     * {@code configure(...)} e {@code disable(...)} são aplicados
     * no bloco {@code static} abaixo, antes da primeira leitura
     * concorrente.
     */
    private static final ObjectMapper MAPPER = createMapper();

    /**
     * TypeReference que descreve "Map de String para Object,
     * preservando ordem de inserção".
     *
     * <p>Declarado como constante para evitar realocação a cada
     * chamada de {@link #parse(String)}. Jackons usa essa referência
     * para inferir os tipos genéricos em tempo de execução.
     */
    private static final TypeReference<LinkedHashMap<String, Object>> MAP_TYPE =
            new TypeReference<>() {};

    private Json(){
        //Classe utilitaria
    }

    private static ObjectMapper createMapper() {
        ObjectMapper mapper = new ObjectMapper();
        // Não queremos indentação ("pretty-print"). JWT é compacto por definição,
        // e cada byte extra aumenta o tamanho do token em toda request HTTP.
        mapper.disable(SerializationFeature.INDENT_OUTPUT);

        // Ao ler claims de tokens de terceiros, ignoramos campos que não
        // conhecemos em vez de falhar. Isso é essencial para interoperabilidade.
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

        // Não emitir timestamps como epoch; queremos controle explícito
        // sobre o formato de datas (vamos tratar `exp`/`iat` como números
        // puros, não como Date).
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        return mapper;
    }

    /**
     * Serializa um Map em JSON compacto.
     *
     * <p><b>Ordem importa:</b> use {@link LinkedHashMap} para garantir
     * que a ordem das chaves seja preservada. Se um {@link java.util.HashMap}
     * for passado, a ordem é indeterminada e a assinatura do JWT
     * resultante será imprevisível.
     *
     * @param map dados a serializar (nunca {@code null})
     * @return JSON compacto em UTF-8
     * @throws IllegalStateException se a serialização falhar (não deveria
     *         acontecer com Map de tipos primitivos; envolve a checked
     *         {@code JsonProcessingException} em runtime)
     */
    public static String stringify(Map<String, Object> map) {
        try {
            return MAPPER.writeValueAsString(map);
        } catch (Exception e) {
            // writeValueAsString só lança se houver um problema estrutural
            // (ex.: ciclo em grafos). Com Map<String, Object> primitivos,
            // isso não deveria ocorrer. Se ocorrer, é bug nosso — falha rápida.
            throw new IllegalStateException("Falha ao serializar JSON", e);
        }
    }

    /**
     * Desserializa um JSON em Map preservando ordem de inserção.
     *
     * <p>Retorna {@link LinkedHashMap} porque a ordem importa para JWT
     * (a assinatura é sobre bytes exatos).
     *
     * @param json string JSON (nunca {@code null})
     * @return mapa com os campos em ordem de inserção original
     * @throws IllegalArgumentException se o JSON for inválido
     */
    public static LinkedHashMap<String, Object> parse(String json) {
        try {
            return MAPPER.readValue(json, MAP_TYPE);
        } catch (Exception e) {
            throw new IllegalArgumentException("JSON inválido: " + e.getMessage(), e);
        }
    }
}
