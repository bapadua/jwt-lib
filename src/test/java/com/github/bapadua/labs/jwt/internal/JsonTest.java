package com.github.bapadua.labs.jwt.internal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JsonTest {

    @Test
    @DisplayName("Serializa Map em JSON compacto (sem espaços)")
    void serializaCompacto() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("alg", "HS256");
        map.put("typ", "JWT");

        assertEquals("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", Json.stringify(map));
    }

    @Test
    @DisplayName("Preserva ordem de inserção das chaves")
    void preservaOrdem() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("z", 1);
        map.put("a", 2);
        map.put("m", 3);

        String json = Json.stringify(map);
        assertEquals("{\"z\":1,\"a\":2,\"m\":3}", json);
    }

    @Test
    @DisplayName("Desserializa JSON em LinkedHashMap")
    void desserializaParaLinkedHashMap() {
        Map<String, Object> original = new LinkedHashMap<>();
        original.put("sub", "user-1");
        original.put("exp", 1234567890L);
        original.put("admin", true);

        String json = Json.stringify(original);
        var parsed = Json.parse(json);

        assertInstanceOf(LinkedHashMap.class, parsed);
        assertEquals("user-1", parsed.get("sub"));
        assertEquals(Boolean.TRUE, parsed.get("admin"));

        // NÃO assumimos Long nem Integer — lemos como Number e comparamos
        // o valor numérico. Isso é o que um consumidor real de JWT precisa fazer.
        assertInstanceOf(Number.class, parsed.get("exp"));
        assertEquals(1234567890L, ((Number) parsed.get("exp")).longValue());
    }

    @Test
    @DisplayName("Jackson escolhe Integer para inteiros pequenos, Long para grandes")
    void jacksonEscolheTipoNumerico() {
        var parsed = Json.parse("""
            {"pequeno": 42, "grande": 99999999999, "decimal": 3.14}
            """);

        // 42 cabe em int -> Integer
        assertInstanceOf(Integer.class, parsed.get("pequeno"));

        // 99999999999 não cabe em int -> Long
        assertInstanceOf(Long.class, parsed.get("grande"));

        // Decimal -> Double
        assertInstanceOf(Double.class, parsed.get("decimal"));
    }

    @Test
    @DisplayName("Preserva valores null em claims (não remove a chave)")
    void preservaNulls() {
        // Importante: `null` é um valor válido de claim? A RFC 7519 não proíbe,
        // mas algumas libs omitem. Nós mantemos a semântica explícita:
        // se o usuário colocou a chave, ela vai no token.
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("foo", null);

        assertEquals("{\"foo\":null}", Json.stringify(map));
    }

    @Test
    @DisplayName("Lança IllegalArgumentException em JSON inválido")
    void falhaEmJsonInvalido() {
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{nao é json"));
    }
}