package com.github.bapadua.labs.jwt;

import com.github.bapadua.labs.jwt.internal.jwk.Jwk;
import com.github.bapadua.labs.jwt.internal.jwk.JwkRsaConverter;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Debug {
    static void main() throws NoSuchAlgorithmException {
        // Em um main temporário ou num teste marcado @Disabled por padrão

// 1. Gera par RSA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

// 2. Converte a pública em JWK
        Jwk jwk = JwkRsaConverter.toJwk(
                (RSAPublicKey) kp.getPublic(),
                "key-01", "sig", "RS256"
        );

// 3. Imprime o JWK (é isto que vai para o JWKS endpoint)
        System.out.println(jwk.toJson());

// 4. Assina um token JWT com a privada (usando nossa lib)
        String token = Jwts.builder()
                .alg(Algorithm.RS256)
                .signWith((PrivateKey) kp.getPrivate())
                .keyId("key-01")
                .subject("user-1")
                .compact();

        System.out.println(token);
    }
}
