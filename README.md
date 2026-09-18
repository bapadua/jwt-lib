# 🛡️ jwt-lib

> Uma biblioteca Java moderna, leve, ultra-segura e focada nas RFCs para criação, assinatura e validação de JSON Web Tokens (JWT) e JSON Web Key Sets (JWKS).

[![Java Version](https://img.shields.io/badge/Java-25%2B-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Maven Central](https://img.shields.io/badge/Maven%20Central-1.0.0-4c1?style=for-the-badge&logo=apache-maven&logoColor=white)](https://central.sonatype.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/Tests-110%20Passed-brightgreen?style=for-the-badge&logo=junit5&logoColor=white)](#-testes--qualidade)
[![RFC Compliant](https://img.shields.io/badge/RFC-7515%20%7C%207517%20%7C%207518%20%7C%207519-informational?style=for-the-badge)](#-conformidade-com-rfcs)

---

## 🌟 Por que escolher a `jwt-lib`?

Muitas bibliotecas JWT do ecossistema Java trazem dependências pesadas, APIs legadas pré-Java 8 ou brechas de segurança históricas (como aceitar `alg=none`, confusão de algoritmo HMAC/RSA ou aceitar chaves como meras Strings).

A **`jwt-lib`** foi projetada do zero com foco em:

- 🔒 **Segurança por Padrão (Security-by-Design)**:
  - Imune ao ataque de *Algorithm Confusion*: API fortemente tipada (`SecretKey` vs `PrivateKey`/`PublicKey`).
  - Rejeição irrestrita de `alg=none`.
  - Comparação de assinaturas em tempo constante (*constant-time*) via `MessageDigest.isEqual` contra *timing attacks*.
  - *Algorithm Pinning* no parser para restringir estritamente quais algoritmos seu serviço aceita.
  - Interfaces seladas (`sealed interface`) para blindar os signers criptográficos internos contra injeções.
- ⚡ **Zero Bloat & Dependências Mínimas**:
  - Utiliza o motor criptográfico padrão da JVM (`java.security`, `javax.crypto`).
  - Utiliza o moderno `java.net.http.HttpClient` do JDK para requisições JWKS HTTP/2.
  - Única dependência externa de runtime: Jackson Databind.
- 🌐 **Suporte Nativo a JWK & JWKS Remoto**:
  - Cache em memória com TTL configurável e proteção contra *thundering herd* (concorrência protegida).
  - Mecanismo inteligente de **Refresh-on-Miss** para suporte transparente a rotação de chaves em IdPs (Keycloak, Auth0, Cognito, Okta).
- 🧩 **API Fluente & Ergonômica**:
  - Ponto de entrada unificado via `Jwts.builder()` e `Jwts.parser()`.
  - Objetos `Jwt` imutáveis pós-validação, com *defensive copies* de arrays e coleções.
  - Normalização inteligente de claims (`exp`, `iat`, `nbf`, `aud` como String ou List).

---

## 📋 Sumário

- [Conformidade com RFCs](#-conformidade-com-rfcs)
- [Instalação](#-instalação)
  - [Coordenadas do Artefato](#coordenadas-do-artefato)
  - [Instalação via Maven (pom.xml)](#instalação-via-maven-pomxml)
  - [Instalação via Gradle](#instalação-via-gradle)
- [Algoritmos Suportados](#-algoritmos-suportados)
- [Guia Rápido](#-guia-rápido)
  - [1. Assinatura Simétrica (HMAC - HS256)](#1-assinatura-simétrica-hmac---hs256)
  - [2. Assinatura Assimétrica (RSA - RS256)](#2-assinatura-assimétrica-rsa---rs256)
  - [3. Validação com JWKS Remoto (Keycloak / Auth0 / OIDC)](#3-validação-com-jwks-remoto-keycloak--auth0--oidc)
- [Recursos de Segurança & Validações](#-recursos-de-segurança--validações)
  - [Algorithm Pinning](#algorithm-pinning)
  - [Validações de Claims (Issuer, Audience, Type, Key ID)](#validações-de-claims)
  - [Tolerância a Clock Skew](#tolerância-a-clock-skew)
- [Manipulação de JWK & JWKS](#-manipulação-de-jwk--jwks)
- [Arquitetura Interna](#-arquitetura-interna)
- [Testes & Qualidade](#-testes--qualidade)
- [Licença & Autor](#-licença--autor)

---

## 📜 Conformidade com RFCs

A biblioteca implementa estritamente os padrões IETF:

| RFC | Título | Cobertura |
| :--- | :--- | :--- |
| **[RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)** | JSON Web Signature (JWS) | Compact Serialization, Header parsing, verificação e assinatura digital |
| **[RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)** | JSON Web Key (JWK) | Modelagem de JWK, JWK Sets (JWKS), serialização JSON e conversões JCA |
| **[RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)** | JSON Web Algorithms (JWA) | Criptografia HS256/384/512, RS256/384/512 e codificação `Base64UInt` |
| **[RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)** | JSON Web Token (JWT) | Claims registrados (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) |

---

## 📦 Instalação

### Coordenadas do Artefato

| Artefato | Group ID | Versão |
| :--- | :--- | :--- |
| **`jwt-lib`** | **`io.github.bapadua`** | **`1.0.0`** |

---

### Instalação via Maven (`pom.xml`)

Adicione o bloco abaixo dentro da tag `<dependencies>` do seu arquivo `pom.xml`:

```xml
<dependencies>
    <!-- JWT Library -->
    <dependency>
        <groupId>io.github.bapadua</groupId>
        <artifactId>jwt-lib</artifactId>
        <version>1.0.0</version>
    </dependency>
</dependencies>
```

Se desejar fixar a versão via `<properties>`:

```xml
<properties>
    <jwt-lib.version>1.0.0</jwt-lib.version>
</properties>

<dependencies>
    <dependency>
        <groupId>io.github.bapadua</groupId>
        <artifactId>jwt-lib</artifactId>
        <version>${jwt-lib.version}</version>
    </dependency>
</dependencies>
```

---

### Instalação via Gradle

#### Groovy DSL (`build.gradle`)
```groovy
dependencies {
    implementation 'io.github.bapadua:jwt-lib:1.0.0'
}
```

#### Kotlin DSL (`build.gradle.kts`)
```kotlin
dependencies {
    implementation("io.github.bapadua:jwt-lib:1.0.0")
}
```

---

## 🔐 Algoritmos Suportados

| Algoritmo | Família | Tipo de Chave | Classe Java Requerida |
| :--- | :--- | :--- | :--- |
| `HS256` | HMAC com SHA-256 | Simétrica | `javax.crypto.SecretKey` |
| `HS384` | HMAC com SHA-384 | Simétrica | `javax.crypto.SecretKey` |
| `HS512` | HMAC com SHA-512 | Simétrica | `javax.crypto.SecretKey` |
| `RS256` | RSASSA-PKCS1-v1_5 com SHA-256 | Assimétrica | `PrivateKey` (assinar) / `PublicKey` (verificar) |
| `RS384` | RSASSA-PKCS1-v1_5 com SHA-384 | Assimétrica | `PrivateKey` (assinar) / `PublicKey` (verificar) |
| `RS512` | RSASSA-PKCS1-v1_5 com SHA-512 | Assimétrica | `PrivateKey` (assinar) / `PublicKey` (verificar) |

---

## 🚀 Guia Rápido

### 1. Assinatura Simétrica (HMAC - HS256)

```java
import com.github.bapadua.labs.jwt.Algorithm;
import com.github.bapadua.labs.jwt.Jwt;
import com.github.bapadua.labs.jwt.Jwts;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

// 1. Defina sua chave secreta
SecretKeySpec secretKey = new SecretKeySpec(
    "sua-chave-secreta-super-segura-com-pelo-menos-256-bits!".getBytes(StandardCharsets.UTF_8),
    "HmacSHA256"
);

// 2. Gere o token
String token = Jwts.builder()
    .alg(Algorithm.HS256)
    .signWith(secretKey)
    .subject("user-12345")
    .issuer("https://auth.meudominio.com")
    .audience("api://minha-api")
    .issuedNow()
    .expiresInSeconds(3600) // 1 hora
    .id() // Gera UUID v4 automático para jti
    .claim("role", "ADMIN")
    .claim("email", "usuario@dominio.com")
    .compact();

// 3. Valide e leia os claims
Jwt jwt = Jwts.parser()
    .verifyWith(secretKey)
    .requireAlgorithm(Algorithm.HS256)
    .requireIssuer("https://auth.meudominio.com")
    .requireAudience("api://minha-api")
    .parse(token);

System.out.println("Subject: " + jwt.getSubject());
System.out.println("Role: " + jwt.getStringClaim("role"));
System.out.println("Token ID (jti): " + jwt.getId());
```

---

### 2. Assinatura Assimétrica (RSA - RS256)

```java
import com.github.bapadua.labs.jwt.Algorithm;
import com.github.bapadua.labs.jwt.Jwt;
import com.github.bapadua.labs.jwt.Jwts;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

// Gerando par de chaves RSA (2048+ bits)
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(2048);
KeyPair keyPair = kpg.generateKeyPair();

// Emissor: Assina com Chave Privada
String token = Jwts.builder()
    .alg(Algorithm.RS256)
    .signWith(keyPair.getPrivate())
    .keyId("auth-key-2026-01")
    .subject("usuario-corporativo")
    .expiresInSeconds(1800)
    .compact();

// Consumidor/API: Valida com Chave Pública
Jwt jwt = Jwts.parser()
    .verifyWith(keyPair.getPublic())
    .requireAlgorithm(Algorithm.RS256)
    .requireKeyId("auth-key-2026-01")
    .parse(token);

System.out.println("Validado com sucesso para: " + jwt.getSubject());
```

---

### 3. Validação com JWKS Remoto (Keycloak / Auth0 / OIDC)

Ideal para APIs e Microsserviços que validam tokens emitidos por Identity Providers externos via `/.well-known/jwks.json`.

```java
import com.github.bapadua.labs.jwt.Algorithm;
import com.github.bapadua.labs.jwt.Jwt;
import com.github.bapadua.labs.jwt.Jwts;
import com.github.bapadua.labs.jwt.internal.jwk.RemoteJwksKeyProvider;
import com.github.bapadua.labs.jwt.internal.jwk.http.HttpJwksFetcher;
import java.time.Duration;

// 1. Configure o fetcher HTTP com timeouts
HttpJwksFetcher fetcher = HttpJwksFetcher.of(
    "https://auth.meudominio.com/realms/master/protocol/openid-connect/certs",
    Duration.ofSeconds(3), // Timeout de conexão
    Duration.ofSeconds(5)  // Timeout de leitura
);

// 2. Crie o provedor com cache e rotação automática de chaves (TTL 10 min)
RemoteJwksKeyProvider keyProvider = RemoteJwksKeyProvider.of(fetcher, Duration.ofMinutes(10));

// 3. Valide o token usando a chave pública resolvida automaticamente pelo 'kid'
Jwt jwt = Jwts.parser()
    .keyProvider(keyProvider)
    .requireAlgorithm(Algorithm.RS256)
    .requireIssuer("https://auth.meudominio.com/realms/master")
    .requireAudience("minha-api")
    .clockSkewSeconds(60) // 1 minuto de tolerância
    .parse(tokenRecebido);

System.out.println("Usuário autenticado via JWKS: " + jwt.getSubject());
```

---

## 🛡️ Recursos de Segurança & Validações

### Algorithm Pinning
Evita ataques onde o invasor forja um token alterando o header para um algoritmo mais fraco:

```java
parser.requireAlgorithm(Algorithm.RS256); // Rejeita qualquer outro algoritmo
```

### Validações de Claims
Valide expectativas diretamente no processo de parsing:

```java
Jwts.parser()
    .verifyWith(publicKey)
    .requireIssuer("https://auth.exemplo.com")   // Valida 'iss'
    .requireAudience("api-faturamento", "api-gateway") // Valida 'aud'
    .requireType("JWT")                          // Valida 'typ' no header (RFC 9068 / RFC 7519)
    .requireKeyId("key-2026-v1")                 // Valida 'kid' no header
    .parse(token);
```

### Tolerância a Clock Skew
Compensa pequenas diferenças de horário entre servidores distribuídos:

```java
Jwts.parser()
    .clockSkewSeconds(30) // Tolera até 30 segundos de atraso/adiantamento em exp e nbf
    .parse(token);
```

---

## 🔑 Manipulação de JWK & JWKS

A biblioteca inclui utilitários para criar e converter chaves criptográficas em formato JWK (RFC 7517/7518):

```java
import com.github.bapadua.labs.jwt.internal.jwk.Jwk;
import com.github.bapadua.labs.jwt.internal.jwk.Jwks;
import com.github.bapadua.labs.jwt.internal.jwk.JwkRsaConverter;
import java.security.interfaces.RSAPublicKey;

// Converte RSAPublicKey em JWK
Jwk jwk = JwkRsaConverter.toJwk((RSAPublicKey) keyPair.getPublic(), "key-01", "sig", "RS256");

// Exporta JWKS JSON para expor no endpoint /.well-known/jwks.json
Jwks jwks = Jwks.of(jwk);
String jwksJson = jwks.toJson();
// {"keys":[{"kty":"RSA","kid":"key-01","use":"sig","alg":"RS256","n":"...","e":"AQAB"}]}
```

---

## 🏗️ Arquitetura Interna

```
com.github.bapadua.labs.jwt
├── Jwts.java                   # Facade principal (builder() / parser())
├── Jwt.java                    # Modelo imutável do token decodificado
├── JwtBuilder.java             # Fluent builder para criação e assinatura
├── JwtParser.java              # Validador e parser com pipeline de segurança
├── Algorithm.java              # Enum de algoritmos com tipagem forte
├── KeyProvider.java            # Interface funcional para resolução dinâmica de chaves
├── JwtException.java           # Exceção raiz para falhas de validação/parse
└── internal
    ├── Signer.java             # Sealed interface para motores de assinatura
    ├── Verifier.java           # Sealed interface para motores de verificação
    ├── HmacSigner.java         # Motor HMAC (HS256, HS384, HS512)
    ├── RsaSigner.java          # Motor RSA (RS256, RS384, RS512)
    ├── Json.java               # Wrapper Jackson isolado
    ├── Base64Url.java          # Encoder/Decoder URL-safe sem padding (RFC 7515)
    └── jwk
        ├── Jwk.java            # Modelo imutável de JSON Web Key
        ├── Jwks.java           # Modelo de JSON Web Key Set
        ├── JwkRsaConverter.java# Conversor bidirecional RSA <-> JWK
        ├── Base64UInt.java     # Manipulador de inteiros não-assinados (RFC 7518)
        ├── RemoteJwksKeyProvider.java # Provider com cache e refresh-on-miss
        └── http
            └── HttpJwksFetcher.java   # Fetcher HTTP/2 baseado em java.net.http
```

---

## 🧪 Testes & Qualidade

A biblioteca possui uma suíte completa de testes unitários e de integração utilizando JUnit 5:

```bash
mvn test
```

- **110 testes automatizados** cobrindo:
  - Assinatura e verificação de todos os algoritmos suportados.
  - Ataques de *Algorithm Confusion* e tokens adulterados.
  - Expiração de tokens, tolerâncias de *clock skew* e validação de `nbf`.
  - Serialização e conversão de chaves JWK/JWKS e conformidade `Base64UInt`.
  - Concorrência de cache, expiração de TTL e *refresh-on-miss* do `RemoteJwksKeyProvider`.

---

## 📄 Licença & Autor

Distribuído sob a licença **Apache License 2.0**. Consulte o arquivo [pom.xml](pom.xml) para detalhes legais.

- **Autor**: Bruno A. Padua ([@bapadua](https://github.com/bapadua))
- **Contato**: bapadua.cloud@gmail.com
- **Repositório**: [github.com/bapadua/jwt-lib](https://github.com/bapadua/jwt-lib)
