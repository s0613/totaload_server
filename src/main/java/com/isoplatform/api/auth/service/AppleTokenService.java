package com.isoplatform.api.auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.isoplatform.api.auth.exception.InvalidCredentialsException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class AppleTokenService {

    private static final String APPLE_KEYS_URL = "https://appleid.apple.com/auth/keys";
    private static final String APPLE_ISSUER = "https://appleid.apple.com";

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${apple.client-id:com.totaload.app}")
    private String appleClientId;

    // 캐시: kid -> PublicKey (키 로테이션 대응)
    private final Map<String, PublicKey> publicKeyCache = new ConcurrentHashMap<>();
    private long lastKeyFetchTime = 0;
    private static final long KEY_CACHE_DURATION_MS = 24 * 60 * 60 * 1000; // 24시간

    /**
     * Apple Identity Token 검증 및 사용자 정보 추출
     */
    public AppleUserInfo verifyIdToken(String identityToken) {
        try {
            // 1. JWT 헤더에서 kid 추출
            String[] parts = identityToken.split("\\.");
            if (parts.length != 3) {
                throw new InvalidCredentialsException("Invalid token format");
            }

            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
            JsonNode header = objectMapper.readTree(headerJson);
            String kid = header.get("kid").asText();
            String alg = header.get("alg").asText();

            // 2. Apple 공개키 가져오기
            PublicKey publicKey = getApplePublicKey(kid);

            // 3. JWT 검증 및 파싱
            Claims claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .requireIssuer(APPLE_ISSUER)
                    .requireAudience(appleClientId)
                    .build()
                    .parseSignedClaims(identityToken)
                    .getPayload();

            // 4. 만료 시간 확인
            Date expiration = claims.getExpiration();
            if (expiration.before(new Date())) {
                throw new InvalidCredentialsException("Token has expired");
            }

            // 5. 사용자 정보 추출
            String sub = claims.getSubject();  // Apple user ID (고유, 불변)
            String email = claims.get("email", String.class);
            Boolean emailVerified = Boolean.parseBoolean(
                    claims.get("email_verified", String.class));

            log.info("Apple token verified: sub={}, email={}", sub, email);

            return AppleUserInfo.builder()
                    .sub(sub)
                    .email(email)
                    .emailVerified(emailVerified)
                    .build();

        } catch (InvalidCredentialsException e) {
            throw e;
        } catch (Exception e) {
            log.error("Apple token verification failed: {}", e.getMessage());
            throw new InvalidCredentialsException("Invalid Apple identity token");
        }
    }

    /**
     * Apple 공개키 가져오기 (캐싱 적용)
     */
    private PublicKey getApplePublicKey(String kid) {
        // 캐시 만료 확인
        if (System.currentTimeMillis() - lastKeyFetchTime > KEY_CACHE_DURATION_MS) {
            publicKeyCache.clear();
        }

        // 캐시에서 조회
        if (publicKeyCache.containsKey(kid)) {
            return publicKeyCache.get(kid);
        }

        // Apple에서 공개키 가져오기
        try {
            String response = restTemplate.getForObject(APPLE_KEYS_URL, String.class);
            JsonNode keys = objectMapper.readTree(response).get("keys");

            for (JsonNode key : keys) {
                String keyId = key.get("kid").asText();
                if (keyId.equals(kid)) {
                    String n = key.get("n").asText();
                    String e = key.get("e").asText();

                    PublicKey publicKey = createPublicKey(n, e);
                    publicKeyCache.put(kid, publicKey);
                    lastKeyFetchTime = System.currentTimeMillis();

                    return publicKey;
                }
            }

            throw new InvalidCredentialsException("Apple public key not found for kid: " + kid);

        } catch (InvalidCredentialsException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to fetch Apple public keys: {}", e.getMessage());
            throw new InvalidCredentialsException("Failed to verify Apple token");
        }
    }

    /**
     * RSA 공개키 생성
     */
    private PublicKey createPublicKey(String n, String e) throws Exception {
        byte[] nBytes = Base64.getUrlDecoder().decode(n);
        byte[] eBytes = Base64.getUrlDecoder().decode(e);

        BigInteger modulus = new BigInteger(1, nBytes);
        BigInteger exponent = new BigInteger(1, eBytes);

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");

        return factory.generatePublic(spec);
    }

    @Getter
    @lombok.Builder
    public static class AppleUserInfo {
        private final String sub;  // Apple user ID (고유 식별자)
        private final String email;
        private final Boolean emailVerified;
    }
}
