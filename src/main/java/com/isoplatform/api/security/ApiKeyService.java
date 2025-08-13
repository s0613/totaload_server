package com.isoplatform.api.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

@Slf4j
@Service
public class ApiKeyService {

    @Value("${security.api-keys.keys.qload}")
    private String validApiKey;

    /**
     * API 키를 안전하게 검증합니다.
     * 타이밍 공격을 방지하기 위해 상수 시간 비교를 사용합니다.
     *
     * @param providedApiKey 클라이언트에서 제공한 API 키
     * @return 검증 결과
     */
    public boolean validateApiKey(String providedApiKey) {
        if (providedApiKey == null || providedApiKey.trim().isEmpty()) {
            log.warn("API 키가 제공되지 않음");
            return false;
        }

        try {
            // 제공된 API 키와 설정된 API 키를 해시하여 비교
            byte[] providedHash = hashApiKey(providedApiKey.trim());
            byte[] validHash = hashApiKey(validApiKey);

            // 타이밍 공격 방지를 위한 상수 시간 비교
            boolean isValid = constantTimeEquals(providedHash, validHash);

            if (!isValid) {
                log.warn("유효하지 않은 API 키 제공: {}", maskApiKey(providedApiKey));
            }

            return isValid;

        } catch (Exception e) {
            log.error("API 키 검증 중 오류 발생", e);
            return false;
        }
    }

    /**
     * API 키를 SHA-256으로 해시합니다.
     */
    private byte[] hashApiKey(String apiKey) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(apiKey.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 타이밍 공격을 방지하기 위한 상수 시간 비교
     */
    private boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     * 로깅을 위해 API 키를 마스킹합니다.
     */
    private String maskApiKey(String apiKey) {
        if (apiKey == null || apiKey.length() < 8) {
            return "***";
        }
        return apiKey.substring(0, 8) + "***";
    }

    /**
     * API 키의 유효성을 체크하고 상세한 로그를 남깁니다.
     */
    public ApiKeyValidationResult validateApiKeyWithDetails(String providedApiKey) {
        if (providedApiKey == null || providedApiKey.trim().isEmpty()) {
            return new ApiKeyValidationResult(false, "API 키가 제공되지 않았습니다");
        }

        // API 키 길이 검증 제거 - 설정 파일의 API 키와 일치하면 유효함
        boolean isValid = validateApiKey(providedApiKey);
        String message = isValid ? "유효한 API 키" : "유효하지 않은 API 키";

        return new ApiKeyValidationResult(isValid, message);
    }

    /**
     * API 키 검증 결과를 담는 클래스
     */
    public static class ApiKeyValidationResult {
        private final boolean valid;
        private final String message;

        public ApiKeyValidationResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }

        public boolean isValid() {
            return valid;
        }

        public String getMessage() {
            return message;
        }
    }
}
