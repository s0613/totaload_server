package com.isoplatform.api.certification.controller;

import com.isoplatform.api.certification.request.CertificateRequest;
import com.isoplatform.api.certification.service.CertificateService;
import com.isoplatform.api.security.ApiKeyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@Slf4j
@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;
    private final ApiKeyService apiKeyService;

    /**
     * 인증서 생성
     */
    @PostMapping("/issue")
    public ResponseEntity<String> issueCertificate(
            @Valid @RequestBody CertificateRequest request,
            @RequestHeader("X-API-KEY") String apiKey) {

        log.info("인증서 발급 요청 - VIN: {}", request.getVin());

        // 보안 강화된 API 키 검증
        ApiKeyService.ApiKeyValidationResult validationResult = apiKeyService.validateApiKeyWithDetails(apiKey);

        if (!validationResult.isValid()) {
            log.warn("인증서 발급 실패 - VIN: {}, 이유: {}", request.getVin(), validationResult.getMessage());
            return ResponseEntity.status(401).body("Unauthorized: " + validationResult.getMessage());
        }

        try {
            certificateService.issueCertificate(request, "API_USER");
            log.info("인증서 발급 완료 - VIN: {}", request.getVin());
            return ResponseEntity.ok("Certificate issued successfully");
        } catch (Exception e) {
            log.error("인증서 발급 실패 - VIN: {}, 오류: {}", request.getVin(), e.getMessage());
            return ResponseEntity.internalServerError().body("Failed to issue certificate: " + e.getMessage());
        }
    }


    /**
     * 예외 처리
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException e) {
        log.warn("잘못된 요청: {}", e.getMessage());
        return ResponseEntity.badRequest().body(e.getMessage());
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<String> handleRuntimeException(RuntimeException e) {
        log.error("서버 오류", e);
        return ResponseEntity.internalServerError().body("서버 내부 오류가 발생했습니다.");
    }
}
