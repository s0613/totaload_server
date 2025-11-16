package com.isoplatform.api.certification.controller;

import com.isoplatform.api.certification.request.CertificateRequest;
import com.isoplatform.api.certification.response.CertificateResponse;
import com.isoplatform.api.certification.service.CertificateService;
import com.isoplatform.api.security.ApiKeyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;


@Slf4j
@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;
    private final ApiKeyService apiKeyService;

    /**
     * 인증서 생성 (레거시 - 하위 호환성 유지)
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
     * 업로드 흐름: PDF → Images → AI Analysis → DB
     * PDF 파일을 업로드하면 AI가 분석하여 데이터 추출 후 DB 저장
     */
    @PostMapping("/upload")
    public ResponseEntity<?> uploadCertificate(
            @RequestParam("file") MultipartFile file,
            @RequestHeader("X-API-KEY") String apiKey) {

        log.info("인증서 업로드 요청 - 파일명: {}", file.getOriginalFilename());

        // API 키 검증
        ApiKeyService.ApiKeyValidationResult validationResult = apiKeyService.validateApiKeyWithDetails(apiKey);
        if (!validationResult.isValid()) {
            log.warn("인증서 업로드 실패 - 이유: {}", validationResult.getMessage());
            return ResponseEntity.status(401).body("Unauthorized: " + validationResult.getMessage());
        }

        // PDF 파일 검증
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("파일이 비어있습니다.");
        }

        String filename = file.getOriginalFilename();
        if (filename == null || !filename.toLowerCase().endsWith(".pdf")) {
            return ResponseEntity.badRequest().body("PDF 파일만 업로드 가능합니다.");
        }

        try {
            CertificateResponse response = certificateService.uploadAndVerify(file);
            log.info("인증서 업로드 완료 - 인증번호: {}", response.getCertNumber());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("인증서 업로드 실패", e);
            return ResponseEntity.internalServerError()
                    .body("인증서 업로드 실패: " + e.getMessage());
        }
    }

    /**
     * 생성 흐름: Data → DB → PDF Generation
     * 데이터를 받아서 DB 저장 후 PDF 생성
     */
    @PostMapping("/generate")
    public ResponseEntity<?> generateCertificate(
            @Valid @RequestBody CertificateRequest request,
            @RequestHeader("X-API-KEY") String apiKey) {

        log.info("인증서 생성 요청 - VIN: {}", request.getVin());

        // API 키 검증
        ApiKeyService.ApiKeyValidationResult validationResult = apiKeyService.validateApiKeyWithDetails(apiKey);
        if (!validationResult.isValid()) {
            log.warn("인증서 생성 실패 - VIN: {}, 이유: {}", request.getVin(), validationResult.getMessage());
            return ResponseEntity.status(401).body("Unauthorized: " + validationResult.getMessage());
        }

        try {
            CertificateResponse response = certificateService.createAndGenerate(request);
            log.info("인증서 생성 완료 - 인증번호: {}", response.getCertNumber());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("인증서 생성 실패 - VIN: {}", request.getVin(), e);
            return ResponseEntity.internalServerError()
                    .body("인증서 생성 실패: " + e.getMessage());
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
