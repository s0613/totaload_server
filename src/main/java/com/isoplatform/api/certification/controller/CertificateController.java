package com.isoplatform.api.certification.controller;

import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.certification.request.CertificateRequest;
import com.isoplatform.api.certification.response.CertificateResponse;
import com.isoplatform.api.certification.service.CertificateService;
import com.isoplatform.api.security.ApiKeyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;


@Slf4j
@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;
    private final ApiKeyService apiKeyService;
    private final UserRepository userRepository;

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


    // ========== iso-server 통합: 인증서 관리 엔드포인트 ==========

    /**
     * 인증서 전체 조회 (iso-server 통합)
     */
    @GetMapping
    public ResponseEntity<List<CertificateResponse>> getAllCertificates(
            @RequestHeader("X-API-KEY") String apiKey) {
        ApiKeyService.ApiKeyValidationResult validationResult = apiKeyService.validateApiKeyWithDetails(apiKey);
        if (!validationResult.isValid()) {
            return ResponseEntity.status(401).build();
        }

        try {
            List<CertificateResponse> certificates = certificateService.getAllCertificates();
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            log.error("인증서 전체 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * ID로 인증서 단건 조회 (iso-server 통합)
     */
    @GetMapping("/{id}")
    public ResponseEntity<CertificateResponse> getCertificateById(
            @PathVariable Long id,
            @RequestHeader("X-API-KEY") String apiKey) {
        ApiKeyService.ApiKeyValidationResult validationResult = apiKeyService.validateApiKeyWithDetails(apiKey);
        if (!validationResult.isValid()) {
            return ResponseEntity.status(401).build();
        }

        try {
            CertificateResponse certificate = certificateService.getCertificateById(id);
            return ResponseEntity.ok(certificate);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            log.error("인증서 조회 실패 - ID: {}", id, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 인증서 발급 요청 - 발급자 ID가 리스트에 자동 추가됨 (iso-server 통합)
     */
    @PostMapping("/{id}/issue")
    public ResponseEntity<CertificateResponse> issueCertificateRequest(
            @PathVariable Long id,
            @RequestHeader("X-API-KEY") String apiKey) {

        ApiKeyService.ApiKeyValidationResult validationResult = apiKeyService.validateApiKeyWithDetails(apiKey);
        if (!validationResult.isValid()) {
            return ResponseEntity.status(401).build();
        }

        try {
            // 현재 인증된 사용자 가져오기
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String email = authentication.getName();
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found: " + email));

            CertificateResponse certificate = certificateService.issueCertificateRequest(id, user);
            log.info("인증서 발급 완료 - ID: {}, 인증번호: {}, 발급자: {}, 총 발급자 수: {}",
                    certificate.getId(), certificate.getCertNumber(),
                    certificate.getIssuedBy(), certificate.getIssuerUserIds().size());

            return ResponseEntity.status(HttpStatus.CREATED).body(certificate);
        } catch (IllegalArgumentException e) {
            log.warn("인증서 발급 실패 - 인증서를 찾을 수 없음: ID {}, 오류: {}", id, e.getMessage());
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            log.error("인증서 발급 실패 - ID: {}, 오류: {}", id, e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 특정 인증서의 발급자 ID 리스트 조회 (iso-server 통합)
     */
    @GetMapping("/{certificateId}/issuers")
    public ResponseEntity<List<Long>> getCertificateIssuers(
            @PathVariable Long certificateId,
            @RequestHeader("X-API-KEY") String apiKey) {
        ApiKeyService.ApiKeyValidationResult validationResult = apiKeyService.validateApiKeyWithDetails(apiKey);
        if (!validationResult.isValid()) {
            return ResponseEntity.status(401).build();
        }

        try {
            CertificateResponse certificate = certificateService.getCertificateById(certificateId);
            return ResponseEntity.ok(certificate.getIssuerUserIds());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            log.error("발급자 리스트 조회 실패 - ID: {}", certificateId, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 특정 발급자가 발급한 인증서 조회 (iso-server 통합)
     */
    @GetMapping("/issued-by/{userId}")
    public ResponseEntity<List<CertificateResponse>> getCertificatesByIssuer(
            @PathVariable Long userId,
            @RequestHeader("X-API-KEY") String apiKey) {
        ApiKeyService.ApiKeyValidationResult validationResult = apiKeyService.validateApiKeyWithDetails(apiKey);
        if (!validationResult.isValid()) {
            return ResponseEntity.status(401).build();
        }

        try {
            List<CertificateResponse> certificates = certificateService.getCertificatesByIssuer(userId);
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            log.error("발급자별 인증서 조회 실패 - userId: {}", userId, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 현재 로그인된 사용자가 발급한 인증서 조회 (iso-server 통합)
     */
    @GetMapping("/my-issued")
    public ResponseEntity<List<CertificateResponse>> getMyIssuedCertificates(
            @RequestHeader("X-API-KEY") String apiKey) {
        ApiKeyService.ApiKeyValidationResult validationResult = apiKeyService.validateApiKeyWithDetails(apiKey);
        if (!validationResult.isValid()) {
            return ResponseEntity.status(401).build();
        }

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String email = authentication.getName();
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found: " + email));

            List<CertificateResponse> certificates = certificateService.getCertificatesByIssuer(user.getId());
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            log.error("내 발급 인증서 조회 실패", e);
            return ResponseEntity.internalServerError().build();
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
