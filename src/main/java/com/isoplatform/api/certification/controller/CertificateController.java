package com.isoplatform.api.certification.controller;

import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.certification.CertificateStatus;
import com.isoplatform.api.certification.request.CertificateRequest;
import com.isoplatform.api.certification.request.ReissueCertificateRequest;
import com.isoplatform.api.certification.request.RevokeCertificateRequest;
import com.isoplatform.api.certification.response.CertificateResponse;
import com.isoplatform.api.certification.response.CertificateStatsResponse;
import com.isoplatform.api.certification.service.CertificateService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDate;
import java.util.List;


@Slf4j
@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;
    private final UserRepository userRepository;

    /**
     * 인증서 생성 (JWT 인증 필요)
     */
    @PostMapping("/issue")
    public ResponseEntity<?> issueCertificate(@Valid @RequestBody CertificateRequest request) {
        log.info("인증서 발급 요청 - VIN: {}", request.getVin());

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String email = authentication.getName();

            CertificateResponse response = certificateService.issueCertificate(request, email);
            log.info("인증서 발급 완료 - VIN: {}", request.getVin());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("인증서 발급 실패 - VIN: {}, 오류: {}", request.getVin(), e.getMessage());
            return ResponseEntity.internalServerError().body("Failed to issue certificate: " + e.getMessage());
        }
    }

    /**
     * 업로드 흐름: PDF → Images → AI Analysis → DB
     * PDF 파일을 업로드하면 AI가 분석하여 데이터 추출 후 DB 저장 (JWT 인증 필요)
     */
    @PostMapping("/upload")
    public ResponseEntity<?> uploadCertificate(@RequestParam("file") MultipartFile file) {
        log.info("인증서 업로드 요청 - 파일명: {}", file.getOriginalFilename());

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
     * 데이터를 받아서 DB 저장 후 PDF 생성 (JWT 인증 필요)
     */
    @PostMapping("/generate")
    public ResponseEntity<?> generateCertificate(@Valid @RequestBody CertificateRequest request) {
        log.info("인증서 생성 요청 - VIN: {}", request.getVin());

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
    public ResponseEntity<List<CertificateResponse>> getAllCertificates() {
        // Spring Security가 이미 인증 처리함 (authenticated())
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
    public ResponseEntity<CertificateResponse> getCertificateById(@PathVariable Long id) {
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
    public ResponseEntity<CertificateResponse> issueCertificateRequest(@PathVariable Long id) {
        try {
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
    public ResponseEntity<List<Long>> getCertificateIssuers(@PathVariable Long certificateId) {
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
    public ResponseEntity<List<CertificateResponse>> getCertificatesByIssuer(@PathVariable Long userId) {
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
    public ResponseEntity<List<CertificateResponse>> getMyIssuedCertificates() {
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
     * 현재 로그인된 사용자가 발급받은 인증서 조회 (내 인증서)
     */
    @Operation(
        summary = "내가 발급받은 인증서 조회",
        description = "현재 로그인한 사용자가 발급받은 모든 인증서를 조회합니다."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "조회 성공"),
        @ApiResponse(responseCode = "401", description = "인증 필요")
    })
    @GetMapping("/my-received")
    public ResponseEntity<List<CertificateResponse>> getMyReceivedCertificates() {
        List<CertificateResponse> certificates = certificateService.getMyReceivedCertificates();
        return ResponseEntity.ok(certificates);
    }

    /**
     * Create certificate from checklist (JWT 인증 필요)
     * POST /api/certificates/from-checklist?checklistId={id}
     */
    @PostMapping("/from-checklist")
    public ResponseEntity<?> createCertificateFromChecklist(@RequestParam("checklistId") Long checklistId) {
        log.info("체크리스트로부터 인증서 생성 요청 - 체크리스트 ID: {}", checklistId);

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String email = authentication.getName();

            CertificateResponse response = certificateService.createCertificateFromChecklist(checklistId, email);
            log.info("체크리스트로부터 인증서 생성 완료 - 인증서 번호: {}, VIN: {}",
                    response.getCertNumber(), response.getVin());
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            log.warn("체크리스트 조회 실패: {}", e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            log.error("인증서 생성 실패", e);
            return ResponseEntity.internalServerError()
                    .body("인증서 생성 실패: " + e.getMessage());
        }
    }

    // ========== 앱 API 호환성: 추가 엔드포인트 ==========

    /**
     * 인증서 재발급
     * POST /api/certificates/{id}/reissue
     */
    @PostMapping("/{id}/reissue")
    public ResponseEntity<CertificateResponse> reissueCertificate(
            @PathVariable Long id,
            @RequestBody(required = false) ReissueCertificateRequest request) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String email = authentication.getName();
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found: " + email));

            String reason = request != null ? request.getReason() : null;
            String notes = request != null ? request.getAdditionalNotes() : null;

            CertificateResponse certificate = certificateService.reissueCertificate(id, user, reason, notes);
            log.info("인증서 재발급 완료 - 원본 ID: {}, 새 인증번호: {}", id, certificate.getCertNumber());

            return ResponseEntity.status(HttpStatus.CREATED).body(certificate);
        } catch (IllegalArgumentException e) {
            log.warn("인증서 재발급 실패: {}", e.getMessage());
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            log.error("인증서 재발급 실패 - ID: {}", id, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 인증서 취소
     * POST /api/certificates/{id}/revoke
     */
    @PostMapping("/{id}/revoke")
    public ResponseEntity<CertificateResponse> revokeCertificate(
            @PathVariable Long id,
            @RequestBody(required = false) RevokeCertificateRequest request) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String email = authentication.getName();
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found: " + email));

            String reason = request != null ? request.getReason() : null;

            CertificateResponse certificate = certificateService.revokeCertificate(id, user, reason);
            log.info("인증서 취소 완료 - ID: {}, 인증번호: {}", id, certificate.getCertNumber());

            return ResponseEntity.ok(certificate);
        } catch (IllegalArgumentException e) {
            log.warn("인증서 취소 실패: {}", e.getMessage());
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            log.error("인증서 취소 실패 - ID: {}", id, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 인증서 검색 (키워드)
     * GET /api/certificates/search?keyword=xxx
     */
    @GetMapping("/search")
    public ResponseEntity<List<CertificateResponse>> searchCertificates(
            @RequestParam String keyword) {
        try {
            List<CertificateResponse> certificates = certificateService.searchByKeyword(keyword);
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            log.error("인증서 검색 실패 - keyword: {}", keyword, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 인증서 고급 검색
     * GET /api/certificates/advanced-search?certNumber=xxx&manufacturer=xxx...
     */
    @GetMapping("/advanced-search")
    public ResponseEntity<List<CertificateResponse>> advancedSearchCertificates(
            @RequestParam(required = false) String certNumber,
            @RequestParam(required = false) String manufacturer,
            @RequestParam(required = false) String modelName,
            @RequestParam(required = false) String vin,
            @RequestParam(required = false) String country,
            @RequestParam(required = false) CertificateStatus status,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate issueDateFrom,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate issueDateTo,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate expireDateFrom,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate expireDateTo,
            @RequestParam(required = false) String inspectorName) {
        try {
            List<CertificateResponse> certificates = certificateService.advancedSearch(
                    certNumber, manufacturer, modelName, vin, country, status,
                    issueDateFrom, issueDateTo, expireDateFrom, expireDateTo, inspectorName);
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            log.error("인증서 고급 검색 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 인증서 통계
     * GET /api/certificates/stats
     */
    @GetMapping("/stats")
    public ResponseEntity<CertificateStatsResponse> getCertificateStats() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String email = authentication.getName();
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found: " + email));

            CertificateStatsResponse stats = certificateService.getCertificateStats(user.getId());
            return ResponseEntity.ok(stats);
        } catch (Exception e) {
            log.error("인증서 통계 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
