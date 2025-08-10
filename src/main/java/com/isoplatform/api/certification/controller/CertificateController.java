package com.isoplatform.api.certification.controller;

import com.isoplatform.api.certification.request.CertificateRequest;
import com.isoplatform.api.certification.service.CertificateService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;


@Slf4j
@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;

    /**
     * 인증서 생성
     */
    @PostMapping("/issue")
    public ResponseEntity<Void> issueCertificate(
            @Valid @RequestBody CertificateRequest request,
            Authentication authentication) {

        log.info("인증서 발급 요청 - VIN: {}, 발급자: {}", request.getVin(), authentication.getName());

        try {
            certificateService.issueCertificate(request, authentication.getName());
            log.info("인증서 발급 완료 - VIN: {}", request.getVin());
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("인증서 발급 실패 - VIN: {}, 오류: {}", request.getVin(), e.getMessage());
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
