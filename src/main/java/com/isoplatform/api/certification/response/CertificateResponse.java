package com.isoplatform.api.certification.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateResponse {
    private Long id;
    private String certNumber;
    private LocalDate issueDate;
    private LocalDate expireDate;
    private LocalDate inspectDate;
    private String manufacturer;
    private String modelName;
    private String vin;
    private Integer manufactureYear;
    private LocalDate firstRegisterDate;
    private Integer mileage;
    private String inspectorCode;
    private String inspectorName;

    // 발급자 ID 리스트 (iso-server 통합)
    private List<Long> issuerUserIds;

    // 호환성을 위한 기존 발급자 정보
    private String issuedBy;          // 발급자 이메일
    private String issuedByName;      // 발급자 성명
    private String issuedByCompany;   // 발급자 소속회사
    private LocalDateTime issuedAt;   // 발급 시각
    private Long issuerUserId;        // 발급자 User ID

    private String pdfFilePath;  // CloudFront URL
}
