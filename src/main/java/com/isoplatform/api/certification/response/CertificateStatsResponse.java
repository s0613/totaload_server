package com.isoplatform.api.certification.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateStatsResponse {
    private Long totalCertificates;
    private Long validCertificates;
    private Long expiredCertificates;
    private Long expiringSoonCertificates;  // 30일 내 만료 예정
    private Long myIssuedCertificates;
    private Long myReceivedCertificates;
    private Long revokedCertificates;
}
