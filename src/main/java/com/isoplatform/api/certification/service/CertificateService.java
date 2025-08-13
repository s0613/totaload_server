package com.isoplatform.api.certification.service;

import com.isoplatform.api.certification.Certificate;
import com.isoplatform.api.certification.repository.CertificateRepository;
import com.isoplatform.api.certification.request.CertificateRequest;
import com.isoplatform.api.certification.response.CertificateResponse;
import com.isoplatform.api.util.Gemini;
import com.isoplatform.api.util.PDFParser;
import com.isoplatform.api.util.S3Service;
import com.isoplatform.api.util.S3UploadResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateService {

    private final S3Service s3Service;
    private final CertificateRepository certificateRepository;
    private final PDFParser pdfParser;
    private final Gemini gemini;

    @Transactional
    public CertificateResponse issueCertificate(CertificateRequest req, String issuedBy) {
        try {
            // 중복 인증서 체크
            Certificate dup = certificateRepository.findByVin(req.getVin()).orElse(null);
            if (dup != null) return toResponse(dup);

            // 이미지-설명 검증
            if (req.getImageUrls() != null && !req.getImageUrls().isEmpty()) {
                validateImagesWithDescriptions(req.getImageUrls(), req.getDescriptions());
            }

            // 인증서 생성
            Certificate cert = toEntity(req, issuedBy);
            String localPdf = pdfParser.createCertificatePdf(cert);

            String s3Key = "certificates/" + cert.getCertNumber() + ".pdf";
            S3UploadResult up = s3Service.uploadFile(localPdf, s3Key);
            cert.setPdfS3Key(up.getS3Key());
            cert.setPdfUrl(up.getCloudFrontUrl());
            certificateRepository.save(cert);
            s3Service.deleteLocalFile(localPdf);

            return toResponse(cert);

        } catch (Exception e) {
            log.error("issueCertificate error", e);
            throw new RuntimeException("인증서 발급 실패: " + e.getMessage());
        }
    }

    private void validateImagesWithDescriptions(List<String> imageUrls, List<String> descriptions) {
        if (descriptions == null || imageUrls.size() != descriptions.size()) {
            throw new IllegalArgumentException("이미지와 설명의 개수가 일치하지 않습니다.");
        }

        try {
            // Gemini API로 이미지-설명 일치 여부 확인
            List<Boolean> validationResults = gemini.checkImageDescriptions(imageUrls, descriptions);

            // 모든 이미지가 설명과 일치하는지 확인
            for (int i = 0; i < validationResults.size(); i++) {
                if (!validationResults.get(i)) {
                    throw new IllegalArgumentException(
                            String.format("이미지 %d번과 설명이 일치하지 않습니다: \"%s\"",
                                    i + 1, descriptions.get(i)));
                }
            }

            log.info("이미지-설명 검증 완료: {} 개 이미지 모두 통과", imageUrls.size());

        } catch (Exception e) {
            log.error("이미지-설명 검증 실패", e);
            throw new RuntimeException("이미지-설명 검증 중 오류가 발생했습니다: " + e.getMessage());
        }
    }

    private Certificate toEntity(CertificateRequest r, String by){
        return certificateRepository.save(
                Certificate.builder()
                        .certNumber(r.getCertNumber() != null ? r.getCertNumber() : genCert())
                        .issueDate(r.getIssueDate() != null ? r.getIssueDate() : LocalDate.now())
                        .expireDate(r.getExpireDate() != null ? r.getExpireDate() :
                                (r.getIssueDate() != null ? r.getIssueDate().plusYears(1) : LocalDate.now().plusYears(1)))
                        .inspectDate(r.getInspectDate())
                        .manufacturer(r.getManufacturer())
                        .modelName(r.getModelName())
                        .vin(r.getVin())
                        .manufactureYear(r.getManufactureYear())
                        .firstRegisterDate(r.getFirstRegisterDate())
                        .mileage(r.getMileage())
                        .inspectorCode(r.getInspectorCode())
                        .inspectorName(r.getInspectorName())
                        .signaturePath(r.getSignaturePath())
                        .issuedBy(r.getIssuedBy() != null ? r.getIssuedBy() : by)
                        .build()
        );
    }

    private CertificateResponse toResponse(Certificate c) {
        return CertificateResponse.builder()
                .id(c.getId())
                .certNumber(c.getCertNumber())
                .issueDate(c.getIssueDate())
                .expireDate(c.getExpireDate())
                .inspectDate(c.getInspectDate())
                .manufacturer(c.getManufacturer())
                .modelName(c.getModelName())
                .vin(c.getVin())
                .manufactureYear(c.getManufactureYear())
                .firstRegisterDate(c.getFirstRegisterDate())
                .mileage(c.getMileage())
                .inspectorCode(c.getInspectorCode())
                .inspectorName(c.getInspectorName())
                .issuedBy(c.getIssuedBy())
                .pdfFilePath(c.getPdfUrl())
                .build();
    }

    private String genCert() {
        String d = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String r = UUID.randomUUID().toString().replace("-", "").substring(0,6).toUpperCase();
        return "CERT-" + d + "-" + r;
    }
}