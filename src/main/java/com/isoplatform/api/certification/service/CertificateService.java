package com.isoplatform.api.certification.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.certification.Certificate;
import com.isoplatform.api.certification.repository.CertificateRepository;
import com.isoplatform.api.certification.request.CertificateRequest;
import com.isoplatform.api.certification.response.CertificateResponse;
import com.isoplatform.api.util.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateService {

    private final S3Service s3Service;
    private final CertificateRepository certificateRepository;
    private final PDFParser pdfParser;
    private final Gemini gemini;
    private final UserRepository userRepository;
    private final PdfImageConverter pdfImageConverter;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Transactional
    public CertificateResponse issueCertificate(CertificateRequest req, String issuedBy) {
        try {
            // VIN 중복이면 기존 레코드 반환
            Certificate dup = certificateRepository.findByVin(req.getVin()).orElse(null);
            if (dup != null) return toResponse(dup);

            // 엔티티 생성(저장은 나중에)
            Certificate cert = toEntity(req, issuedBy);

            // PDF 생성 전 핵심값 점검 로그
            log.info("PDF 직전 값 확인: manufacturer={}, modelName={}, vin={}, manuYear={}, displacement={}, seatCount={}, fuelType={}, variant={}, inspectCountry={}",
                    cert.getManufacturer(), cert.getModelName(), cert.getVin(), cert.getManuYear(),
                    cert.getDisplacement(), cert.getSeatCount(), cert.getFuelType(), cert.getVariant(), cert.getInspectCountry());

            // PDF 생성
            String localPdf = pdfParser.createCertificatePdf(cert);

            // 업로드
            String s3Key = "certificates/" + cert.getCertNumber() + ".pdf";
            S3UploadResult up = s3Service.uploadFile(localPdf, s3Key);
            cert.setPdfS3Key(up.getS3Key());
            cert.setPdfUrl(up.getCloudFrontUrl());

            // 로컬 파일 제거
            s3Service.deleteLocalFile(localPdf);

            // 최종 저장
            certificateRepository.save(cert);

            // 응답
            return toResponse(cert);

        } catch (Exception e) {
            log.error("issueCertificate error", e);
            throw new RuntimeException("인증서 발급 실패: " + e.getMessage());
        }
    }

    /**
     * 이미지-설명 검증이 필요하면 주석 해제해 사용
     */
//    private void validateImagesWithDescriptions(List<String> imageUrls, List<String> descriptions) {
//        if (descriptions == null || imageUrls.size() != descriptions.size()) {
//            throw new IllegalArgumentException("이미지와 설명의 개수가 일치하지 않습니다.");
//        }
//        try {
//            List<Boolean> validationResults = gemini.checkImageDescriptions(imageUrls, descriptions);
//            for (int i = 0; i < validationResults.size(); i++) {
//                if (!validationResults.get(i)) {
//                    throw new IllegalArgumentException(
//                            String.format("이미지 %d번과 설명이 일치하지 않습니다: \"%s\"", i + 1, descriptions.get(i)));
//                }
//            }
//            log.info("이미지-설명 검증 완료: {} 개 이미지 모두 통과", imageUrls.size());
//        } catch (Exception e) {
//            log.error("이미지-설명 검증 실패", e);
//            throw new RuntimeException("이미지-설명 검증 중 오류가 발생했습니다: " + e.getMessage());
//        }
//    }

    /**
     * 요청 → 엔티티 풀 매핑
     * - 기본값: certNumber, issueDate, expireDate
     * - 대체 매핑: manuYear ← req.manuYear 우선, 없으면 req.manufactureYear
     *            displacement ← req.displacement 우선, 없으면 req.engineDisplacement
     */
    private Certificate toEntity(CertificateRequest r, String by) {
        String certNumber = (r.getCertNumber() != null) ? r.getCertNumber() : genCert();
        LocalDate issueDate = (r.getIssueDate() != null) ? r.getIssueDate() : LocalDate.now();
        LocalDate expireDate = (r.getExpireDate() != null) ? r.getExpireDate()
                : (r.getIssueDate() != null ? r.getIssueDate().plusYears(1) : LocalDate.now().plusYears(1));

        Integer manuYear = (r.getManuYear() != null) ? r.getManuYear() : r.getManufactureYear();
        String displacement = (r.getDisplacement() != null && !r.getDisplacement().isEmpty())
                ? r.getDisplacement() : (r.getEngineDisplacement() == null ? null : r.getEngineDisplacement());

        Certificate cert = Certificate.builder()
                // 인증 기본
                .certNumber(certNumber)
                .issueDate(issueDate)
                .expireDate(expireDate)
                .issuedBy(r.getIssuedBy() != null ? r.getIssuedBy() : by)

                // 검사 정보
                .inspectDate(r.getInspectDate())
                .inspectCountry(r.getInspectCountry())
                .inspectSite(r.getInspectSite())
//                .eVerifyId(r.geteVerifyId())
                .verifyUrl(r.getVerifyUrl())

                // 차량 기본
                .manufacturer(r.getManufacturer())
                .modelName(r.getModelName())
                .vin(r.getVin())

                // 연식/등록/주행
                .manufactureYear(r.getManufactureYear())
                .manuYear(manuYear)
                .firstRegisterDate(r.getFirstRegisterDate())
                .mileage(r.getMileage())

                // 차량 식별 추가
                .variant(r.getVariant())
                .engineNumber(r.getEngineNumber())
                .displacement(displacement)
                .engineDisplacement(r.getEngineDisplacement())
                .modelYear(r.getModelYear())
                .usecase(r.getUsecase())
                .colorCode(r.getColorCode())
                .seatCount(r.getSeatCount())
                .doorCount(r.getDoorCount())
                .fuelType(r.getFuelType())
                .driveType(r.getDriveType())
                .odoType(r.getOdoType())

                // 치수·중량
                .length(r.getLength())
                .width(r.getWidth())
                .height(r.getHeight())
                .wheelbase(r.getWheelbase())
                .trackFront(r.getTrackFront())
                .gvm(r.getGvm())
                .curbWeight(r.getCurbWeight())
                .axleFront(r.getAxleFront())
                .axleRear(r.getAxleRear())
                .bodyType(r.getBodyType())

                // 파워트레인·배출
                .engineType(r.getEngineType())
                .cylinderCount(r.getCylinderCount())
                .induction(r.getInduction())
                .enginePower(r.getEnginePower())
                .emissionStd(r.getEmissionStd())
                .motorPower(r.getMotorPower())
                .batteryVoltage(r.getBatteryVoltage())
                .transmission(r.getTransmission())
                .brakeType(r.getBrakeType())
                .fuelEconomy(r.getFuelEconomy())

                // 등급/결함
                .jaaiGrade(r.getJaaiGrade())
                .aisScore(r.getAisScore())
                .aisDefectCode(r.getAisDefectCode())
                .repairHistory(r.getRepairHistory())
                .comment(r.getComment())

                // 수입국 규정
                .destinationCountry(r.getDestinationCountry())
                .validityNote(r.getValidityNote())
                .disclaimer(r.getDisclaimer())

                // 항균(방사선)
                .radiationResult(r.getRadiationResult())

                // 평가사
                .inspectorCode(r.getInspectorCode())
                .inspectorName(r.getInspectorName())

                // 서명 이미지(선택)
                .signaturePath(r.getSignaturePath())
                .build();

        return cert;
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
                // 발급자 ID 리스트 (iso-server 통합)
                .issuerUserIds(c.getIssuerUserIds())
                // 호환성을 위한 기존 발급자 정보
                .issuedBy(c.getIssuedBy())
                .issuedByName(c.getIssuedByName())
                .issuedByCompany(c.getIssuedByCompany())
                .issuedAt(c.getIssuedAt())
                .issuerUserId(c.getIssuerUserId())
                .pdfFilePath(c.getPdfUrl())
                .build();
    }

    private String genCert() {
        String d = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String r = UUID.randomUUID().toString().replace("-", "").substring(0, 6).toUpperCase();
        return "CERT-" + d + "-" + r;
    }

    /**
     * 현재 인증된 사용자 조회
     */
    private User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new RuntimeException("User not authenticated");
        }
        String email = auth.getName();
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found: " + email));
    }

    /**
     * 업로드 흐름: PDF → Images → AI Analysis → DB
     * 1. PDF 업로드 받음
     * 2. PDF를 이미지로 변환
     * 3. Gemini API로 AI 분석
     * 4. 분석 결과를 DB에 저장
     *
     * @param pdfFile 업로드된 PDF 파일
     * @return 인증서 응답 (AI 분석 결과 포함)
     */
    @Transactional
    public CertificateResponse uploadAndVerify(MultipartFile pdfFile) throws IOException {
        User currentUser = getCurrentUser();
        List<String> imagePaths = null;

        try {
            // 1. PDF를 임시 파일로 저장
            Path tempPdf = Files.createTempFile("upload-", ".pdf");
            pdfFile.transferTo(tempPdf.toFile());
            log.info("PDF 업로드 완료: {}", tempPdf);

            // 2. PDF → Images 변환
            imagePaths = pdfImageConverter.convertPdfToImages(tempPdf.toString());
            log.info("PDF 이미지 변환 완료: {} 페이지", imagePaths.size());

            // 3. S3에 이미지 업로드하여 URL 생성
            List<String> imageUrls = s3Service.uploadImages(imagePaths);
            log.info("이미지 S3 업로드 완료: {} 개", imageUrls.size());

            // 4. Gemini AI 분석
            JsonNode aiAnalysis = gemini.analyzeCertificate(imageUrls);
            log.info("AI 분석 완료: {}", aiAnalysis);

            // 5. AI 분석 결과에서 필드 추출
            String manufacturer = aiAnalysis.path("manufacturer").asText("UNKNOWN");
            String modelName = aiAnalysis.path("modelName").asText("UNKNOWN");
            String vin = aiAnalysis.path("vin").asText("VIN-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase());
            Integer manuYear = aiAnalysis.path("manuYear").isNull() ? null : aiAnalysis.path("manuYear").asInt();
            String displacement = aiAnalysis.path("displacement").asText(null);
            String fuelType = aiAnalysis.path("fuelType").asText(null);
            Integer seatCount = aiAnalysis.path("seatCount").isNull() ? null : aiAnalysis.path("seatCount").asInt();
            String variant = aiAnalysis.path("variant").asText(null);
            String inspectCountry = aiAnalysis.path("inspectCountry").asText(null);
            Integer mileage = aiAnalysis.path("mileage").isNull() ? null : aiAnalysis.path("mileage").asInt();
            String colorCode = aiAnalysis.path("colorCode").asText(null);
            String engineNumber = aiAnalysis.path("engineNumber").asText(null);

            // 신뢰도 추출
            BigDecimal aiConfidence = aiAnalysis.path("confidence").isNull()
                    ? BigDecimal.valueOf(0.0)
                    : BigDecimal.valueOf(aiAnalysis.path("confidence").asDouble());

            // 검사일자 파싱
            LocalDate inspectDate = null;
            String inspectDateStr = aiAnalysis.path("inspectDate").asText(null);
            if (inspectDateStr != null && !inspectDateStr.isBlank()) {
                try {
                    inspectDate = LocalDate.parse(inspectDateStr);
                } catch (Exception e) {
                    log.warn("검사일자 파싱 실패: {}", inspectDateStr, e);
                    inspectDate = LocalDate.now();
                }
            } else {
                inspectDate = LocalDate.now();
            }

            // 6. Certificate 엔티티 생성 및 저장
            Certificate cert = Certificate.builder()
                    .user(currentUser)
                    .certNumber(genCert())
                    .issueDate(LocalDate.now())
                    .expireDate(LocalDate.now().plusYears(1))
                    .inspectDate(inspectDate)
                    // AI 분석 결과로 필드 채우기
                    .manufacturer(manufacturer)
                    .modelName(modelName)
                    .vin(vin)
                    .manuYear(manuYear)
                    .displacement(displacement)
                    .fuelType(fuelType)
                    .seatCount(seatCount)
                    .variant(variant)
                    .inspectCountry(inspectCountry)
                    .mileage(mileage)
                    .colorCode(colorCode)
                    .engineNumber(engineNumber)
                    .aiAnalysis(aiAnalysis)
                    .aiConfidence(aiConfidence)
                    .verified(false)
                    .build();

            certificateRepository.save(cert);
            log.info("인증서 생성 완료: {}", cert.getCertNumber());

            // 7. 임시 파일 정리
            Files.deleteIfExists(tempPdf);

            return toResponse(cert);

        } finally {
            // 임시 이미지 파일 정리
            if (imagePaths != null) {
                pdfImageConverter.cleanupImages(imagePaths);
            }
        }
    }

    /**
     * 생성 흐름: Data → DB → PDF Generation
     * 1. 요청 데이터로 Certificate 엔티티 생성
     * 2. DB에 저장
     * 3. PDF 생성 및 S3 업로드
     *
     * @param req 인증서 요청 데이터
     * @return 인증서 응답 (PDF URL 포함)
     */
    @Transactional
    public CertificateResponse createAndGenerate(CertificateRequest req) {
        User currentUser = getCurrentUser();

        try {
            // VIN 중복 체크
            if (certificateRepository.existsByVin(req.getVin())) {
                Certificate existing = certificateRepository.findByVin(req.getVin())
                        .orElseThrow(() -> new RuntimeException("VIN exists but not found: " + req.getVin()));
                log.info("VIN 중복: 기존 인증서 반환 - {}", existing.getCertNumber());
                return toResponse(existing);
            }

            // 1. Certificate 엔티티 생성 (User 연결)
            Certificate cert = toEntity(req, currentUser.getEmail());
            cert.setUser(currentUser);

            // 2. PDF 생성 전 로그
            log.info("PDF 생성 직전: manufacturer={}, modelName={}, vin={}",
                    cert.getManufacturer(), cert.getModelName(), cert.getVin());

            // 3. PDF 생성
            String localPdf = pdfParser.createCertificatePdf(cert);

            // 4. S3 업로드
            String s3Key = "certificates/" + cert.getCertNumber() + ".pdf";
            S3UploadResult uploadResult = s3Service.uploadFile(localPdf, s3Key);
            cert.setPdfS3Key(uploadResult.getS3Key());
            cert.setPdfUrl(uploadResult.getCloudFrontUrl());
            cert.setS3Bucket("iso-platform-certificates"); // TODO: 환경변수로 관리

            // 5. 로컬 PDF 파일 삭제
            s3Service.deleteLocalFile(localPdf);

            // 6. DB 저장
            certificateRepository.save(cert);
            log.info("인증서 생성 완료: {}", cert.getCertNumber());

            return toResponse(cert);

        } catch (Exception e) {
            log.error("createAndGenerate 실패", e);
            throw new RuntimeException("인증서 생성 실패: " + e.getMessage(), e);
        }
    }

    // ========== iso-server 통합: 인증서 관리 메서드들 ==========

    /**
     * 모든 인증서 조회 (iso-server 통합)
     */
    public List<CertificateResponse> getAllCertificates() {
        try {
            List<Certificate> certificates = certificateRepository.findAllWithIssuers();
            return certificates.stream()
                    .map(this::toResponse)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            log.error("getAllCertificates error", e);
            throw new RuntimeException("인증서 조회 실패: " + e.getMessage());
        }
    }

    /**
     * ID로 인증서 조회 (iso-server 통합)
     */
    public CertificateResponse getCertificateById(Long id) {
        try {
            Certificate certificate = certificateRepository.findById(id)
                    .orElseThrow(() -> new IllegalArgumentException("해당 ID의 인증서를 찾을 수 없습니다: " + id));

            return toResponse(certificate);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            log.error("getCertificateById error", e);
            throw new RuntimeException("인증서 조회 실패: " + e.getMessage());
        }
    }

    /**
     * 인증서 발급 요청 (실제 사용자 정보 활용) (iso-server 통합)
     */
    @Transactional
    public CertificateResponse issueCertificateRequest(Long id, User issuer) {
        try {
            // 기존 인증서 조회
            Certificate certificate = certificateRepository.findById(id)
                    .orElseThrow(() -> new IllegalArgumentException("해당 ID의 인증서를 찾을 수 없습니다: " + id));

            // 발급자 ID를 리스트에 추가
            certificate.addIssuer(issuer.getId());

            // 호환성을 위해 기존 필드도 업데이트 (첫 번째 발급자 또는 현재 발급자)
            certificate.setIssuedBy(issuer.getEmail());
            certificate.setIssuedByName(issuer.getName());
            certificate.setIssuedByCompany(issuer.getCompany());
            certificate.setIssuedAt(LocalDateTime.now());
            certificate.setIssuerUserId(issuer.getId());

            // 인증서 저장
            Certificate updatedCertificate = certificateRepository.save(certificate);

            log.info("인증서 발급 완료 - ID: {}, 인증번호: {}, VIN: {}, 발급자: {} ({}), 총 발급자 수: {}",
                    updatedCertificate.getId(),
                    updatedCertificate.getCertNumber(),
                    updatedCertificate.getVin(),
                    issuer.getName(),
                    issuer.getEmail(),
                    updatedCertificate.getIssuerUserIds().size());

            return toResponse(updatedCertificate);
        } catch (IllegalArgumentException e) {
            log.warn("issueCertificateRequest - 인증서를 찾을 수 없음: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("issueCertificateRequest error", e);
            throw new RuntimeException("인증서 발급 요청 실패: " + e.getMessage());
        }
    }

    /**
     * 인증서에 발급자 추가 (iso-server 통합)
     */
    @Transactional
    public CertificateResponse addIssuerToCertificate(Long certificateId, Long issuerUserId) {
        try {
            Certificate certificate = certificateRepository.findById(certificateId)
                    .orElseThrow(() -> new IllegalArgumentException("해당 ID의 인증서를 찾을 수 없습니다: " + certificateId));

            // 발급자 ID를 리스트에 추가
            certificate.addIssuer(issuerUserId);

            // 인증서 저장
            Certificate updatedCertificate = certificateRepository.save(certificate);

            log.info("인증서 발급자 추가 완료 - 인증서 ID: {}, 발급자 ID: {}, 총 발급자 수: {}",
                    certificateId, issuerUserId, updatedCertificate.getIssuerUserIds().size());

            return toResponse(updatedCertificate);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            log.error("addIssuerToCertificate error", e);
            throw new RuntimeException("발급자 추가 실패: " + e.getMessage());
        }
    }

    /**
     * 특정 발급자가 발급한 인증서 조회 (iso-server 통합)
     */
    public List<CertificateResponse> getCertificatesByIssuer(Long issuerUserId) {
        try {
            // JOIN FETCH를 사용하여 한 번의 쿼리로 해결 (N+1 문제 해결)
            List<Certificate> certificates = certificateRepository.findByIssuerUserIdWithFetch(issuerUserId);

            return certificates.stream()
                    .map(this::toResponse)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            log.error("getCertificatesByIssuer error", e);
            throw new RuntimeException("발급자별 인증서 조회 실패: " + e.getMessage());
        }
    }
}
