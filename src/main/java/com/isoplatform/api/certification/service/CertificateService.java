package com.isoplatform.api.certification.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.certification.Certificate;
import com.isoplatform.api.certification.CertificateStatus;
import com.isoplatform.api.certification.repository.CertificateRepository;
import com.isoplatform.api.certification.request.CertificateRequest;
import com.isoplatform.api.certification.response.CertificateResponse;
import com.isoplatform.api.certification.response.CertificateStatsResponse;
import com.isoplatform.api.exception.CertificateNotFoundException;
import com.isoplatform.api.exception.ImageValidationException;
import com.isoplatform.api.exception.UserNotAuthenticatedException;
import com.isoplatform.api.inspection.Photo;
import com.isoplatform.api.inspection.VehicleChecklist;
import com.isoplatform.api.inspection.service.ChecklistService;
import com.isoplatform.api.inspection.service.PhotoService;
import com.isoplatform.api.certification.response.PhotoResponse;
import com.isoplatform.api.storage.S3Service;
import com.isoplatform.api.util.*;
import org.springframework.beans.factory.annotation.Value;
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
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
    private final ChecklistService checklistService;
    private final PhotoService photoService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final String S3_CERTIFICATES_FOLDER = "certificates";
    private static final int CERTIFICATE_VALIDITY_YEARS = 1;

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

            // S3에 업로드
            String fileName = cert.getCertNumber() + ".pdf";
            File sourceFile = new File(localPdf);
            S3UploadResult uploadResult = s3Service.uploadFile(sourceFile, S3_CERTIFICATES_FOLDER, fileName, "application/pdf");

            cert.setPdfS3Key(uploadResult.getS3Key());
            cert.setPdfUrl(uploadResult.getCloudFrontUrl());

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
     * AI-powered image validation
     * Validates that uploaded images match their checklist item descriptions
     *
     * @param imageUrls List of CloudFront URLs for images
     * @param descriptions List of descriptions for each image
     * @throws ImageValidationException if any image fails validation
     */
    private void validateImagesWithDescriptions(List<String> imageUrls, List<String> descriptions) {
        if (descriptions == null || imageUrls.size() != descriptions.size()) {
            throw new IllegalArgumentException("이미지와 설명의 개수가 일치하지 않습니다.");
        }

        if (imageUrls.isEmpty()) {
            log.warn("검증할 이미지가 없습니다.");
            return;
        }

        try {
            log.info("AI 이미지 검증 시작: {} 개 이미지", imageUrls.size());
            List<Boolean> validationResults = gemini.checkImageDescriptions(imageUrls, descriptions);

            // Collect failed images
            List<String> failedImages = new ArrayList<>();
            for (int i = 0; i < validationResults.size(); i++) {
                if (!validationResults.get(i)) {
                    String failedInfo = String.format("[이미지 %d] 설명: \"%s\", URL: %s",
                            i + 1, descriptions.get(i), imageUrls.get(i));
                    failedImages.add(failedInfo);
                    log.warn("이미지 검증 실패: {}", failedInfo);
                }
            }

            // Throw exception if any validation failed
            if (!failedImages.isEmpty()) {
                String errorMessage = String.format(
                        "AI 이미지 검증 실패: %d개 이미지가 설명과 일치하지 않습니다.",
                        failedImages.size());
                log.error("{}\n실패한 이미지:\n{}", errorMessage, String.join("\n", failedImages));
                throw new ImageValidationException(errorMessage, failedImages);
            }

            log.info("AI 이미지 검증 완료: {} 개 이미지 모두 통과", imageUrls.size());

        } catch (ImageValidationException e) {
            // Re-throw validation exception
            throw e;
        } catch (Exception e) {
            log.error("이미지-설명 검증 중 오류 발생", e);
            throw new RuntimeException("이미지-설명 검증 중 오류가 발생했습니다: " + e.getMessage(), e);
        }
    }

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
                : (r.getIssueDate() != null ? r.getIssueDate().plusYears(CERTIFICATE_VALIDITY_YEARS) : LocalDate.now().plusYears(CERTIFICATE_VALIDITY_YEARS));

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
                // 이미지 URL 리스트
                .imageUrls(r.getImageUrls() != null ? new ArrayList<>(r.getImageUrls()) : new ArrayList<>())
                .build();

        return cert;
    }

    private CertificateResponse toResponse(Certificate c) {
        // VIN 기준으로 체크리스트 항목별 사진 조회
        List<PhotoResponse> photoResponses = new ArrayList<>();
        List<String> damagedParts = new ArrayList<>();

        if (c.getVin() != null) {
            // 사진 조회
            List<Photo> photos = photoService.getPhotosByVin(c.getVin());
            if (photos != null && !photos.isEmpty()) {
                photoResponses = photos.stream()
                        .map(p -> PhotoResponse.builder()
                                .id(p.getId())
                                .category(p.getCategory())
                                .itemCode(p.getItemCode())
                                .cloudFrontUrl(p.getCloudFrontUrl())
                                .fileName(p.getFileName())
                                .build())
                        .collect(Collectors.toList());
            }

            // 체크리스트에서 damagedParts 조회
            try {
                VehicleChecklist checklist = checklistService.getChecklistByVin(c.getVin());
                if (checklist != null && checklist.getDamagedParts() != null) {
                    damagedParts = objectMapper.readValue(
                            checklist.getDamagedParts(),
                            objectMapper.getTypeFactory().constructCollectionType(List.class, String.class)
                    );
                }
            } catch (Exception e) {
                log.debug("체크리스트 조회 실패 (VIN: {}): {}", c.getVin(), e.getMessage());
            }
        }

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
                // 검사 국가 (앱 호환성)
                .country(c.getInspectCountry())
                // 발급자 ID 리스트 (iso-server 통합)
                .issuerUserIds(c.getIssuerUserIds())
                // 호환성을 위한 기존 발급자 정보
                .issuedBy(c.getIssuedBy())
                .issuedByName(c.getIssuedByName())
                .issuedByCompany(c.getIssuedByCompany())
                .issuedAt(c.getIssuedAt())
                .issuerUserId(c.getIssuerUserId())
                .pdfFilePath(c.getPdfUrl())
                // 이미지 URL 리스트
                .imageUrls(c.getImageUrls())
                // 체크리스트 항목별 사진
                .photos(photoResponses)
                // 도막 수치 높은 부위 목록
                .damagedParts(damagedParts)
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
            throw new UserNotAuthenticatedException();
        }
        String email = auth.getName();
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotAuthenticatedException("User not found: " + email));
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

            // 3. S3에 이미지 업로드하여 URL 생성 -> Data URI로 변환
            // List<String> imageUrls = s3Service.uploadImages(imagePaths);
            List<String> imageUrls = new ArrayList<>();
            for (String path : imagePaths) {
                byte[] bytes = Files.readAllBytes(Paths.get(path));
                String base64 = java.util.Base64.getEncoder().encodeToString(bytes);
                // MIME type detection simplified for example (assuming jpg/png from converter)
                String mimeType = "image/jpeg"; 
                if (path.toLowerCase().endsWith(".png")) mimeType = "image/png";
                
                imageUrls.add("data:" + mimeType + ";base64," + base64);
            }
            log.info("이미지 Data URI 변환 완료: {} 개", imageUrls.size());

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
                    .expireDate(LocalDate.now().plusYears(CERTIFICATE_VALIDITY_YEARS))
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
            String fileName = cert.getCertNumber() + ".pdf";
            File sourceFile = new File(localPdf);
            S3UploadResult uploadResult = s3Service.uploadFile(sourceFile, S3_CERTIFICATES_FOLDER, fileName, "application/pdf");

            cert.setPdfS3Key(uploadResult.getS3Key());
            cert.setPdfUrl(uploadResult.getCloudFrontUrl());

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
        Certificate certificate = certificateRepository.findById(id)
                .orElseThrow(() -> new CertificateNotFoundException(id));
        return toResponse(certificate);
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

    /**
     * 현재 로그인된 사용자가 발급받은 인증서 조회
     */
    @Transactional(readOnly = true)
    public List<CertificateResponse> getMyReceivedCertificates() {
        User currentUser = getCurrentUser();

        List<Certificate> certificates = certificateRepository.findByUserIdWithFetch(currentUser.getId());

        return certificates.stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    /**
     * Create certificate from existing checklist
     * 1. Retrieve checklist by ID
     * 2. Fetch photos by VIN
     * 3. Validate images with AI (match photos to checklist descriptions)
     * 4. Extract vehicle info from checklist
     * 5. Generate certificate PDF
     *
     * @param checklistId ID of the checklist
     * @param issuedBy Who is issuing the certificate
     * @return Certificate response with PDF URL
     * @throws ImageValidationException if AI validation fails
     */
    @Transactional
    public CertificateResponse createCertificateFromChecklist(Long checklistId, String issuedBy) {
        User currentUser = getCurrentUser();

        try {
            // 1. Get checklist
            VehicleChecklist checklist = checklistService.getChecklistById(checklistId);
            log.info("체크리스트로부터 인증서 생성 - 체크리스트 ID: {}, VIN: {}", checklistId, checklist.getVin());

            // 2. Validate VIN format
            String vin = checklist.getVin();
            if (vin == null || vin.trim().isEmpty()) {
                throw new IllegalArgumentException("VIN이 입력되지 않았습니다");
            }

            // VIN must be 17 characters
            if (vin.length() != 17) {
                throw new IllegalArgumentException(
                        String.format("VIN은 17자리여야 합니다 (현재: %d자리)", vin.length()));
            }

            // VIN should only contain alphanumeric characters (excluding I, O, Q to avoid confusion with 1, 0)
            String vinPattern = "^[A-HJ-NPR-Z0-9]{17}$";
            if (!vin.toUpperCase().matches(vinPattern)) {
                throw new IllegalArgumentException(
                        "VIN에 허용되지 않는 문자가 포함되어 있습니다. 영문(I, O, Q 제외)과 숫자만 허용됩니다.");
            }

            log.info("VIN 형식 검증 완료: {}", vin);

            // 3. Check if certificate already exists for this VIN
            Certificate existing = certificateRepository.findByVin(checklist.getVin()).orElse(null);
            if (existing != null) {
                log.info("VIN 중복: 기존 인증서 반환 - {}", existing.getCertNumber());
                return toResponse(existing);
            }

            // 4. Fetch photos by VIN for AI validation
            List<Photo> photos = photoService.getPhotosByVin(checklist.getVin());
            log.info("VIN: {} 에 대한 사진 조회 완료: {} 개", checklist.getVin(), photos.size());

            // 5. Build image URLs and descriptions for AI validation
            List<String> imageUrls = new ArrayList<>();
            List<String> descriptions = new ArrayList<>();

            // Create a map of photos by category+itemCode for easy lookup (support multiple photos per item)
            Map<String, List<Photo>> photoMap = photos.stream()
                    .collect(Collectors.groupingBy(
                            photo -> photo.getCategory() + "_" + photo.getItemCode()
                    ));

            // Match checklist items with photos - validate ALL photos for each item
            for (var item : checklist.getItems()) {
                String key = item.getCategory() + "_" + item.getCode();
                List<Photo> itemPhotos = photoMap.get(key);

                if (itemPhotos != null && !itemPhotos.isEmpty()) {
                    // Add all photos for this checklist item
                    for (Photo photo : itemPhotos) {
                        imageUrls.add(photo.getCloudFrontUrl());

                        // Build description from checklist item
                        String description = String.format("%s - %s: %s",
                                item.getCategory(),
                                item.getItem(),
                                item.getDetailedCriteria() != null ? item.getDetailedCriteria() : "상태 확인");

                        descriptions.add(description);
                        log.debug("이미지 매칭 완료 - {}: {} (사진 {}장 중 하나)", key, description, itemPhotos.size());
                    }
                }
            }

            // 6. Validate images with AI before generating certificate
            if (imageUrls.isEmpty()) {
                log.error("인증서 생성 불가: 업로드된 이미지가 없습니다. VIN: {}", checklist.getVin());
                throw new IllegalArgumentException(
                        "인증서 생성을 위해서는 최소 1개 이상의 검증 이미지가 필요합니다. " +
                        "체크리스트 항목에 해당하는 사진을 업로드해주세요.");
            }

            log.info("AI 이미지 검증 시작: {} 개 이미지", imageUrls.size());
            validateImagesWithDescriptions(imageUrls, descriptions);
            log.info("AI 이미지 검증 완료 - 모든 이미지 통과");

            // 7. Parse vehicle info JSON
            Map<String, Object> vehicleInfo;
            try {
                vehicleInfo = objectMapper.readValue(
                    checklist.getVehicleInfoJson(),
                    objectMapper.getTypeFactory().constructMapType(Map.class, String.class, Object.class)
                );
            } catch (Exception e) {
                log.error("차량 정보 JSON 파싱 실패", e);
                throw new RuntimeException("차량 정보 파싱 실패: " + e.getMessage());
            }

            // 8. Extract values from vehicle info with safe type conversion
            String manufacturer = getStringValue(vehicleInfo, "manufacturer");
            String modelName = getStringValue(vehicleInfo, "model");
            Integer manuYear = getIntegerValue(vehicleInfo, "year");
            String fuelType = getStringValue(vehicleInfo, "fuelType");
            Integer seatCount = getIntegerValue(vehicleInfo, "seatCount");
            String displacement = getStringValue(vehicleInfo, "displacement");
            String variant = getStringValue(vehicleInfo, "variant");

            // 9. Create Certificate entity
            String certNumber = genCert();
            LocalDate now = LocalDate.now();

            Certificate cert = Certificate.builder()
                    .user(currentUser)
                    .certNumber(certNumber)
                    .issueDate(now)
                    .expireDate(now.plusYears(CERTIFICATE_VALIDITY_YEARS))
                    .issuedBy(issuedBy)
                    .inspectDate(now)
                    .inspectCountry("KR") // Default to Korea
                    .manufacturer(manufacturer)
                    .modelName(modelName)
                    .vin(checklist.getVin())
                    .manuYear(manuYear)
                    .manufactureYear(manuYear)
                    .fuelType(fuelType)
                    .seatCount(seatCount)
                    .displacement(displacement)
                    .variant(variant)
                    .jaaiGrade(calculateGrade(checklist.getTotalScore(), checklist.getMaxTotalScore()))
                    .aisScore(String.valueOf(checklist.getTotalScore()))
                    .comment(String.format("체크리스트 평가 점수: %d/%d (%s)",
                            checklist.getTotalScore(),
                            checklist.getMaxTotalScore(),
                            checklist.getStatus()))
                    .build();

            log.info("PDF 생성 직전 - VIN: {}, manufacturer: {}, modelName: {}",
                    cert.getVin(), cert.getManufacturer(), cert.getModelName());

            // 10. Generate PDF
            String localPdf = pdfParser.createCertificatePdf(cert);

            // 11. Upload PDF to S3
            String fileName = cert.getCertNumber() + ".pdf";
            File sourceFile = new File(localPdf);
            S3UploadResult uploadResult = s3Service.uploadFile(sourceFile, S3_CERTIFICATES_FOLDER, fileName, "application/pdf");

            cert.setPdfS3Key(uploadResult.getS3Key());
            cert.setPdfUrl(uploadResult.getCloudFrontUrl());

            // Delete local file
            s3Service.deleteLocalFile(localPdf);

            // 12. Save certificate
            certificateRepository.save(cert);
            log.info("체크리스트로부터 인증서 생성 완료 - 인증서 번호: {}, VIN: {}", cert.getCertNumber(), cert.getVin());

            return toResponse(cert);

        } catch (ImageValidationException e) {
            // Re-throw image validation exception with full details
            log.error("AI 이미지 검증 실패로 인증서 생성 중단", e);
            throw e;
        } catch (IllegalArgumentException e) {
            log.warn("체크리스트 조회 실패: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("체크리스트로부터 인증서 생성 실패", e);
            throw new RuntimeException("인증서 생성 실패: " + e.getMessage(), e);
        }
    }

    /**
     * Calculate grade based on score percentage
     */
    private String calculateGrade(Integer totalScore, Integer maxTotalScore) {
        if (totalScore == null || maxTotalScore == null || maxTotalScore == 0) {
            return "N/A";
        }

        double percentage = (totalScore.doubleValue() / maxTotalScore.doubleValue()) * 100;

        if (percentage >= 90) return "S";
        if (percentage >= 80) return "A";
        if (percentage >= 70) return "B";
        if (percentage >= 60) return "C";
        if (percentage >= 50) return "D";
        return "F";
    }

    /**
     * Safe extraction of String value from Map
     */
    private String getStringValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        return value != null ? value.toString() : null;
    }

    /**
     * Safe extraction of Integer value from Map
     */
    private Integer getIntegerValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) return null;

        if (value instanceof Integer) {
            return (Integer) value;
        } else if (value instanceof Number) {
            return ((Number) value).intValue();
        } else {
            try {
                return Integer.parseInt(value.toString());
            } catch (NumberFormatException e) {
                log.warn("Failed to parse integer value for key {}: {}", key, value);
                return null;
            }
        }
    }

    // ========== 앱 API 호환성: 추가 메서드 ==========

    /**
     * 인증서 재발급
     */
    @Transactional
    public CertificateResponse reissueCertificate(Long originalId, User issuer, String reason, String additionalNotes) {
        Certificate original = certificateRepository.findById(originalId)
                .orElseThrow(() -> new IllegalArgumentException("인증서를 찾을 수 없습니다: " + originalId));

        // 새 인증서 생성 (원본 데이터 복사)
        Certificate newCert = Certificate.builder()
                .user(original.getUser())
                .certNumber(genCert())
                .issueDate(LocalDate.now())
                .expireDate(LocalDate.now().plusYears(CERTIFICATE_VALIDITY_YEARS))
                .inspectDate(original.getInspectDate())
                .inspectCountry(original.getInspectCountry())
                .inspectSite(original.getInspectSite())
                .manufacturer(original.getManufacturer())
                .modelName(original.getModelName())
                .vin(original.getVin() + "-R" + (original.getReissueCount() != null ? original.getReissueCount() + 1 : 1))
                .manuYear(original.getManuYear())
                .manufactureYear(original.getManufactureYear())
                .firstRegisterDate(original.getFirstRegisterDate())
                .mileage(original.getMileage())
                .variant(original.getVariant())
                .fuelType(original.getFuelType())
                .seatCount(original.getSeatCount())
                .displacement(original.getDisplacement())
                .inspectorCode(original.getInspectorCode())
                .inspectorName(original.getInspectorName())
                .issuedBy(issuer.getEmail())
                .issuedByName(issuer.getName())
                .issuedByCompany(issuer.getCompany())
                .issuedAt(LocalDateTime.now())
                .issuerUserId(issuer.getId())
                .status(CertificateStatus.VALID)
                .originalCertificateId(originalId)
                .reissueCount(original.getReissueCount() != null ? original.getReissueCount() + 1 : 1)
                .comment(reason != null ? "재발급 사유: " + reason + (additionalNotes != null ? " / " + additionalNotes : "") : null)
                .build();

        newCert.addIssuer(issuer.getId());

        // 원본 인증서 재발급 횟수 증가
        original.setReissueCount(original.getReissueCount() != null ? original.getReissueCount() + 1 : 1);
        certificateRepository.save(original);

        Certificate saved = certificateRepository.save(newCert);
        log.info("인증서 재발급 완료 - 원본 ID: {}, 새 ID: {}, 새 인증번호: {}", originalId, saved.getId(), saved.getCertNumber());

        return toResponse(saved);
    }

    /**
     * 인증서 취소
     */
    @Transactional
    public CertificateResponse revokeCertificate(Long id, User revoker, String reason) {
        Certificate certificate = certificateRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("인증서를 찾을 수 없습니다: " + id));

        if (certificate.getStatus() == CertificateStatus.REVOKED) {
            throw new IllegalStateException("이미 취소된 인증서입니다");
        }

        certificate.setStatus(CertificateStatus.REVOKED);
        certificate.setRevokedAt(LocalDateTime.now());
        certificate.setRevokeReason(reason);
        certificate.setRevokedByUserId(revoker.getId());

        Certificate saved = certificateRepository.save(certificate);
        log.info("인증서 취소 완료 - ID: {}, 인증번호: {}, 취소자: {}", id, saved.getCertNumber(), revoker.getEmail());

        return toResponse(saved);
    }

    /**
     * 키워드 검색
     */
    public List<CertificateResponse> searchByKeyword(String keyword) {
        List<Certificate> certificates = certificateRepository.searchByKeyword(keyword);
        return certificates.stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    /**
     * 고급 검색
     */
    public List<CertificateResponse> advancedSearch(
            String certNumber, String manufacturer, String modelName, String vin,
            String country, CertificateStatus status,
            LocalDate issueDateFrom, LocalDate issueDateTo,
            LocalDate expireDateFrom, LocalDate expireDateTo,
            String inspectorName) {

        List<Certificate> certificates = certificateRepository.advancedSearch(
                certNumber, manufacturer, modelName, vin, country, status,
                issueDateFrom, issueDateTo, expireDateFrom, expireDateTo, inspectorName);

        return certificates.stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    /**
     * 인증서 통계 조회
     */
    public CertificateStatsResponse getCertificateStats(Long userId) {
        LocalDate today = LocalDate.now();
        LocalDate expiringSoon = today.plusDays(30);

        long total = certificateRepository.count();
        long valid = certificateRepository.countValidCertificates(today);
        long expired = certificateRepository.countExpiredCertificates(today);
        long expiringSoonCount = certificateRepository.countExpiringSoonCertificates(today, expiringSoon);
        long revoked = certificateRepository.countByStatus(CertificateStatus.REVOKED);
        long myIssued = certificateRepository.countByIssuerUserId(userId);
        long myReceived = certificateRepository.countByUserId(userId);

        return CertificateStatsResponse.builder()
                .totalCertificates(total)
                .validCertificates(valid)
                .expiredCertificates(expired)
                .expiringSoonCertificates(expiringSoonCount)
                .revokedCertificates(revoked)
                .myIssuedCertificates(myIssued)
                .myReceivedCertificates(myReceived)
                .build();
    }
}
