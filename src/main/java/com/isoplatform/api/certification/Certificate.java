package com.isoplatform.api.certification;

import com.fasterxml.jackson.databind.JsonNode;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.certification.converter.JsonNodeConverter;
import com.isoplatform.api.certification.converter.VehicleDetailsConverter;
import com.isoplatform.api.certification.domain.VehicleDetails;
import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "certificates")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Certificate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;  // PK

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // 인증서 고유 정보
    @Column(nullable = false, unique = true)
    private String certNumber;     // 인증번호

    @Column(nullable = false)
    private LocalDate issueDate;   // 발급일자

    @Column(nullable = false)
    private LocalDate expireDate;  // 유효일자

    @Column(nullable = false)
    private LocalDate inspectDate; // 검사일자

    // 검사 정보 추가
    private String inspectCountry; // 검사국가
    private String inspectSite;    // 검사장소
    private String eVerifyId;      // 전자검증번호
    private String verifyUrl;      // 검증URL

    // 자동차 정보
    @Column(nullable = false)
    private String manufacturer;   // 제조사

    @Column(nullable = false)
    private String modelName;      // 모델명

    @Column(nullable = false, unique = true)
    private String vin;            // 차대번호

    private Integer manufactureYear;       // 제조연도 (기존)
    private Integer manuYear;              // 제조연도 (새 필드명)
    private LocalDate firstRegisterDate;   // 최초등록일
    private Integer mileage;               // 주행거리

    // 차량 식별 추가 정보
    private String variant;         // 트림/파생형
    private String engineNumber;    // 엔진번호
    private String displacement;    // 배기량
    private Integer modelYear;      // 모델연식
    private String usecase;         // 용도
    private String colorCode;       // 외장색상코드
    private Integer seatCount;      // 좌석수
    private Integer doorCount;      // 도어수
    private String fuelType;        // 연료
    private String driveType;       // 구동방식
    private String odoType;         // 오도미터종류

    // 치수·중량
    private String length;          // 전장
    private String width;           // 전폭
    private String height;          // 전고
    private String wheelbase;       // 휠베이스
    private String trackFront;      // 전륜윤거
    private String gvm;             // 총중량
    private String curbWeight;      // 공차중량
    private String axleFront;       // 전축하중
    private String axleRear;        // 후축하중
    private String bodyType;        // 차체형식

    // 파워트레인·배출
    private String engineType;      // 엔진형식
    private Integer cylinderCount;  // 실린더수
    private String engineDisplacement; // 배기량
    private String induction;       // 흡기방식
    private String enginePower;     // 정격출력(kW)
    private String emissionStd;     // 배출가스기준
    private String motorPower;      // 전기모터출력
    private String batteryVoltage;  // 배터리전압
    private String transmission;    // 변속기
    private String brakeType;       // 브레이크방식
    private String fuelEconomy;     // 연비지표

    // 등급/결함
    private String jaaiGrade;       // JAAI등급
    private String aisScore;        // AIS점수
    private String aisDefectCode;   // AIS결함코드
    private String repairHistory;   // 수리이력
    private String comment;         // 코멘트

    // 수입국 규정
    private String destinationCountry; // 대상국
    private String validityNote;    // 유효기간비고
    private String disclaimer;      // 면책사항

    // 방사선 (항균으로 변경)
    private String radiationResult; // 방사선결과 (항균)

    // 평가사 정보
    private String inspectorCode;  // 평가사 코드
    private String inspectorName;  // 평가사 성명

    // AI Analysis
    @Column(columnDefinition = "JSON")
    @Convert(converter = JsonNodeConverter.class)
    private JsonNode aiAnalysis;

    @Column(precision = 5, scale = 2)
    private BigDecimal aiConfidence;

    // All other vehicle specifications stored as JSON
    @Column(columnDefinition = "JSON")
    @Convert(converter = VehicleDetailsConverter.class)
    private VehicleDetails vehicleDetails;

    // PDF 관련 필드 추가
    private String pdfS3Key;          // S3 키
    private String pdfUrl;            // CloudFront URL
    private String s3Bucket;          // S3 bucket name
    // 서명 이미지 (선택)
    private String signaturePath;  // Authorized Signature 이미지 경로 (S3 또는 서버 경로)

    // 발급자 ID 리스트 (JSON 형태로 저장) - iso-server 통합
    @ElementCollection
    @CollectionTable(name = "certificate_issuers", joinColumns = @JoinColumn(name = "certificate_id"))
    @Column(name = "issuer_user_id")
    @Builder.Default
    private List<Long> issuerUserIds = new ArrayList<>();

    // 발급 메타데이터 - 호환성을 위해 유지
    private String issuedBy;       // 발급자 이메일
    private String issuedByName;   // 발급자 성명
    private String issuedByCompany; // 발급자 소속회사

    @Column(name = "issued_at")
    private LocalDateTime issuedAt; // 발급 시각

    @Column(name = "issuer_user_id")
    private Long issuerUserId;     // 발급자 User ID (FK 역할)

    // Verification
    private Boolean verified;      // 검증 여부

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "verified_by")
    private User verifiedBy;       // 검증한 사용자

    // Status tracking (reissue/revoke 지원)
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    @Builder.Default
    private CertificateStatus status = CertificateStatus.VALID;

    private LocalDateTime revokedAt;      // 취소 일시
    private String revokeReason;           // 취소 사유
    private Long revokedByUserId;          // 취소한 사용자 ID

    // Reissue tracking
    private Long originalCertificateId;    // 재발급 시 원본 인증서 ID
    private Integer reissueCount;          // 재발급 횟수

    // 이미지 URL 리스트 (인증서 생성 시 첨부된 이미지들)
    @ElementCollection
    @CollectionTable(name = "certificate_images", joinColumns = @JoinColumn(name = "certificate_id"))
    @Column(name = "image_url")
    @Builder.Default
    private List<String> imageUrls = new ArrayList<>();

    // 헬퍼 메서드들 - iso-server 통합
    public void addIssuer(Long userId) {
        if (issuerUserIds == null) {
            issuerUserIds = new ArrayList<>();
        }
        if (!issuerUserIds.contains(userId)) {
            issuerUserIds.add(userId);
        }
    }

    public void removeIssuer(Long userId) {
        if (issuerUserIds != null) {
            issuerUserIds.remove(userId);
        }
    }

    public boolean hasIssuer(Long userId) {
        return issuerUserIds != null && issuerUserIds.contains(userId);
    }
}
