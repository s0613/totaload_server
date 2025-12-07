package com.isoplatform.api.certification.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;
import java.util.List;

@Getter
@Setter
public class CertificateRequest {

    @NotBlank(message = "차대번호는 필수입니다")
    private String vin;            // 차대번호

    @NotBlank(message = "제조사는 필수입니다")
    private String manufacturer;   // 제조사

    @NotBlank(message = "모델명은 필수입니다")
    private String modelName;      // 모델명

    private Integer manufactureYear;       // 제조연도
    private LocalDate firstRegisterDate;   // 최초등록일
    private Integer mileage;               // 주행거리

    @NotNull(message = "검사일자는 필수입니다")
    private LocalDate inspectDate; // 검사일자

    @NotBlank(message = "평가사 코드는 필수입니다")
    private String inspectorCode;  // 평가사 코드

    @NotBlank(message = "평가사 성명은 필수입니다")
    private String inspectorName;  // 평가사 성명

    private String signaturePath;  // 서명 이미지 경로 (선택)

    // PDF에 추가로 들어갈 수 있는 필드들
    private String certNumber;     // 인증서 번호 (자동생성되지만 수동 지정 가능)
    private LocalDate issueDate;   // 발급일 (기본값: 현재날짜)
    private LocalDate expireDate;  // 만료일 (기본값: 1년 후)
    private String issuedBy;       // 발급기관명 (컨트롤러에서 전달되지만 요청에서도 받을 수 있음)

    // 1) 발급/검증 추가 필드
    private String inspectCountry; // 검사국가
    private String inspectSite;    // 검사장소
    private String eVerifyId;      // 전자검증번호
    private String verifyUrl;      // 검증URL

    // 2) 차량 식별 추가 정보
    private Integer manuYear;              // 제조연도 (새 필드명)
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

    // 3) 치수·중량
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

    // 4) 파워트레인·배출
    private String engineType;      // 엔진형식
    private Integer cylinderCount;  // 실린더수
    private String engineDisplacement; // 엔진 배기량
    private String induction;       // 흡기방식
    private String enginePower;     // 정격출력(kW)
    private String emissionStd;     // 배출가스기준
    private String motorPower;      // 전기모터출력
    private String batteryVoltage;  // 배터리전압
    private String transmission;    // 변속기
    private String brakeType;       // 브레이크방식
    private String fuelEconomy;     // 연비지표

    // 5) 등급/결함
    private String jaaiGrade;       // JAAI등급
    private String aisScore;        // AIS점수
    private String aisDefectCode;   // AIS결함코드
    private String repairHistory;   // 수리이력
    private String comment;         // 코멘트

    // 6) 수입국 규정
    private String destinationCountry; // 대상국
    private String validityNote;    // 유효기간비고
    private String disclaimer;      // 면책사항

    // 7) 방사선 (항균으로 변경)
    private String radiationResult; // 방사선결과 (항균)

    // 이미지-설명 검증을 위한 필드들
    private List<String> imageUrls;          // 검증할 이미지 URL들
    private List<String> descriptions;       // 각 이미지에 대한 설명들
}