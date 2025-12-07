package com.isoplatform.api.certification.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * 체크리스트 항목별 사진 정보 응답 DTO
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PhotoResponse {
    private Long id;
    private String category;      // A, B, C, D, E
    private String itemCode;      // A1, A2, B1, etc.
    private String cloudFrontUrl; // 이미지 URL
    private String fileName;
}
