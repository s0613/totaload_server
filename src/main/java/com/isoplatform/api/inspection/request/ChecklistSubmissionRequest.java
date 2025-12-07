package com.isoplatform.api.inspection.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class ChecklistSubmissionRequest {

    @NotBlank(message = "차량번호는 필수입니다")
    private String vehicleNumber;

    @NotBlank(message = "VIN은 필수입니다")
    private String vin;

    @NotNull(message = "차량 정보는 필수입니다")
    private Map<String, Object> vehicleInfo;

    @NotNull(message = "체크리스트 항목은 필수입니다")
    private List<ChecklistItemData> items;

    private String status = "completed";

    private List<String> damagedParts; // 도막 수치가 높은 부위 목록

    @Data
    public static class ChecklistItemData {
        @NotBlank(message = "항목 코드는 필수입니다")
        private String code;

        @NotBlank(message = "카테고리는 필수입니다")
        private String category;

        @NotBlank(message = "항목명은 필수입니다")
        private String item;

        private String detailedCriteria;

        @NotNull(message = "최대 점수는 필수입니다")
        private Integer maxScore;

        @NotNull(message = "점수는 필수입니다")
        private Integer score;

        private String evidence;
        private String remarks;
    }
}
