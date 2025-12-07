package com.isoplatform.api.accident.response;

import com.isoplatform.api.accident.AccidentHistory;
import com.isoplatform.api.accident.AccidentType;
import lombok.Builder;
import lombok.Getter;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Getter
@Builder
public class AccidentHistoryResponse {

    private Long id;
    private String vin;
    private AccidentType accidentType;
    private String accidentTypeName;
    private LocalDate accidentDate;
    private boolean repaired;
    private String remarks;
    private Long registeredBy;
    private LocalDateTime createdAt;

    public static AccidentHistoryResponse from(AccidentHistory entity) {
        return AccidentHistoryResponse.builder()
                .id(entity.getId())
                .vin(entity.getVin())
                .accidentType(entity.getAccidentType())
                .accidentTypeName(entity.getAccidentType().getDisplayName())
                .accidentDate(entity.getAccidentDate())
                .repaired(entity.isRepaired())
                .remarks(entity.getRemarks())
                .registeredBy(entity.getRegisteredBy())
                .createdAt(entity.getCreatedAt())
                .build();
    }
}
