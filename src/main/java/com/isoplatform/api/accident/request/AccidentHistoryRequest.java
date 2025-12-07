package com.isoplatform.api.accident.request;

import com.isoplatform.api.accident.AccidentType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PastOrPresent;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import java.time.LocalDate;

@Getter
@Setter
public class AccidentHistoryRequest {

    @NotBlank(message = "VIN은 필수입니다")
    @Size(min = 17, max = 17, message = "VIN은 정확히 17자여야 합니다")
    @Pattern(regexp = "^[A-HJ-NPR-Z0-9]{17}$", message = "VIN 형식이 올바르지 않습니다")
    private String vin;

    @NotNull(message = "사고 유형은 필수입니다")
    private AccidentType accidentType;

    @NotNull(message = "사고 일자는 필수입니다")
    @PastOrPresent(message = "사고 일자는 미래일 수 없습니다")
    private LocalDate accidentDate;

    private boolean repaired;

    @Size(max = 500, message = "비고는 500자 이하입니다")
    private String remarks;
}
