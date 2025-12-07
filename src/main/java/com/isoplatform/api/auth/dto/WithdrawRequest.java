package com.isoplatform.api.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class WithdrawRequest {

    private String reason;  // 탈퇴 사유 (선택)

    private String password;  // LOCAL 사용자의 경우 비밀번호 확인
}
