package com.isoplatform.api.auth.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class WithdrawResponse {
    private boolean success;
    private String message;

    public static WithdrawResponse success() {
        return WithdrawResponse.builder()
                .success(true)
                .message("회원 탈퇴가 완료되었습니다.")
                .build();
    }
}
