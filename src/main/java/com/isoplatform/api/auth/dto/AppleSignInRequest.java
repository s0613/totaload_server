package com.isoplatform.api.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class AppleSignInRequest {

    @NotBlank(message = "identityToken is required")
    private String identityToken;  // Apple에서 받은 JWT

    private String authorizationCode;  // 선택적

    private String name;  // 첫 로그인 시에만 제공됨

    private String email;  // 첫 로그인 시에만 제공됨 (identityToken에서도 추출 가능)

    private String deviceInfo;  // 디바이스 정보 (선택)
}
