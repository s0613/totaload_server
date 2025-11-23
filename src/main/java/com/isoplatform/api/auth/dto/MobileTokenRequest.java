package com.isoplatform.api.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class MobileTokenRequest {
    @NotBlank(message = "Authorization code is required")
    private String authorizationCode;

    @NotBlank(message = "Code verifier is required")
    private String codeVerifier;

    @NotBlank(message = "Redirect URI is required")
    private String redirectUri;

    private String deviceInfo;
}
