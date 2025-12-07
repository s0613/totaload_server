package com.isoplatform.api.auth.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class MobileTokenResponse {
    private String accessToken;
    private String refreshToken;
    private long expiresIn;
    private String email;
    private String name;
}
