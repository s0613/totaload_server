package com.isoplatform.api.auth.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthResponse {

    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private Long expiresIn;

    // User info
    private Long userId;
    private String email;
    private String name;
    private String role;

    public static AuthResponse of(String accessToken, String refreshToken, Long expiresIn,
                                   Long userId, String email, String name, String role) {
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(expiresIn)
                .userId(userId)
                .email(email)
                .name(name)
                .role(role)
                .build();
    }
}
