package com.isoplatform.api.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {

    @NotBlank(message = "Email or username is required")
    private String usernameOrEmail;

    @NotBlank(message = "Password is required")
    private String password;
}
