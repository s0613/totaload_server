package com.isoplatform.api.auth.dto;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AuthDtoValidationTest {

    private static Validator validator;

    @BeforeAll
    static void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Test
    void signupRequest_shouldFailWithInvalidEmail() {
        SignupRequest request = new SignupRequest();
        request.setEmail("invalid-email");
        request.setPassword("Password123!");
        request.setName("Test User");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty());
        assertTrue(violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("email")));
    }

    @Test
    void signupRequest_shouldFailWithShortPassword() {
        SignupRequest request = new SignupRequest();
        request.setEmail("test@example.com");
        request.setPassword("short");
        request.setName("Test User");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty());
        assertTrue(violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("password")));
    }

    @Test
    void signupRequest_shouldPassWithValidData() {
        SignupRequest request = new SignupRequest();
        request.setEmail("test@example.com");
        request.setPassword("Password123!");
        request.setName("Test User");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(request);

        assertTrue(violations.isEmpty());
    }

    @Test
    void loginRequest_shouldFailWithBlankFields() {
        LoginRequest request = new LoginRequest();
        request.setEmail("");
        request.setPassword("");

        Set<ConstraintViolation<LoginRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty());
        assertEquals(2, violations.size());
    }

    @Test
    void refreshTokenRequest_shouldFailWithBlankToken() {
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("");

        Set<ConstraintViolation<RefreshTokenRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty());
    }
}
