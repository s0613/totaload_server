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
    void signupRequest_shouldFailWithLettersOnlyPassword() {
        SignupRequest request = new SignupRequest();
        request.setEmail("test@example.com");
        request.setPassword("abcdefgh");
        request.setName("Test User");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty());
        assertTrue(violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("password")));
    }

    @Test
    void signupRequest_shouldFailWithNumbersOnlyPassword() {
        SignupRequest request = new SignupRequest();
        request.setEmail("test@example.com");
        request.setPassword("12345678");
        request.setName("Test User");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty());
        assertTrue(violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("password")));
    }

    @Test
    void signupRequest_shouldPassWithAlphanumericPassword() {
        SignupRequest request = new SignupRequest();
        request.setEmail("test@example.com");
        request.setPassword("abc12345");
        request.setName("Test User");

        Set<ConstraintViolation<SignupRequest>> violations = validator.validate(request);

        assertTrue(violations.isEmpty());
    }

    @Test
    void loginRequest_shouldFailWithBlankFields() {
        LoginRequest request = new LoginRequest();
        request.setUsernameOrEmail("");
        request.setPassword("");

        Set<ConstraintViolation<LoginRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty());
        assertEquals(2, violations.size());
    }

    @Test
    void loginRequest_shouldPassWithUsernameOrEmail() {
        // Test with email
        LoginRequest request1 = new LoginRequest();
        request1.setUsernameOrEmail("user@example.com");
        request1.setPassword("password123");

        Set<ConstraintViolation<LoginRequest>> violations1 = validator.validate(request1);
        assertTrue(violations1.isEmpty());

        // Test with username
        LoginRequest request2 = new LoginRequest();
        request2.setUsernameOrEmail("testuser");
        request2.setPassword("password123");

        Set<ConstraintViolation<LoginRequest>> violations2 = validator.validate(request2);
        assertTrue(violations2.isEmpty());
    }

    @Test
    void refreshTokenRequest_shouldFailWithBlankToken() {
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("");

        Set<ConstraintViolation<RefreshTokenRequest>> violations = validator.validate(request);

        assertFalse(violations.isEmpty());
    }
}
