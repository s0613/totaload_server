package com.isoplatform.api.auth.service;

import com.isoplatform.api.auth.dto.SignupRequest;
import com.isoplatform.api.auth.dto.SignupResponse;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    @Test
    void shouldSignupNewUser() {
        // Given
        SignupRequest request = SignupRequest.builder()
                .email("test@example.com")
                .username("testuser")
                .password("password123")
                .confirmPassword("password123")
                .name("Test User")
                .build();

        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(userRepository.existsByUsername(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(userRepository.save(any(User.class))).thenAnswer(i -> {
            User user = i.getArgument(0);
            user.setId(1L);
            return user;
        });

        // When
        SignupResponse response = authService.signup(request);

        // Then
        assertThat(response.isSuccess()).isTrue();
        assertThat(response.getUserId()).isEqualTo(1L);
        verify(userRepository).save(any(User.class));
    }

    @Test
    void shouldFailSignupWhenPasswordsDontMatch() {
        // Given
        SignupRequest request = SignupRequest.builder()
                .email("test@example.com")
                .username("testuser")
                .password("password123")
                .confirmPassword("different")
                .name("Test User")
                .build();

        // When & Then
        assertThatThrownBy(() -> authService.signup(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("비밀번호가 일치하지 않습니다");
    }

    @Test
    void shouldFailSignupWhenEmailExists() {
        // Given
        SignupRequest request = SignupRequest.builder()
                .email("test@example.com")
                .username("testuser")
                .password("password123")
                .confirmPassword("password123")
                .name("Test User")
                .build();

        when(userRepository.existsByEmail(anyString())).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> authService.signup(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("이미 사용 중인 이메일입니다");
    }

    @Test
    void shouldFailSignupWhenUsernameExists() {
        // Given
        SignupRequest request = SignupRequest.builder()
                .email("test@example.com")
                .username("testuser")
                .password("password123")
                .confirmPassword("password123")
                .name("Test User")
                .build();

        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(userRepository.existsByUsername(anyString())).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> authService.signup(request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("이미 사용 중인 사용자명입니다");
    }
}
