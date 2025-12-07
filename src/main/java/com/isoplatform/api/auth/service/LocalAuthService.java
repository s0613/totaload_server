package com.isoplatform.api.auth.service;

import com.isoplatform.api.auth.RefreshToken;
import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.dto.AuthResponse;
import com.isoplatform.api.auth.dto.LoginRequest;
import com.isoplatform.api.auth.dto.SignupRequest;
import com.isoplatform.api.auth.exception.EmailAlreadyExistsException;
import com.isoplatform.api.auth.exception.InvalidCredentialsException;
import com.isoplatform.api.auth.exception.OAuth2UserCannotLoginLocallyException;
import com.isoplatform.api.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class LocalAuthService {

    private static final String PROVIDER_LOCAL = "LOCAL";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;

    @Value("${jwt.expiration-time:3600000}")
    private Long accessTokenExpirationMs;

    @Transactional
    public AuthResponse signup(SignupRequest request) {
        // Check if email already exists
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            log.warn("Attempted registration with existing email: {}", request.getEmail());
            throw new EmailAlreadyExistsException("Unable to complete registration");
        }

        // Create new user
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .company(request.getCompany() != null ? request.getCompany() : "SELF")
                .provider(PROVIDER_LOCAL)
                .role(Role.USER)
                .build();

        user = userRepository.save(user);
        log.info("Registered new local user: {}", user.getEmail());

        // Generate tokens
        String accessToken = jwtTokenProvider.generateToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return AuthResponse.of(
                accessToken,
                refreshToken.getToken(),
                accessTokenExpirationMs / 1000, // Convert to seconds
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getRole().name(),
                user.getCompany()
        );
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        // Find user by username or email
        String usernameOrEmail = request.getUsernameOrEmail();
        User user = userRepository.findByUsername(usernameOrEmail)
                .or(() -> userRepository.findByEmail(usernameOrEmail))
                .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

        // Check if provider is LOCAL
        if (!PROVIDER_LOCAL.equals(user.getProvider())) {
            throw new OAuth2UserCannotLoginLocallyException(
                    "Please login with " + user.getProvider());
        }

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        log.info("User logged in: {}", user.getEmail());

        // Generate tokens
        String accessToken = jwtTokenProvider.generateToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return AuthResponse.of(
                accessToken,
                refreshToken.getToken(),
                accessTokenExpirationMs / 1000,
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getRole().name(),
                user.getCompany()
        );
    }

    @Transactional
    public AuthResponse refreshAccessToken(String refreshTokenString) {
        // Verify refresh token
        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(refreshTokenString);
        User user = refreshToken.getUser();

        // Generate new access token
        String accessToken = jwtTokenProvider.generateToken(user);

        // Rotate refresh token (for enhanced security)
        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

        log.info("Refreshed access token for user: {}", user.getEmail());

        return AuthResponse.of(
                accessToken,
                newRefreshToken.getToken(),
                accessTokenExpirationMs / 1000,
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getRole().name(),
                user.getCompany()
        );
    }

    @Transactional
    public void logout(String refreshTokenString) {
        RefreshToken token = refreshTokenService.verifyRefreshToken(refreshTokenString);
        refreshTokenService.revokeToken(refreshTokenString);
        log.info("User logged out successfully: {}", token.getUser().getEmail());
    }
}
