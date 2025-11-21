package com.isoplatform.api.auth.handler;

import com.isoplatform.api.auth.RefreshToken;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.auth.service.JwtTokenProvider;
import com.isoplatform.api.auth.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;

    @Value("${frontend.url}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication) throws IOException {
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String email = oauth2User.getAttribute("email");

        log.info("OAuth2 authentication successful for: {}", email);

        // Find user from database
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found after OAuth2 login"));

        // Generate JWT access token
        String accessToken = jwtTokenProvider.generateToken(user);

        // Generate refresh token
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        // Get redirect URL from request parameter (for mobile deep links)
        String redirectUrl = request.getParameter("redirectUrl");

        String targetUrl;
        if (redirectUrl != null && !redirectUrl.isEmpty()) {
            // Mobile deep link with tokens
            targetUrl = UriComponentsBuilder.fromUriString(redirectUrl)
                    .queryParam("access_token", accessToken)
                    .queryParam("refresh_token", refreshToken.getToken())
                    .queryParam("token_type", "Bearer")
                    .build()
                    .toUriString();

            log.info("OAuth2 login successful for user: {} - redirecting to mobile deep link", email);
        } else {
            // Web redirect (default) with tokens
            targetUrl = UriComponentsBuilder.fromUriString(frontendUrl)
                    .queryParam("access_token", accessToken)
                    .queryParam("refresh_token", refreshToken.getToken())
                    .queryParam("token_type", "Bearer")
                    .build()
                    .toUriString();

            log.info("OAuth2 login successful for user: {} - redirecting to web URL", email);
        }

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
