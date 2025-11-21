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
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Set<String> ALLOWED_REDIRECT_SCHEMES = Set.of("totaload", "myapp");

    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;

    @Value("${frontend.url}")
    private String frontendUrl;

    @Value("${auth.allowed-redirect-domains:localhost:3000}")
    private List<String> allowedRedirectDomains;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication) throws IOException {
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String email = oauth2User.getAttribute("email");

        log.info("OAuth2 authentication successful for: {}", email);

        // Find user from database
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.error("OAuth2 authentication succeeded but user not found in database for email hash: {}",
                            email.hashCode()); // Don't log full email
                    return new IllegalStateException("User account not found");
                });

        // Generate JWT access token
        String accessToken = jwtTokenProvider.generateToken(user);

        // Generate refresh token
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        // Get redirect URL from request parameter (for mobile deep links)
        String redirectUrl = request.getParameter("redirectUrl");

        String targetUrl;
        if (redirectUrl != null && !redirectUrl.isEmpty()) {
            // Validate redirect URL before using it
            validateRedirectUrl(redirectUrl);

            // Mobile deep link with tokens in fragment (more secure)
            String fragment = String.format("access_token=%s&refresh_token=%s&token_type=Bearer",
                    URLEncoder.encode(accessToken, StandardCharsets.UTF_8),
                    URLEncoder.encode(refreshToken.getToken(), StandardCharsets.UTF_8));

            targetUrl = UriComponentsBuilder.fromUriString(redirectUrl)
                    .fragment(fragment)
                    .build()
                    .toUriString();

            log.info("OAuth2 login successful for user: {} - redirecting to mobile deep link", email);
        } else {
            // Web redirect (default) with tokens in fragment (more secure)
            String fragment = String.format("access_token=%s&refresh_token=%s&token_type=Bearer",
                    URLEncoder.encode(accessToken, StandardCharsets.UTF_8),
                    URLEncoder.encode(refreshToken.getToken(), StandardCharsets.UTF_8));

            targetUrl = UriComponentsBuilder.fromUriString(frontendUrl)
                    .fragment(fragment)
                    .build()
                    .toUriString();

            log.info("OAuth2 login successful for user: {} - redirecting to web URL", email);
        }

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    /**
     * Validates the redirect URL to prevent open redirect attacks.
     * Only allows whitelisted mobile deep link schemes and approved domains.
     *
     * @param redirectUrl The URL to validate
     * @throws IllegalArgumentException if the URL is not in the whitelist
     */
    private void validateRedirectUrl(String redirectUrl) {
        if (redirectUrl == null || redirectUrl.isEmpty()) {
            return; // Will use default frontend URL
        }

        try {
            URI uri = new URI(redirectUrl);
            String scheme = uri.getScheme();

            // Allow whitelisted mobile deep link schemes
            if (ALLOWED_REDIRECT_SCHEMES.contains(scheme)) {
                log.info("Valid mobile deep link scheme: {}", scheme);
                return;
            }

            // For HTTP/HTTPS, check against allowed domains
            if ("http".equals(scheme) || "https".equals(scheme)) {
                String authority = uri.getAuthority();
                if (allowedRedirectDomains != null && allowedRedirectDomains.contains(authority)) {
                    log.info("Valid redirect domain: {}", authority);
                    return;
                }
            }

            log.warn("Rejected redirect URL - not in whitelist: {}", redirectUrl);
            throw new IllegalArgumentException("Redirect URL not in whitelist");
        } catch (URISyntaxException e) {
            log.warn("Invalid redirect URL syntax: {}", redirectUrl);
            throw new IllegalArgumentException("Invalid redirect URL format");
        }
    }
}
