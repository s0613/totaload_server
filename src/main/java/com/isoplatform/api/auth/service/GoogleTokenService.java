package com.isoplatform.api.auth.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import lombok.Data;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import java.util.Arrays;
import java.util.Collections;

@Service
@Slf4j
public class GoogleTokenService {

    private static final String GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";

    private final RestTemplate restTemplate;

    // Web client (기존 - client_secret 사용)
    private final String webClientId;
    private final String webClientSecret;

    // Mobile clients (PKCE - client_secret 없음)
    private final String mobileAndroidClientId;
    private final String mobileIosClientId;
    private final String mobileRedirectUri;

    private final GoogleIdTokenVerifier webVerifier;
    private final GoogleIdTokenVerifier mobileVerifier;

    public GoogleTokenService(
            RestTemplate restTemplate,
            @Value("${spring.security.oauth2.client.registration.google.client-id}") String webClientId,
            @Value("${spring.security.oauth2.client.registration.google.client-secret}") String webClientSecret,
            @Value("${app.oauth.mobile.android-client-id}") String mobileAndroidClientId,
            @Value("${app.oauth.mobile.ios-client-id}") String mobileIosClientId,
            @Value("${app.oauth.mobile.redirect-uri}") String mobileRedirectUri) {
        this.restTemplate = restTemplate;
        this.webClientId = webClientId;
        this.webClientSecret = webClientSecret;
        this.mobileAndroidClientId = mobileAndroidClientId;
        this.mobileIosClientId = mobileIosClientId;
        this.mobileRedirectUri = mobileRedirectUri;

        // Web verifier
        this.webVerifier = new GoogleIdTokenVerifier.Builder(
            new NetHttpTransport(),
            GsonFactory.getDefaultInstance()
        )
            .setAudience(Collections.singletonList(webClientId))
            .build();

        // Mobile verifier (Android + iOS 클라이언트 ID 모두 허용)
        this.mobileVerifier = new GoogleIdTokenVerifier.Builder(
            new NetHttpTransport(),
            GsonFactory.getDefaultInstance()
        )
            .setAudience(Arrays.asList(mobileAndroidClientId, mobileIosClientId))
            .build();

        log.info("Mobile OAuth configured - Android: {}, iOS: {}",
            mobileAndroidClientId.substring(0, 20) + "...",
            mobileIosClientId.substring(0, 20) + "...");
    }

    /**
     * Get configured mobile redirect URI (for security - don't trust client input)
     */
    public String getMobileRedirectUri() {
        return mobileRedirectUri;
    }

    /**
     * Exchange Google authorization code for tokens (Web - with client_secret)
     */
    public GoogleTokenResponse exchangeCodeForTokens(String code, String codeVerifier, String redirectUri) {
        return doTokenExchange(code, codeVerifier, redirectUri, webClientId, webClientSecret);
    }

    /**
     * Exchange Google authorization code for tokens (Mobile PKCE - no client_secret)
     * Uses server-configured redirect URI for security
     * Note: This uses Android client ID by default. For iOS, use exchangeCodeForTokensMobileIos()
     */
    public GoogleTokenResponse exchangeCodeForTokensMobile(String code, String codeVerifier) {
        log.info("Mobile token exchange (Android) with configured redirect URI: {}", mobileRedirectUri);
        return doTokenExchange(code, codeVerifier, mobileRedirectUri, mobileAndroidClientId, null);
    }

    /**
     * Exchange Google authorization code for tokens (iOS PKCE - no client_secret)
     */
    public GoogleTokenResponse exchangeCodeForTokensMobileIos(String code, String codeVerifier, String redirectUri) {
        log.info("Mobile token exchange (iOS) with redirect URI: {}", redirectUri);
        return doTokenExchange(code, codeVerifier, redirectUri, mobileIosClientId, null);
    }

    private GoogleTokenResponse doTokenExchange(String code, String codeVerifier, String redirectUri,
                                                 String clientId, String clientSecret) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("client_id", clientId);
        params.add("redirect_uri", redirectUri);
        params.add("grant_type", "authorization_code");
        params.add("code_verifier", codeVerifier);

        // client_secret은 Web 클라이언트에만 필요 (PKCE 모바일은 불필요)
        if (clientSecret != null && !clientSecret.isEmpty()) {
            params.add("client_secret", clientSecret);
        }

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<GoogleTokenResponse> response = restTemplate.exchange(
                GOOGLE_TOKEN_URL,
                HttpMethod.POST,
                request,
                GoogleTokenResponse.class
            );
            return response.getBody();
        } catch (Exception e) {
            log.error("Failed to exchange code with Google: {}", e.getMessage());
            throw new RuntimeException("Google token exchange failed", e);
        }
    }

    /**
     * Verify Google ID token and extract user info (Web client)
     */
    public GoogleUserInfo verifyIdToken(String idToken) {
        return doVerifyIdToken(idToken, webVerifier, "web");
    }

    /**
     * Verify Google ID token and extract user info (Mobile client)
     */
    public GoogleUserInfo verifyIdTokenMobile(String idToken) {
        return doVerifyIdToken(idToken, mobileVerifier, "mobile");
    }

    private GoogleUserInfo doVerifyIdToken(String idToken, GoogleIdTokenVerifier verifier, String clientType) {
        try {
            GoogleIdToken googleIdToken = verifier.verify(idToken);
            if (googleIdToken == null) {
                throw new RuntimeException("Invalid ID token for " + clientType + " client");
            }

            GoogleIdToken.Payload payload = googleIdToken.getPayload();
            return GoogleUserInfo.builder()
                .sub(payload.getSubject())
                .email(payload.getEmail())
                .emailVerified(payload.getEmailVerified())
                .name((String) payload.get("name"))
                .pictureUrl((String) payload.get("picture"))
                .build();
        } catch (Exception e) {
            log.error("Failed to verify {} ID token: {}", clientType, e.getMessage());
            throw new RuntimeException("ID token verification failed", e);
        }
    }

    @Data
    public static class GoogleTokenResponse {
        @JsonProperty("access_token")
        private String accessToken;

        @JsonProperty("id_token")
        private String idToken;

        @JsonProperty("refresh_token")
        private String refreshToken;

        @JsonProperty("token_type")
        private String tokenType;

        @JsonProperty("expires_in")
        private int expiresIn;
    }

    @Data
    @Builder
    public static class GoogleUserInfo {
        private String sub;
        private String email;
        private boolean emailVerified;
        private String name;
        private String pictureUrl;
    }
}
