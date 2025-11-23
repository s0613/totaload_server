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
import java.util.Collections;

@Service
@Slf4j
public class GoogleTokenService {

    private static final String GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";

    private final RestTemplate restTemplate;
    private final String clientId;
    private final String clientSecret;
    private final GoogleIdTokenVerifier verifier;

    public GoogleTokenService(
            RestTemplate restTemplate,
            @Value("${spring.security.oauth2.client.registration.google.client-id}") String clientId,
            @Value("${spring.security.oauth2.client.registration.google.client-secret}") String clientSecret) {
        this.restTemplate = restTemplate;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.verifier = new GoogleIdTokenVerifier.Builder(
            new NetHttpTransport(),
            GsonFactory.getDefaultInstance()
        )
            .setAudience(Collections.singletonList(clientId))
            .build();
    }

    /**
     * Exchange Google authorization code for tokens
     */
    public GoogleTokenResponse exchangeCodeForTokens(String code, String codeVerifier, String redirectUri) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("redirect_uri", redirectUri);
        params.add("grant_type", "authorization_code");
        params.add("code_verifier", codeVerifier);

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
     * Verify Google ID token and extract user info
     */
    public GoogleUserInfo verifyIdToken(String idToken) {
        try {
            GoogleIdToken googleIdToken = verifier.verify(idToken);
            if (googleIdToken == null) {
                throw new RuntimeException("Invalid ID token");
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
            log.error("Failed to verify ID token: {}", e.getMessage());
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
