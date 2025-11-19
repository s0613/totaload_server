package com.isoplatform.api.auth.service;

import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.dto.GoogleOAuth2UserInfo;
import com.isoplatform.api.auth.dto.OAuth2UserInfo;
import com.isoplatform.api.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.info("OAuth2 login attempt from provider: {}", registrationId);

        OAuth2UserInfo userInfo = getOAuth2UserInfo(registrationId, oauth2User.getAttributes());

        User user = saveOrUpdate(userInfo);
        log.info("OAuth2 user processed: {} (id: {})", user.getEmail(), user.getId());

        return oauth2User;
    }

    private OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if ("google".equalsIgnoreCase(registrationId)) {
            return new GoogleOAuth2UserInfo(attributes);
        }
        throw new OAuth2AuthenticationException("Unsupported provider: " + registrationId);
    }

    private User saveOrUpdate(OAuth2UserInfo userInfo) {
        Optional<User> existingUser = userRepository.findByProviderAndProviderId(
                userInfo.getProvider(),
                userInfo.getProviderId()
        );

        if (existingUser.isPresent()) {
            User user = existingUser.get();
            user.setName(userInfo.getName());
            user.setLastLoginAt(LocalDateTime.now());
            return userRepository.save(user);
        }

        User newUser = User.builder()
                .email(userInfo.getEmail())
                .name(userInfo.getName())
                .password("OAUTH2_USER") // OAuth users don't use password
                .provider(userInfo.getProvider())
                .providerId(userInfo.getProviderId())
                .role(Role.USER)
                .company("SELF")
                .isActive(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .lastLoginAt(LocalDateTime.now())
                .build();

        return userRepository.save(newUser);
    }
}
