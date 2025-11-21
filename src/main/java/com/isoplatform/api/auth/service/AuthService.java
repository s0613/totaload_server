package com.isoplatform.api.auth.service;

import com.isoplatform.api.auth.dto.*;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public SignupResponse signup(SignupRequest request) {
        log.info("회원가입 시작 - email: {}, username: {}", request.getEmail(), request.getUsername());

        // 비밀번호 확인
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다");
        }

        // 이메일 중복 확인
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다");
        }

        // 사용자명 중복 확인
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("이미 사용 중인 사용자명입니다");
        }

        // 사용자 생성
        User.UserBuilder userBuilder = User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .phoneNumber(request.getPhoneNumber())
                .isEvaluator(request.getIsEvaluator() != null ? request.getIsEvaluator() : false)
                .agreeMarketing(request.getAgreeMarketing() != null ? request.getAgreeMarketing() : false);

        // 생년월일 파싱
        if (request.getBirthdate() != null && !request.getBirthdate().isEmpty()) {
            try {
                LocalDate birthdate = LocalDate.parse(request.getBirthdate(), DateTimeFormatter.ISO_DATE);
                userBuilder.birthdate(birthdate);
            } catch (Exception e) {
                log.warn("생년월일 파싱 실패: {}", request.getBirthdate());
            }
        }

        // 평가자 정보
        if (Boolean.TRUE.equals(request.getIsEvaluator())) {
            userBuilder.role(Role.EVALUATOR)
                    .evaluatorCertNumber(request.getEvaluatorCertNumber())
                    .evaluatorCertCopyUrl(request.getEvaluatorCertCopyUrl());

            if (request.getEvaluatorCertExpiry() != null && !request.getEvaluatorCertExpiry().isEmpty()) {
                try {
                    LocalDate expiry = LocalDate.parse(request.getEvaluatorCertExpiry(), DateTimeFormatter.ISO_DATE);
                    userBuilder.evaluatorCertExpiry(expiry);
                } catch (Exception e) {
                    log.warn("평가자 인증서 만료일 파싱 실패: {}", request.getEvaluatorCertExpiry());
                }
            }
        } else {
            userBuilder.role(Role.USER);
        }

        User user = userRepository.save(userBuilder.build());
        log.info("회원가입 완료 - userId: {}", user.getId());

        return SignupResponse.builder()
                .success(true)
                .message("회원가입이 완료되었습니다")
                .userId(user.getId())
                .build();
    }

    public CurrentUserResponse getCurrentUser(User user) {
        return CurrentUserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .username(user.getUsername())
                .name(user.getName())
                .role(user.getRole().name())
                .isEvaluator(user.getIsEvaluator())
                .build();
    }
}
