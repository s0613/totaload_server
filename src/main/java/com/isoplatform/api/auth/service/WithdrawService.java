package com.isoplatform.api.auth.service;

import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.dto.WithdrawRequest;
import com.isoplatform.api.auth.exception.InvalidCredentialsException;
import com.isoplatform.api.auth.exception.UserNotFoundException;
import com.isoplatform.api.auth.repository.RefreshTokenRepository;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.certification.repository.CertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class WithdrawService {

    private static final String PROVIDER_LOCAL = "LOCAL";

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CertificateRepository certificateRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void withdraw(Long userId, WithdrawRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // LOCAL 사용자의 경우 비밀번호 확인
        if (PROVIDER_LOCAL.equals(user.getProvider())) {
            if (request.getPassword() == null || request.getPassword().isBlank()) {
                throw new InvalidCredentialsException("Password is required for local users");
            }
            if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                throw new InvalidCredentialsException("Invalid password");
            }
        }

        log.info("User withdrawal initiated: userId={}, email={}, reason={}",
                userId, user.getEmail(), request.getReason());

        // 1. 인증서에서 사용자 참조 해제 (법적 보관 의무로 인증서 자체는 유지)
        certificateRepository.detachUserFromCertificates(userId);
        certificateRepository.detachVerifierFromCertificates(userId);

        // 2. 모든 리프레시 토큰 삭제
        refreshTokenRepository.deleteByUser(user);

        // 3. 사용자 삭제
        userRepository.delete(user);

        log.info("User withdrawal completed: userId={}", userId);
    }
}
