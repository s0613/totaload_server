package com.isoplatform.api.auth.controller;

import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.dto.ChangePasswordRequest;
import com.isoplatform.api.auth.dto.UpdateProfileRequest;
import com.isoplatform.api.auth.dto.WithdrawRequest;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.auth.service.WithdrawService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Positive;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final WithdrawService withdrawService;

    /**
     * Update user profile
     * PUT /api/users/{userId}/profile
     */
    @PutMapping("/{userId}/profile")
    public ResponseEntity<Map<String, Object>> updateProfile(
            @PathVariable Long userId,
            @RequestBody UpdateProfileRequest request,
            Authentication authentication) {

        // 인증 확인
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication required");
        }

        String currentEmail = authentication.getName();
        User currentUser = userRepository.findByEmail(currentEmail)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        // 본인만 수정 가능 (관리자 예외 추가 가능)
        if (!currentUser.getId().equals(userId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You can only update your own profile");
        }

        log.info("Profile update request for user: {}", userId);

        // 업데이트
        if (request.getName() != null && !request.getName().isBlank()) {
            currentUser.setName(request.getName());
        }
        if (request.getEmail() != null && !request.getEmail().isBlank()) {
            // 이메일 중복 체크
            if (!request.getEmail().equals(currentUser.getEmail())
                    && userRepository.existsByEmail(request.getEmail())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
            }
            currentUser.setEmail(request.getEmail());
        }
        if (request.getPhoneNumber() != null) {
            currentUser.setPhoneNumber(request.getPhoneNumber());
        }
        if (request.getCompany() != null && !request.getCompany().isBlank()) {
            currentUser.setCompany(request.getCompany());
        }

        userRepository.save(currentUser);
        log.info("Profile updated for user: {}", userId);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "프로필이 업데이트되었습니다",
                "userId", currentUser.getId(),
                "name", currentUser.getName(),
                "email", currentUser.getEmail()
        ));
    }

    /**
     * Change user password
     * PUT /api/users/{userId}/password
     */
    @PutMapping("/{userId}/password")
    public ResponseEntity<Map<String, Object>> changePassword(
            @PathVariable Long userId,
            @Valid @RequestBody ChangePasswordRequest request,
            Authentication authentication) {

        // 인증 확인
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication required");
        }

        String currentEmail = authentication.getName();
        User currentUser = userRepository.findByEmail(currentEmail)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        // 본인만 수정 가능
        if (!currentUser.getId().equals(userId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You can only change your own password");
        }

        // OAuth 사용자는 비밀번호 변경 불가
        if (!"LOCAL".equals(currentUser.getProvider())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "OAuth users cannot change password");
        }

        log.info("Password change request for user: {}", userId);

        // 현재 비밀번호 확인
        if (!passwordEncoder.matches(request.getCurrentPassword(), currentUser.getPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Current password is incorrect");
        }

        // 새 비밀번호 확인
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "New passwords do not match");
        }

        // 비밀번호 변경
        currentUser.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(currentUser);
        log.info("Password changed for user: {}", userId);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "비밀번호가 변경되었습니다"
        ));
    }

    /**
     * Delete user account (회원탈퇴)
     * DELETE /api/users/{userId}
     */
    @DeleteMapping("/{userId}")
    public ResponseEntity<Map<String, Object>> deleteAccount(
            @PathVariable @Positive(message = "User ID must be positive") Long userId,
            @Valid @RequestBody(required = false) WithdrawRequest request,
            Authentication authentication) {

        // 인증 확인
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication required");
        }

        String currentEmail = authentication.getName();
        User currentUser = userRepository.findByEmail(currentEmail)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        // 본인만 삭제 가능
        if (!currentUser.getId().equals(userId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You can only delete your own account");
        }

        log.info("Account deletion request for user: {}", userId);

        // LOCAL 사용자는 반드시 비밀번호가 필요함
        if ("LOCAL".equals(currentUser.getProvider())) {
            if (request == null || request.getPassword() == null || request.getPassword().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Password is required for account deletion");
            }
        }

        // WithdrawRequest가 없으면 기본값 생성 (OAuth 사용자용)
        if (request == null) {
            request = new WithdrawRequest();
            request.setReason("User requested account deletion");
        }

        withdrawService.withdraw(userId, request);
        log.info("Account deleted for user: {}", userId);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "회원 탈퇴가 완료되었습니다."
        ));
    }
}
