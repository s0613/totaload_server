package com.isoplatform.api.auth.controller;

import com.isoplatform.api.auth.dto.*;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.security.CustomUserDetails;
import com.isoplatform.api.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;

    @PostMapping("/signup")
    public ResponseEntity<SignupResponse> signup(@Valid @RequestBody SignupRequest request) {
        log.info("회원가입 요청 - email: {}", request.getEmail());
        SignupResponse response = authService.signup(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        log.info("로그인 요청 - usernameOrEmail: {}", request.getUsernameOrEmail());

        try {
            // 인증 수행
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsernameOrEmail(),
                            request.getPassword()
                    )
            );

            // SecurityContext에 인증 정보 저장
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            // 세션에 SecurityContext 저장
            securityContextRepository.saveContext(context, httpRequest, httpResponse);

            log.info("로그인 성공 - user: {}", request.getUsernameOrEmail());

            return ResponseEntity.ok(LoginResponse.builder()
                    .success(true)
                    .message("로그인에 성공했습니다")
                    .redirectUrl("/")
                    .build());

        } catch (Exception e) {
            log.error("로그인 실패 - user: {}, error: {}", request.getUsernameOrEmail(), e.getMessage());
            return ResponseEntity.status(401).body(LoginResponse.builder()
                    .success(false)
                    .message("이메일 또는 비밀번호가 올바르지 않습니다")
                    .build());
        }
    }

    @GetMapping("/me")
    public ResponseEntity<CurrentUserResponse> getCurrentUser(
            @AuthenticationPrincipal CustomUserDetails userDetails) {

        if (userDetails == null) {
            log.warn("인증되지 않은 사용자의 /me 요청");
            return ResponseEntity.status(401).build();
        }

        User user = userDetails.getUser();
        CurrentUserResponse response = authService.getCurrentUser(user);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<LogoutResponse> logout(HttpServletRequest request) {
        log.info("로그아웃 요청");

        try {
            // 세션 무효화
            request.getSession().invalidate();
            SecurityContextHolder.clearContext();

            return ResponseEntity.ok(LogoutResponse.builder()
                    .success(true)
                    .message("로그아웃되었습니다")
                    .build());
        } catch (IllegalStateException e) {
            // Session already invalidated - this is fine
            log.debug("로그아웃 시 세션 이미 무효화됨: {}", e.getMessage());
            return ResponseEntity.ok(LogoutResponse.builder()
                    .success(true)
                    .message("로그아웃되었습니다")
                    .build());
        } catch (Exception e) {
            log.error("로그아웃 실패: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(LogoutResponse.builder()
                    .success(false)
                    .message("로그아웃 처리 중 오류가 발생했습니다")
                    .build());
        }
    }
}
