package com.isoplatform.api.config.filter;

import com.isoplatform.api.security.ApiKeyService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Slf4j
@Component
@RequiredArgsConstructor
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    private final ApiKeyService apiKeyService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String requestPath = request.getRequestURI();

        // API Key가 필요한 엔드포인트만 처리
        if (requestPath.startsWith("/api/photos/") ||
            requestPath.startsWith("/api/checklists/") ||
            requestPath.equals("/api/certificates/from-checklist")) {

            String apiKey = request.getHeader("X-API-KEY");

            if (apiKey != null) {
                ApiKeyService.ApiKeyValidationResult result = apiKeyService.validateApiKeyWithDetails(apiKey);

                if (result.isValid()) {
                    // API Key 인증 성공 - SecurityContext에 인증 정보 설정
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    "api-key-user",
                                    null,
                                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_API_USER"))
                            );
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    log.debug("API Key 인증 성공: {}", requestPath);
                } else {
                    log.warn("API Key 인증 실패: {} - {}", requestPath, result.getMessage());
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Unauthorized: " + result.getMessage());
                    return;
                }
            } else {
                log.warn("API Key 없음: {}", requestPath);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Unauthorized: API Key required");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
