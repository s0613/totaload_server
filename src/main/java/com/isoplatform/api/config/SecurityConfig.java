package com.isoplatform.api.config;

import com.isoplatform.api.auth.handler.OAuth2AuthenticationFailureHandler;
import com.isoplatform.api.auth.handler.OAuth2AuthenticationSuccessHandler;
import com.isoplatform.api.auth.service.CustomOAuth2UserService;
import com.isoplatform.api.config.filter.ApiKeyAuthFilter;
import com.isoplatform.api.config.handler.Http401Handler;
import com.isoplatform.api.config.handler.Http403Handler;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ObjectMapper objectMapper;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
    private final UserDetailsService userDetailsService;
    private final ApiKeyAuthFilter apiKeyAuthFilter;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(apiKeyAuthFilter, UsernamePasswordAuthenticationFilter.class)

                // 접근 권한
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers(
                                "/api/health",
                                "/api/auth/signup",
                                "/api/auth/login",
                                "/api/auth/logout",
                                "/login/oauth2/**",
                                "/oauth2/**",
                                // Swagger UI와 API Docs 접근 허용
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/swagger-resources/**",
                                "/swagger-ui.html",
                                "/api/certificates/issue"
                        )
                        .permitAll()
                        .requestMatchers(
                                "/api/photos/**",
                                "/api/checklists/**",
                                "/api/certificates/from-checklist"
                        )
                        .authenticated()
                        .anyRequest().authenticated())

                // OAuth2 로그인 설정
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService))
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        .failureHandler(oAuth2AuthenticationFailureHandler)
                )

                // 예외 처리
                .exceptionHandling(exception -> {
                    exception.accessDeniedHandler(new Http403Handler(objectMapper));
                    exception.authenticationEntryPoint(new Http401Handler(objectMapper));
                })

                .csrf(csrf -> csrf.disable());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(provider);
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }
}