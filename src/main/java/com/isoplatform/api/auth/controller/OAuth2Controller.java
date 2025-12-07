package com.isoplatform.api.auth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/auth")
public class OAuth2Controller {

    @GetMapping("/oauth2/google")
    public void googleLogin() {
        // Spring Security가 자동으로 /oauth2/authorization/google로 리다이렉트
        log.info("Initiating Google OAuth2 login");
    }

    @GetMapping("/oauth2/status")
    public String oauth2Status() {
        return "OAuth2 is configured and ready";
    }
}
