package com.auth.jwtsecurity.controller;

import com.auth.jwtsecurity.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class PublicKeyController {

    private final JwtService jwtService;

    @GetMapping(value = "/public-key", produces = MediaType.TEXT_PLAIN_VALUE)
    public String getPublicKey() {
        return Base64.getEncoder()
                .encodeToString(jwtService.getEncodedPublicKey());
    }
}
