package com.auth.jwtsecurity.controller;

import com.auth.jwtsecurity.dto.*;
import com.auth.jwtsecurity.service.AuthService;
import com.auth.jwtsecurity.service.MobileOtpService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final MobileOtpService mobileOtpService;

    @PostMapping("/students/bulk")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<?> bulkCreateStudents(
            @RequestBody @Valid List<BulkStudentRequest> students
    ) {
        authService.bulkCreateStudents(students);
        return ResponseEntity.ok("Students created successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletResponse response
    ) {

        TokenPair tokenPair = authService.login(loginRequest);

        Cookie refreshTokenCookie = new Cookie("refreshToken", tokenPair.getRefreshToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false); // true in prod with HTTPS
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60);
        response.addCookie(refreshTokenCookie);

        return ResponseEntity.ok(
                Map.of("accessToken", tokenPair.getAccessToken())
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(HttpServletRequest request) {

        String refreshToken = null;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refreshToken".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }

        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.badRequest().body("Missing refresh token");
        }

        TokenPair tokenPair = authService.refreshTokenFromCookie(refreshToken);
        return ResponseEntity.ok(Map.of("accessToken", tokenPair.getAccessToken()));
    }

    @PutMapping("/otp/email")
    public ResponseEntity<?> sendOtpToEmail(
            @RequestParam String email
    ) throws Exception {

        String token = mobileOtpService.sendOtpToUserEmail(email);
        return ResponseEntity.ok(Map.of("token", token));
    }

    @PutMapping("/otp/phone")
    public ResponseEntity<?> sendOtpToPhone(
            @RequestParam String email,
            @RequestParam String phone
    ) throws Exception {

        String token = mobileOtpService.sendOtpToUserPhone(email, phone);
        return ResponseEntity.ok(Map.of("token", token));
    }

    @PutMapping("/otp/verify")
    public ResponseEntity<?> verifyOtp(
            @RequestParam String otp,
            @RequestHeader("X_OTP_Token") String otpToken,
            HttpServletResponse response
    ) throws Exception {

        TokenPair tokenPair = mobileOtpService.verifyOTP(otp, otpToken);

        Cookie refreshTokenCookie = new Cookie("refreshToken", tokenPair.getRefreshToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60);
        response.addCookie(refreshTokenCookie);

        return ResponseEntity.ok(
                Map.of("accessToken", tokenPair.getAccessToken())
        );
    }

    @PutMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(
            @RequestParam String email
    ) throws Exception {

        String otpToken = mobileOtpService.sendForgotPasswordOtp(email);
        return ResponseEntity.ok(Map.of(
                "otpToken", otpToken,
                "message", "If email exists, OTP sent"
        ));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(
            @RequestHeader("X_OTP_Token") String otpToken,
            @RequestBody @Valid ResetPasswordWithOtpRequest request
    ) throws Exception {

        mobileOtpService.resetPasswordWithOtp(
                otpToken,
                request.getOtp(),
                request.getNewPassword(),
                request.getConfirmPassword()
        );

        return ResponseEntity.ok(Map.of("message", "Password reset successful"));
    }

    // ================= CHANGE PASSWORD =================
    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestBody @Valid ChangePasswordRequest request,
            Authentication authentication
    ) {
        authService.changePassword(request, authentication);
        return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
    }

    @PostMapping("/admin/create")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<?> createAdmin(
            @RequestBody @Valid CreateAdminRequest request
    ) {
        authService.createAdmin(request);
        return ResponseEntity.ok("Admin created successfully");
    }
}
