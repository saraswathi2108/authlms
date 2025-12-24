package com.auth.jwtsecurity.controller;

import com.auth.jwtsecurity.Client.CustomFeignContext;
//import com.auth.jwtsecurity.Client.TicketsUpdate;
import com.auth.jwtsecurity.dto.*;
import com.auth.jwtsecurity.repository.UserRepository;
//import com.auth.jwtsecurity.security.CheckPermission;
import com.auth.jwtsecurity.service.AuthService;
import com.auth.jwtsecurity.service.MobileOtpService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final CustomFeignContext customFeignContext;
    private final MobileOtpService mobileOtpService;

    @PostMapping("/register")
//    @CheckPermission("PERMISSIONS_BUTTONS")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest request) {
//       customFeignContext.setToken(Authorization);
        authService.registerUser(request);
        return ResponseEntity.ok(Map.of("message", "User registered successfully"));
    }

    @DeleteMapping("/delete/{userId}")
//    @CheckPermission("PERMISSIONS_BUTTONS")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<?> deleteUser(@PathVariable String userId, @RequestHeader String Authorization) {
        customFeignContext.setToken(Authorization);
        authService.deleteUser(userId.toLowerCase());
        return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
    }

    @PutMapping("/update/{userId}")
//    @CheckPermission("PERMISSIONS_BUTTONS")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<?> updateUser(
            @PathVariable String userId,
            @RequestBody UpdateRequest request,
            @RequestHeader String Authorization
    ) {
        customFeignContext.setToken(Authorization);
        authService.updateUser(userId, request);
        return ResponseEntity.ok(Map.of("message", "User updated successfully"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletResponse response
    ) throws BadRequestException {

        TokenPair tokenPair = authService.login(loginRequest);

        Cookie refreshTokenCookie = new Cookie("refreshToken", tokenPair.getRefreshToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
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
        cookie.setSecure(false);
        response.addCookie(cookie);
        return ResponseEntity.ok(Map.of("message", "User logged out successfully"));
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
            return ResponseEntity.badRequest().body("Missing or empty refresh token");
        }

        TokenPair tokenPair = authService.refreshTokenFromCookie(refreshToken);

        return ResponseEntity.ok(
                Map.of("accessToken", tokenPair.getAccessToken())
        );
    }

    @PutMapping("/SendOTPPhone")
    public ResponseEntity<Map<String, String>> SendingOtpPhone(
            @RequestParam(defaultValue = "np") String phone,
            @RequestParam(defaultValue = "np") String userName
    ) throws Exception {

        String encrypted = mobileOtpService.sendOtpToUserPhone(userName, phone);
        return ResponseEntity.ok(Map.of("token", encrypted));
    }

    @PutMapping("/SendOTP")
    public ResponseEntity<Map<String, String>> SendingOtp(
            @RequestParam(defaultValue = "np") String mail,
            @RequestParam(defaultValue = "np") String userName,
            @RequestParam(defaultValue = "np") String phone
    ) throws Exception {

        String encrypted = mobileOtpService.OtpSender(userName, mail, phone);
        return ResponseEntity.ok(Map.of("token", encrypted));
    }

    @PutMapping("/SendOTPMail")
    public ResponseEntity<Map<String, String>> SendingOtpMail(
            @RequestParam(defaultValue = "np") String mail,
            @RequestParam(defaultValue = "np") String userName
    ) throws Exception {

        String encrypted = mobileOtpService.sendOtpToUserEmail(userName, mail);
        return ResponseEntity.ok(Map.of("token", encrypted));
    }

    @PutMapping("/VerifyOTP")
    public ResponseEntity<?> verifyOTP(
            @RequestParam String otp,
            @RequestHeader String X_OTP_Token,
            HttpServletResponse response
    ) throws Exception {

        TokenPair tokenPair = mobileOtpService.verifyOTP(otp, X_OTP_Token);

        Cookie refreshTokenCookie = new Cookie("refreshToken", tokenPair.getRefreshToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60);
        response.addCookie(refreshTokenCookie);

        return ResponseEntity.ok(
                Map.of("accessToken", tokenPair.getAccessToken())
        );
    }

    @PostMapping("/admin/create")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<?> createAdmin(@RequestBody @Valid CreateAdminRequest request) {
        authService.createAdmin(request);
        return ResponseEntity.ok("Admin created successfully");
    }

    @PutMapping("/forgot-password")
    public ResponseEntity<?> sendForgotPasswordOtp(
            @RequestParam String email
    ) throws Exception {

        String otpToken = mobileOtpService.sendForgotPasswordOtp(email);

        return ResponseEntity.ok(Map.of(
                "otpToken", otpToken,
                "message", "If the email exists, OTP has been sent"
        ));
    }
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPasswordWithOtp(
            @RequestHeader("X_OTP_Token") String otpToken,
            @RequestBody @Valid ResetPasswordWithOtpRequest request
    ) throws Exception {

        mobileOtpService.resetPasswordWithOtp(
                otpToken,
                request.getOtp(),
                request.getNewPassword(),
                request.getConfirmPassword()
        );

        return ResponseEntity.ok(Map.of(
                "message", "Password reset successfully"
        ));
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestBody @Valid ChangePasswordRequest request,
            Authentication authentication
    ) {
        authService.changePassword(request, authentication);
        return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
    }






}
