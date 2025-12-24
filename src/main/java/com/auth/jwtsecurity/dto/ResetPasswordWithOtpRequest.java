package com.auth.jwtsecurity.dto;

import lombok.Data;

@Data
public class ResetPasswordWithOtpRequest {
    private String otp;
    private String newPassword;
    private String confirmPassword;
}
