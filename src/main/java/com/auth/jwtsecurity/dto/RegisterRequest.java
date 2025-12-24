package com.auth.jwtsecurity.dto;

import jakarta.validation.constraints.*;
import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    @NotBlank(message = "Full name is required")
    @Size(min = 3, max = 100)
    private String fullName;

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 20)
    private String username;

    @NotBlank(message = "Password is required")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]).{8,}$",
            message = "Password must be at least 8 characters with upper, lower, digit and special character"
    )
    private String password;

    @NotBlank(message = "Phone number is required")
    @Pattern(
            regexp = "^[6-9]\\d{9}$",
            message = "Invalid Indian phone number"
    )
    private String phoneNumber;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "PAN number is required")
    @Pattern(
            regexp = "[A-Z]{5}[0-9]{4}[A-Z]{1}",
            message = "Invalid PAN number"
    )
    private String panNumber;

    @NotBlank(message = "College name is required")
    private String collegeName;

    @NotBlank(message = "College roll number is required")
    private String collegeRollNumber;

    @NotNull(message = "Passout year is required")
    @Min(value = 2000, message = "Invalid passout year")
    @Max(value = 2100, message = "Invalid passout year")
    private Integer passoutYear;
}
