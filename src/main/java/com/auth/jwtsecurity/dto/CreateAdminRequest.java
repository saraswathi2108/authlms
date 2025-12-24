package com.auth.jwtsecurity.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateAdminRequest {

    @NotBlank
    private String fullName;


    @NotBlank
    private String password;

    private String email;
    private String phoneNumber;
}
