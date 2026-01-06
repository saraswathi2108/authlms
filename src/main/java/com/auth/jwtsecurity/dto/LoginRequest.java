package com.auth.jwtsecurity.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

//    private String username = null;
    private String email = null;
//    private String phone = null;

    @NotBlank(message = "Password is required")
    private String password;

    private boolean force = false;
}
