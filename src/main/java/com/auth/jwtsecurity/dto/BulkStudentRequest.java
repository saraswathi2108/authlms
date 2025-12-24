package com.auth.jwtsecurity.dto;

import jakarta.validation.constraints.*;
import lombok.Data;

@Data
public class BulkStudentRequest {

    @NotBlank
    @Size(max = 100)
    private String fullName;



    @NotBlank
    @Email
    private String email;

    @NotBlank
    @Size(min = 10, max = 15)
    private String phoneNumber;

    @NotBlank
    @Size(min = 10, max = 10)
    private String panNumber;

    @NotBlank
    private String collegeName;

    @NotBlank
    private String collegeRollNumber;

    @NotNull
    private Integer passoutYear;
}
